"""Signed Azure compliance predicates over complete, scope-bound snapshot facts.

Policy inputs live in context.metadata.compliance_policy.sw31; they are never
inferred from resource names.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get


def _signed(id, category, kind, title, severity, remediation, dependencies, *, allow_incomplete_failure=False, empty_applicability_dependencies=()):
    """Preserve signed categories pending their addition to the core registry."""
    native_category = category if category in {"hardening", "network"} else "hardening"
    decorator = register(id, "azure", native_category, kind, title, severity,
                         "CM-6", remediation, target="scope", dependencies=dependencies,
                         allow_incomplete_failure=allow_incomplete_failure,
                         empty_applicability_dependencies=empty_applicability_dependencies)
    def apply(fn):
        wrapped = decorator(fn)
        if native_category != category:
            for pos, check in enumerate(CHECKS):
                if check.id == id:
                    CHECKS[pos] = replace(check, category=category)
                    break
        return wrapped
    return apply


def _scope(index, item):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("foreign provider")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"/subscriptions/[^/]+", scope, re.I):
        raise Unavailable("invalid subscription scope")
    if isinstance(item, dict) and "scope" in item and get(item, "scope", str).casefold() != scope.casefold():
        raise Unavailable("foreign scope subject")
    return scope


def _rows(index, item, kind, *, allow_partial=False):
    scope = _scope(index, item)
    envelopes = get(get(index, "collections", dict), kind, list)
    if not envelopes:
        raise Unavailable("inventory absent: " + kind)
    for envelope in envelopes:
        envelope_scope = get(envelope, "scope", str).casefold()
        if envelope_scope != scope.casefold() and not envelope_scope.startswith(scope.casefold() + "/"):
            raise Unavailable("foreign collection scope: " + kind)
        status = get(envelope, "status", str)
        if status not in (("collected", "empty", "partial") if allow_partial else ("collected", "empty")):
            raise Unavailable("incomplete inventory: " + kind)
        batch = get(envelope, "items", list)
        if status == "empty" and batch:
            raise Unavailable("nonempty empty inventory")
    if allow_partial:
        # Retained observations can disprove a universal policy, never certify it.
        if any(envelope.get("type", kind) != kind for envelope in envelopes):
            raise Unavailable("partial collection type differs: " + kind)
        wrappers = get(index, kind, list)
        for wrapper in wrappers:
            if wrapper.get("type", kind) != kind or wrapper.get("provider", "azure") != "azure":
                raise Unavailable("partial resource type/provider differs: " + kind)
            if get(wrapper, "scope", str).casefold() not in {get(e, "scope", str).casefold() for e in envelopes}:
                raise Unavailable("foreign partial resource wrapper: " + kind)
        rows = [get(wrapper, "data", dict) for wrapper in wrappers]
    else:
        rows = complete_items(index, kind)
    declared = [row for envelope in envelopes for row in get(envelope, "items", list)]
    if len(declared) != len(rows):
        raise Unavailable("collection/index item count differs: " + kind)
    declared_ids = []
    declared_by_id = {}
    for row in declared:
        key = get(row, "id", str).casefold()
        declared_ids.append(key)
        declared_by_id[key] = row
    seen = set()
    for row in rows:
        rid = get(row, "id", str)
        if not rid.casefold().startswith(scope.casefold() + "/") or rid.casefold() in seen:
            raise Unavailable("foreign or duplicate resource identity: " + kind)
        for reference in ("parent_id", "path_id"):
            if reference in row and not get(row, reference, str).casefold().startswith(scope.casefold() + "/"):
                raise Unavailable("foreign resource reference: " + kind)
        if declared_by_id.get(rid.casefold()) != row:
            raise Unavailable("collection/index resource facts differ: " + kind)
        seen.add(rid.casefold())
    if set(declared_ids) != seen:
        raise Unavailable("collection/index identities differ: " + kind)
    return rows


def _policy(index, name, typ):
    return get(_policy_root(index), name, typ)


def _policy_root(index):
    return get(index, "context.metadata.compliance_policy.sw31", dict)


def _names(value):
    if not isinstance(value, list) or not value or any(not isinstance(x, str) or not x for x in value):
        raise Unavailable("invalid policy names")
    return {x.casefold() for x in value}


def _join(rows, parent, suffix):
    expected = parent.casefold().rstrip("/") + suffix.casefold()
    found = [row for row in rows if get(row, "id", str).casefold() == expected]
    if len(found) != 1:
        raise Unavailable("required child absent or ambiguous: " + suffix)
    return found[0]


def _proven_empty(index, kind, parent):
    """A child is absent only if its own parent-scoped read completed empty."""
    envelopes = get(get(index, "collections", dict), kind, list)
    matches = [e for e in envelopes if get(e, "scope", str).casefold() == parent.casefold()]
    if len(matches) == 1 and get(matches[0], "status", str) == "empty":
        return True
    field = {"sql_backup_short_term_policy": "backupShortTermRetentionPolicies",
             "sql_database_ltr_policy": "backupLongTermRetentionPolicies"}.get(kind)
    if field is None:
        return False
    for wrapper in index.get("sql_database", []):
        row = get(wrapper, "data", dict)
        if get(row, "id", str).casefold() == parent.casefold():
            coverage = row.get("_coverage", {})
            return isinstance(coverage, dict) and isinstance(coverage.get(field), dict) and coverage[field].get("status") == "empty"
    return False


def _maybe_rows(index, item, kind):
    try:
        return _rows(index, item, kind), False
    except Unavailable:
        return [], True


def _verdict(values, *, empty="NOT_APPLICABLE"):
    if not values:
        return empty, {"reason": "no applicable resources in complete inventory"}
    if any(x is True for x in values):
        return result(True, evaluated=len(values))
    if any(x is None for x in values):
        return unknown("one or more required facts unresolved", evaluated=len(values))
    return result(False, evaluated=len(values))


def _time(value):
    if not isinstance(value, str):
        raise Unavailable("missing or malformed timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("malformed timestamp") from exc
    if parsed.tzinfo is None:
        raise Unavailable("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _sql_user_rows(index, item):
    rows = _rows(index, item, "sql_database")
    users = []
    for row in rows:
        rid = get(row, "id", str)
        if rid.rsplit("/", 1)[-1].casefold() not in ("master", "model", "msdb", "tempdb"):
            users.append(row)
    return users


def _sql_online(row):
    status = get(row, "properties.status", str)
    if status == "Online":
        return True
    if status in ("Paused", "Offline", "Restoring", "Creating", "Scaling"):
        return False
    raise Unavailable("unrecognized SQL database status")


@_signed("azure_recovery_vault_10_3_3_1_1f42f66", "recovery", "sql_database", "SQL databases retain automatic point-in-time backups", "medium", "Enable an applicable SQL short-term retention policy.", ["sql_database", "sql_backup_short_term_policy"], empty_applicability_dependencies=("sql_database",))
def sql_pitr(item, index):
    databases = _sql_user_rows(index, item)
    if not databases:
        return _verdict([])
    try:
        if not any(_sql_online(db) for db in databases):
            return _verdict([])
    except Unavailable:
        pass
    policies = _rows(index, item, "sql_backup_short_term_policy")
    values = []
    for db in databases:
        try:
            if not _sql_online(db):
                continue
            did = get(db, "id", str)
            try:
                policy = _join(policies, did, "/backupShortTermRetentionPolicies/default")
            except Unavailable:
                values.append(True if _proven_empty(index, "sql_backup_short_term_policy", did) else None)
                continue
            days = get(policy, "properties.retentionDays", int)
            values.append(days <= 0)
        except Unavailable:
            values.append(None)
    return _verdict(values)


@_signed("azure_recovery_vault_10_3_3_8_26e08d7", "recovery", "sql_database", "Set SQL Database backup retention", "medium", "Set backup retention and verify recovery points against the declared window.", ["sql_database", "sql_backup_short_term_policy", "sql_restore_point"], allow_incomplete_failure=True, empty_applicability_dependencies=("sql_database",))
def sql_backup_retention(item, index):
    dbs = _sql_user_rows(index, item)
    if not dbs:
        return _verdict([])
    try:
        if not any(_sql_online(db) for db in dbs):
            return _verdict([])
    except Unavailable:
        pass
    policies = _rows(index, item, "sql_backup_short_term_policy")
    points, points_missing = _maybe_rows(index, item, "sql_restore_point")
    policy_inputs = _policy_root(index)
    minimum = policy_inputs.get("minRetentionDays")
    window = policy_inputs.get("backupWindowDays")
    if (minimum is not None and (type(minimum) is not int or minimum <= 0)) or (window is not None and (type(window) is not int or window <= 0)):
        raise Unavailable("invalid backup policy thresholds")
    now = _time(get(index, "context.created_at", str))
    values = []
    for db in dbs:
        try:
            if not _sql_online(db):
                continue
            did = get(db, "id", str)
            try:
                policy = _join(policies, did, "/backupShortTermRetentionPolicies/default")
            except Unavailable:
                values.append(True if _proven_empty(index, "sql_backup_short_term_policy", did) else None)
                continue
            days = get(policy, "properties.retentionDays", int)
            if days <= 0 or (minimum is not None and days < minimum):
                values.append(True)
                continue
            if points_missing:
                values.append(None)
                continue
            matches = [p for p in points if get(p, "parent_id", str).casefold() == did.casefold()]
            if not matches:
                values.append(None)
                continue
            stamps = [_time(get(p, "properties.restorePointCreationDate", str)) for p in matches]
            if max(stamps) > now:
                values.append(None)
            else:
                values.append(max(stamps) < now - timedelta(days=window) if window is not None else False)
        except Unavailable:
            values.append(None)
    return _verdict(values)


def _sql_ltr_copy_bound(copy, database):
    did, cid = get(database, "id", str), get(copy, "id", str)
    if get(copy, "parent_id", str).casefold() != did.casefold():
        raise Unavailable("foreign LTR backup parent")
    # Preserve the previously admitted snapshot representation, while accepting
    # the native location-scoped identity only with its exact read binding.
    if re.fullmatch(re.escape(did) + r"/longTermRetentionBackups/[^/?#%]+", cid, re.I):
        return
    match = re.fullmatch(r"(/subscriptions/[^/?#%]+)/resourceGroups/[^/?#%]+/providers/Microsoft.Sql/servers/([^/?#%]+)/databases/([^/?#%]+)", did, re.I)
    location = get(database, "location", str)
    if match is None or not re.fullmatch(r"[a-zA-Z0-9]{1,64}", location):
        raise Unavailable("native SQL LTR database location unavailable")
    scope, server, name = match.groups()
    path = (scope + "/providers/Microsoft.Sql/locations/" + location
            + "/longTermRetentionServers/" + quote(server, safe="")
            + "/longTermRetentionDatabases/" + quote(name, safe="") + "/longTermRetentionBackups")
    if (not re.fullmatch(re.escape(path) + r"/[^/?#%]+", cid, re.I)
            or any(p in (".", "..") for p in cid.split("/"))
            or get(copy, "type", str).casefold() != "microsoft.sql/locations/longtermretentionservers/longtermretentiondatabases/longtermretentionbackups"
            or get(copy, "properties.serverName", str).casefold() != server.casefold()
            or get(copy, "properties.databaseName", str).casefold() != name.casefold()
            or get(copy, "_provenance.source_operation", str) != "LongTermRetentionBackups_ListByDatabase"
            or get(copy, "_provenance.api_version", str) != "2023-08-01"
            or get(copy, "_provenance.read_only", bool) is not True
            or get(copy, "_provenance.request_path", str).casefold() != path.casefold()
            or get(copy, "_provenance.database_state", str) != "Live"):
        raise Unavailable("foreign or unbound native LTR backup identity")


@_signed("azure.gap.sql_database_long_term_geo_redundant_backup_enabled", "recovery", "sql_database", "SQL long-term backup uses geo-redundant storage", "medium", "Enable LTR and retain geo-redundant copies.", ["sql_database", "sql_database_ltr_policy", "sql_ltr_backup"], allow_incomplete_failure=True, empty_applicability_dependencies=("sql_database",))
def sql_geo_ltr(item, index):
    dbs = _sql_user_rows(index, item)
    policies, policies_missing = _maybe_rows(index, item, "sql_database_ltr_policy")
    copies, copies_missing = _maybe_rows(index, item, "sql_ltr_backup")
    values = []
    for db in dbs:
        did = get(db, "id", str)
        try:
            if not copies_missing:
                matched = [copy for copy in copies if get(copy, "parent_id", str).casefold() == did.casefold()]
                for copy in matched:
                    _sql_ltr_copy_bound(copy, db)
                if any(get(copy, "properties.backupStorageRedundancy", str) in ("Local", "Zone") for copy in matched):
                    values.append(True)
                    continue
            if policies_missing:
                values.append(None)
                continue
            try:
                policy = _join(policies, did, "/backupLongTermRetentionPolicies/default")
            except Unavailable:
                values.append(True if _proven_empty(index, "sql_database_ltr_policy", did) else None)
                continue
            props = get(policy, "properties", dict)
            periods = [get(props, key, str) for key in ("weeklyRetention", "monthlyRetention", "yearlyRetention")]
            # Azure returns PT0S for an unset retention period, including every
            # field after RemovePolicy (Az.Sql's documented native response).
            zero_retention = ("PT0S", "P0D", "P0W", "P0M", "P0Y")
            if all(value in zero_retention for value in periods):
                values.append(True)
                continue
            if any(not re.fullmatch(r"P[1-9][0-9]*[DWMY]", value) and value not in zero_retention for value in periods):
                values.append(None)
                continue
            if copies_missing:
                values.append(None)
                continue
            matched = [copy for copy in copies if get(copy, "parent_id", str).casefold() == did.casefold()]
            if not matched:
                values.append(None)
                continue
            redundancies = [get(copy, "properties.backupStorageRedundancy", str) for copy in matched]
            if any(value in ("Local", "Zone") for value in redundancies):
                values.append(True)
            elif all(value in ("Geo", "GeoZone") for value in redundancies):
                values.append(False)
            else:
                values.append(None)
        except Unavailable:
            values.append(None)
    return _verdict(values)


@_signed("azure.cis.enforce_ssl_connection_mysql_server", "encryption", "mysql_single_server", "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server", "medium", "Enable SSL enforcement on each legacy MySQL Single Server.", ["mysql_single_server"])
def mysql_ssl(item, index):
    values = []
    for row in _rows(index, item, "mysql_single_server"):
        try:
            value = get(row, "properties.sslEnforcement", str)
            values.append({"Enabled": False, "Disabled": True}.get(value))
        except Unavailable:
            values.append(None)
    return _verdict(values)


@_signed("azure.cis.mysql_single_audit_log_enabled", "logging", "mysql_single_server", "Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL Database Server", "medium", "Set audit_log_enabled=ON for every legacy MySQL Single Server.", ["mysql_single_server", "mysql_single_configuration"])
def mysql_audit(item, index):
    servers = _rows(index, item, "mysql_single_server")
    if not servers:
        return _verdict([])
    configs = _rows(index, item, "mysql_single_configuration")
    values = []
    for server in servers:
        sid = get(server, "id", str)
        try:
            matches = [c for c in configs if get(c, "parent_id", str).casefold() == sid.casefold() and get(c, "name", str).casefold() == "audit_log_enabled"]
            if len(matches) != 1:
                values.append(None)
                continue
            if get(matches[0], "id", str).casefold() != sid.casefold() + "/configurations/audit_log_enabled":
                raise Unavailable("foreign MySQL configuration identity")
            value = get(matches[0], "properties.value", str)
            values.append({"ON": False, "OFF": True}.get(value))
        except Unavailable:
            values.append(None)
    return _verdict(values)


@_signed("azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5", "encryption", "sql_database", "SQL databases and managed-instance databases have TDE enabled", "high", "Enable transparent data encryption for SQL and managed-instance databases.", ["sql_database", "sql_tde", "managed_instance_database", "managed_instance_tde"])
def sql_tde(item, index):
    sql_dbs, sql_missing = _maybe_rows(index, item, "sql_database")
    mi_dbs, mi_missing = _maybe_rows(index, item, "managed_instance_database")
    sql_tdes, sql_tde_missing = _maybe_rows(index, item, "sql_tde")
    mi_tdes, mi_tde_missing = _maybe_rows(index, item, "managed_instance_tde")
    dbs = [(d, sql_tdes, sql_tde_missing) for d in sql_dbs if get(d, "id", str).rsplit("/", 1)[-1].casefold() not in ("master", "model", "msdb", "tempdb")]
    dbs += [(d, mi_tdes, mi_tde_missing) for d in mi_dbs]
    values = []
    for db, tdes, tde_missing in dbs:
        did = get(db, "id", str)
        try:
            if tde_missing:
                values.append(None)
                continue
            allowed_ids = {did.casefold(), (did + "/transparentDataEncryption/current").casefold()}
            matches = [t for t in tdes if get(t, "parent_id", str).casefold() == did.casefold()
                       and get(t, "id", str).casefold() in allowed_ids]
            if len(matches) != 1:
                raise Unavailable("current TDE child absent or ambiguous")
            tde = matches[0]
            value = get(tde, "properties.state", str)
            values.append({"Enabled": False, "Disabled": True}.get(value))
        except Unavailable:
            values.append(None)
    if sql_missing or mi_missing:
        values.append(None)
    return _verdict(values)


def _diagnostic(index, item, resource_kind, selected, *, workspace_only=False):
    resources = _rows(index, item, resource_kind)
    required = _names(_policy(index, "requiredCategories", list))
    approved = _names(_policy(index, "approvedSinkIds", list))
    if selected is not None:
        selected = _names(selected)
        resources = [r for r in resources if get(r, "type", str).casefold() in selected]
    if not resources:
        return _verdict([])
    settings = _rows(index, item, "diagnostic_setting")
    categories = _rows(index, item, "diagnostic_category")
    values = []
    for resource in resources:
        rid = get(resource, "id", str)
        supported = {get(c, "name", str).casefold() for c in categories if get(c, "parent_id", str).casefold() == rid.casefold()}
        if not required <= supported:
            values.append(None)
            continue
        attached = [s for s in settings if get(s, "parent_id", str).casefold() == rid.casefold()]
        covered = set()
        for setting in attached:
            if not get(setting, "id", str).casefold().startswith(rid.casefold() + "/providers/microsoft.insights/diagnosticsettings/"):
                raise Unavailable("foreign diagnostic setting identity")
            props = get(setting, "properties", dict)
            keys = ("workspaceId",) if workspace_only else ("workspaceId", "storageAccountId", "eventHubAuthorizationRuleId")
            sinks = [props.get(k) for k in keys]
            if not any(isinstance(sink, str) and sink.casefold() in approved for sink in sinks):
                continue
            for log in get(props, "logs", list):
                if get(log, "enabled", bool):
                    name = log.get("category")
                    group = log.get("categoryGroup")
                    if isinstance(name, str):
                        covered.add(name.casefold())
                    if isinstance(group, str):
                        covered.update(get(c, "name", str).casefold() for c in categories if get(c, "parent_id", str).casefold() == rid.casefold() and group.casefold() in [g.casefold() for g in get(c, "categoryGroups", list)])
        values.append(not required <= covered)
    return _verdict(values)


@_signed("azure.gap.audit_diagnostic_setting", "logging", "resource", "Audit diagnostic setting for selected resource types", "medium", "Route each required diagnostic log category to an approved sink.", ["resource", "diagnostic_setting", "diagnostic_category"])
def audit_diagnostic(item, index):
    return _diagnostic(index, item, "resource", _policy(index, "selectedResourceTypes", list))


@_signed("azure_sql_database_sqlserver_auditing_enabled_77d6841", "logging", "sql_database", "Azure SQL databases export required resource logs to Log Analytics", "medium", "Route required SQL diagnostic categories to an approved Log Analytics workspace.", ["sql_database", "diagnostic_setting", "diagnostic_category"])
def sql_diagnostic(item, index):
    return _diagnostic(index, item, "sql_database", None, workspace_only=True)


@_signed("azure.gap.asset_inventory_required_metadata", "hardening", "resource", "Azure resources have required inventory metadata", "medium", "Add nonblank required tags to every in-scope ARM resource.", ["resource_graph"])
def asset_metadata(item, index):
    rows = _rows(index, item, "resource_graph")
    scope = _scope(index, item)
    required = _names(_policy(index, "requiredTagKeys", list))
    types = _names(_policy(index, "inScopeResourceTypes", list))
    values = []
    for row in rows:
        if get(row, "subscriptionId", str).casefold() != scope.rsplit("/", 1)[-1].casefold():
            values.append(None)
            continue
        if get(row, "type", str).casefold() not in types:
            continue
        get(row, "location", str)
        tags = get(row, "tags", dict)
        normalized = {k.casefold(): v for k, v in tags.items() if isinstance(k, str)}
        values.append(any(not isinstance(normalized.get(key), str) or not normalized[key].strip() for key in required))
    return _verdict(values)


@_signed("azure.other.region_allowlist", "hardening", "resource", "Deploy resources only in approved Azure regions", "high", "Enforce approved regions and zones and verify regional controls and operations.", ["resource", "regional_control_evidence"], allow_incomplete_failure=True)
def region_allowlist(item, index):
    rows = _rows(index, item, "resource")
    owner = _policy_root(index)
    if ("status" in owner and owner["status"] != "collected" or
            "scope" in owner and (not isinstance(owner["scope"], str) or owner["scope"].casefold() != _scope(index, item).casefold())):
        raise Unavailable("regional approval is unavailable or belongs to another subscription")
    regions = _names(_policy(index, "approvedRegions", list))
    declared_exemptions = _policy(index, "globalResourceTypes", list)
    exemptions = _names(declared_exemptions) if declared_exemptions else set()
    declared_zones = get(_policy_root(index), "approvedZones", dict)
    resource_type = r"[A-Za-z][A-Za-z0-9.-]*/[A-Za-z][A-Za-z0-9]*(?:/[A-Za-z][A-Za-z0-9]*)*"
    if (any(not isinstance(kind, str) or not re.fullmatch(resource_type, kind)
            for kind in declared_zones) or
            len({kind.casefold() for kind in declared_zones}) != len(declared_zones)):
        raise Unavailable("ambiguous approved availability-zone resource types")
    # Imported snapshots bypass connector intake. Require the same numeric,
    # unique zone criteria before they can authorize a regional PASS.
    for approved in declared_zones.values():
        if (not isinstance(approved, list) or
                any(not isinstance(zone, str) or not re.fullmatch(r"[1-9][0-9]{0,2}", zone)
                    for zone in approved) or len(set(approved)) != len(approved)):
            raise Unavailable("approved availability zones malformed")
    zones = {kind.casefold(): value for kind, value in declared_zones.items()}
    values = []
    for row in rows:
        kind = get(row, "type", str).casefold()
        identity = get(row, "id", str).casefold()
        parts = identity.rsplit("/providers/", 1)
        tail = parts[1].split("/") if len(parts) == 2 else []
        if (len(tail) < 3 or len(tail) % 2 != 1 or
                kind != "/".join([tail[0], *tail[1::2]]) or
                any(segment in (".", "..") for segment in identity.split("/"))):
            raise Unavailable("resource type differs from its ARM identity")
        if kind in exemptions:
            continue
        try:
            location = get(row, "location", str).casefold()
        except Unavailable:
            values.append(None)
            continue
        if not re.fullmatch(r"[a-z][a-z0-9]{0,62}", location) or location == "global":
            values.append(None)
            continue
        if location not in regions:
            values.append(True)
            continue
        try:
            declared = get(row, "zones", list)
        except Unavailable:
            values.append(None)
            continue
        if (any(not isinstance(zone, str) or not re.fullmatch(r"[1-9][0-9]{0,2}", zone)
                for zone in declared) or len(set(declared)) != len(declared)):
            values.append(None)
            continue
        approved = zones.get(kind)
        if approved is None or not isinstance(approved, list):
            values.append(None)
        else:
            values.append(any(z not in approved for z in declared))
    if any(x is True for x in values):
        return result(True, evaluated=len(values))
    evidence = _rows(index, item, "regional_control_evidence")
    if len(evidence) != 1:
        return unknown("regional deployment, secret probe, and operations evidence absent")
    try:
        control = evidence[0]
        denied = get(control, "properties.disallowedDeploymentDenied", bool)
        secret = get(control, "properties.unauthorizedRegionSecretDenied", bool)
        eu = get(control, "properties.euOperationsVerified", bool)
    except Unavailable:
        return unknown("regional control evidence incomplete")
    return _verdict(values + [not denied, not secret, not eu], empty="UNKNOWN")


def _freshness(item, index, days, *, require_active):
    envelopes = get(get(index, "collections", dict), "backup_protected_item", list)
    partial = any(get(envelope, "status", str) == "partial" for envelope in envelopes)
    rows = _rows(index, item, "backup_protected_item", allow_partial=partial)
    wanted = _names(_policy(index, "requiredBackupItemIds", list))
    now = _time(get(index, "context.created_at", str))
    by_id = {get(r, "id", str).casefold(): r for r in rows}
    values = []
    for rid in wanted:
        row = by_id.get(rid)
        if row is None:
            values.append(None)
            continue
        try:
            props = get(row, "properties", dict)
        except Unavailable:
            values.append(None)
            continue
        try:
            status = get(props, "lastBackupStatus", str)
        except Unavailable:
            status = None
        try:
            state = get(props, "protectionState", str)
        except Unavailable:
            state = None
        if status in ("Failed", "Failure", "Unhealthy") or (require_active and state in ("ProtectionStopped", "NotProtected")):
            values.append(True)
            continue
        try:
            recovery = _time(get(props, "lastRecoveryPoint", str))
        except Unavailable:
            values.append(None)
            continue
        if recovery <= now and recovery < now - timedelta(days=days):
            values.append(True)
        elif recovery > now or status not in ("Completed", "Succeeded", "Success") or state not in ("Protected", "ProtectionConfigured", "ProtectionStopped", "NotProtected") or (require_active and state not in ("Protected", "ProtectionConfigured")):
            values.append(None)
        else:
            values.append(False)
    verdict = _verdict(values, empty="UNKNOWN")
    if partial and verdict[0] != "FAIL":
        return unknown("partial backup inventory cannot certify recovery-point freshness")
    return verdict


@_signed("azure.other.backup_freshness_14_days", "recovery", "backup_protected_item", "Backup freshness within 14 days", "medium", "Create a successful recovery point within the declared 14-day window.", ["backup_protected_item"], allow_incomplete_failure=True)
def backup_14(item, index):
    return _freshness(item, index, 14, require_active=False)


@_signed("azure.other.backup_freshness_30_days", "recovery", "backup_protected_item", "Backup freshness within 30 days", "medium", "Restore active protection and create a recovery point within 30 days.", ["backup_protected_item"], allow_incomplete_failure=True)
def backup_30(item, index):
    return _freshness(item, index, 30, require_active=True)


@_signed("azure_c5_ops_07_01b", "recovery", "backup_protected_item", "Azure Backup protected items have successful recent recovery points", "medium", "Monitor each backup job and retain documented OPS-06 evidence.", ["backup_protected_item", "backup_job", "backup_monitor_evidence", "recovery_vault"], allow_incomplete_failure=True)
def backup_monitoring(item, index):
    from . import azure_backup_evidence as native
    max_age = _policy(index, 'ops06MaxAgeDays', int)
    if max_age <= 0:
        raise Unavailable('invalid OPS-06 age threshold')
    freshness = _freshness(item, index, max_age, require_active=True)
    # Retained native backup failure still disproves the control independently
    # of an unavailable external monitoring/authorization inventory.
    if freshness[0] == 'FAIL':
        return freshness
    jobs = _rows(index, item, 'backup_job')
    evidence = _rows(index, item, 'backup_monitor_evidence')
    if freshness[0] != 'PASS' or not jobs or not evidence:
        return unknown('backup, job correlation or monitoring policy incomplete')
    capture = native.backup_restore_native_capture(index)
    wanted = _names(_policy(index, 'requiredBackupItemIds', list))
    classified = _policy(index, 'requiredBackupItems', list)
    if not classified or any(not isinstance(x, dict) for x in classified):
        return unknown('OPS-06 data-class and workload scope absent')
    by_id = {get(x, 'id', str).casefold(): x for x in classified}
    if set(by_id) != wanted or len(by_id) != len(classified):
        return unknown('OPS-06 classified item scope differs from backup policy')
    protected = {get(r, 'id', str).casefold(): r for r in _rows(index, item, 'backup_protected_item')}
    if len(evidence) != len(wanted):
        raise Unavailable('monitoring evidence roster differs from required item scope')
    policy_document = native.text(_policy(index, 'ops06DocumentId', str))
    end = _time(get(index, 'context.created_at', str))
    start = end - timedelta(days=max_age)
    job_by_id = {get(j, 'id', str).casefold(): j for j in jobs}
    failed = []
    unresolved = []
    for rid in wanted:
        if rid not in protected:
            raise Unavailable('required monitored item absent from native roster')
        protected_item = protected[rid]
        expected_class = native.text(get(by_id[rid], 'dataClass', str))
        workload = get(by_id[rid], 'workloadType', str)
        native.backup_restore_arm_resource(get(protected_item, 'id', str))
        if (get(protected_item, 'properties.workloadType', str) != workload
                or get(protected_item, 'properties.backupManagementType', str) != 'AzureIaasVM'
                or get(protected_item, 'properties.protectedItemType', str) != 'Microsoft.Compute/virtualMachines'):
            raise Unavailable('unsupported or inconsistent monitored native workload')
        vault = get(protected_item, 'parent_id', str)
        segment = r'[^/?#%\x00-\x20]+'
        if not re.fullmatch(re.escape(vault) + r'/backupFabrics/' + segment
                + r'/protectionContainers/' + segment + r'/protectedItems/' + segment,
                get(protected_item, 'id', str), re.I):
            raise Unavailable('monitoring native protected item ARM kind unresolved')
        matched = [e for e in evidence if get(e, 'properties.protectedItemId', str).casefold() == rid]
        if len(matched) != 1:
            raise Unavailable('monitoring evidence exact item binding unresolved')
        record = matched[0]
        props = get(record, 'properties', dict)
        validation = get(props, 'monitoringValidation', dict)
        for observed in (record, validation):
            proof = get(observed, '_provenance', dict)
            if (get(proof, 'source_operation', str) != 'external:backup-monitor-validation'
                    or get(proof, 'representation', str) != 'full' or get(proof, 'read_only', bool) is not True):
                raise Unavailable('monitoring evidence is not full external validation')
        if (get(record, 'scope', str).casefold() != _scope(index, item).casefold()
                or not native.current(validation, index)
                or get(validation, 'policyDocumentId', str) != policy_document
                or native.instant(get(validation, 'windowStart', str)) > start
                or native.instant(get(validation, 'windowEnd', str)) < end
                or get(validation, 'historyComplete', bool) is not True):
            raise Unavailable('monitoring authorization, policy or history window unresolved')
        for value in (props, validation):
            if (get(value, 'protectedItemId', str).casefold() != rid
                    or get(value, 'workloadType', str) != workload or get(value, 'dataClass', str) != expected_class):
                raise Unavailable('monitoring external item/class/workload mapping differs')
        if any(get(validation, key, str) != capture[key] for key in ('credential_context_id', 'customer_context_id')):
            raise Unavailable('monitoring external evidence capture differs')
        vault_jobs = [job for job in jobs if get(job, 'parent_id', str).casefold() == vault.casefold()]
        if get(validation, 'nativeEvidenceSha256', str) != native.backup_restore_digest(
                {'protected_item': protected_item, 'jobs': vault_jobs, 'capture': capture}):
            raise Unavailable('monitoring native evidence digest differs')
        observed_ids = native.strings(get(props, 'observedJobIds', list), nonempty=True)
        bindings = get(validation, 'jobBindings', list)
        binding_ids, completed, observed_missing = set(), False, False
        for binding in bindings:
            jid = get(binding, 'jobId', str).casefold()
            if jid in binding_ids or jid not in job_by_id:
                raise Unavailable('monitoring duplicate or uncollected native job binding')
            binding_ids.add(jid)
            job = job_by_id[jid]
            native.backup_restore_arm_resource(get(job, 'id', str))
            if (not re.fullmatch(re.escape(vault) + r'/backupJobs/[^/?#%\x00-\x20]+', get(job, 'id', str), re.I)
                    or get(job, 'parent_id', str).casefold() != vault.casefold()
                    or get(job, 'properties.operation', str) != 'Backup'
                    or get(job, 'properties.jobType', str) not in ('AzureIaaSVMJob', 'AzureIaaSVMJobV2')
                    or get(job, 'properties.backupManagementType', str) != 'AzureIaasVM'):
                raise Unavailable('monitoring job has unsupported native operation or workload')
            if (get(binding, 'protectedItemId', str).casefold() != rid
                    or get(binding, 'workloadType', str) != workload or get(binding, 'dataClass', str) != expected_class):
                raise Unavailable('monitoring exact external job/item/class mapping differs')
            state = get(job, 'properties.status', str)
            if state not in ('Completed', 'Failed', 'Cancelled') or get(binding, 'jobStatus', str) != state:
                raise Unavailable('monitoring native job outcome unavailable or inconsistent')
            begin = _time(get(job, 'properties.startTime', str))
            finish = _time(get(job, 'properties.endTime', str))
            observed_at = _time(get(binding, 'observedAt', str))
            if not begin <= finish <= observed_at <= end:
                raise Unavailable('monitoring native execution/observation timing inconsistent')
            if not re.fullmatch(r'[0-9a-f]{64}', get(binding, 'resultArtifactSha256', str)):
                raise Unavailable('monitoring result artifact binding unresolved')
            outcome = get(binding, 'monitoringResult', str)
            if outcome not in ('DocumentedAndRouted', 'MissingDocumentation', 'MissingAlertRouting'):
                raise Unavailable('monitoring result semantics unresolved')
            if start <= finish:
                completed = completed or state == 'Completed'
                observed_missing = observed_missing or outcome != 'DocumentedAndRouted'
                if state == 'Failed':
                    failed.append(rid)
        if binding_ids != {jid.casefold() for jid in observed_ids}:
            raise Unavailable('monitoring observed job roster differs from explicit bindings')
        documented = get(props, 'ops06Documented', bool)
        routed = get(props, 'jobAlertsRouted', bool)
        if observed_missing:
            if documented and routed:
                raise Unavailable('monitoring summary conflicts with observed missing process')
            failed.append(rid)
        elif not documented or not routed:
            raise Unavailable('monitoring summary contradicts independent result')
        # A confirmed current scoped backup/process violation does not need a
        # successful sibling execution. Validate every binding and summary
        # first so unavailable or contradictory authority still stays UNKNOWN.
        if not completed and rid not in failed:
            unresolved.append(rid)
    if unresolved and not failed:
        return unknown('no recent completed independently monitored backup job', item_id=sorted(unresolved)[0])
    return result(bool(failed), monitored_items=len(wanted), failed_item_ids=sorted(set(failed)),
        semantics='Native Azure VM backup metadata joined to explicitly supplied independently authorized OPS-06 observations; no delivery probe performed')


def _nsg_rules(row):
    props = get(row, "properties", dict)
    rules = get(props, "securityRules", list) + get(props, "defaultSecurityRules", list)
    priorities = set()
    for rule in rules:
        priority = get(rule, "properties.priority", int)
        direction = get(rule, "properties.direction", str)
        if direction not in ("Inbound", "Outbound"):
            raise Unavailable("invalid NSG rule direction")
        key = (direction, priority)
        if key in priorities or not 100 <= priority <= 65500:
            raise Unavailable("duplicate or invalid NSG priority")
        priorities.add(key)
    return sorted(rules, key=lambda x: get(x, "properties.priority", int))


@_signed("azure_nsg_world_ingress_approved_ports", "network", "nsg", "World-source NSG ingress uses approved ports", "high", "Restrict world ingress to approved TCP and UDP ports.", ["nsg", "nsg_effective_internet_path"], empty_applicability_dependencies=("nsg",))
def nsg_ports(item, index):
    rows = _rows(index, item, "nsg")
    if not rows:
        return _verdict([])
    paths = _rows(index, item, "nsg_effective_internet_path")
    known = {get(row, "id", str).casefold() for row in rows}
    if any(get(path, "parent_id", str).casefold() not in known for path in paths):
        raise Unavailable("effective path refers to an uncollected NSG")
    approved = _policy(index, "approvedInternetPorts", list)
    if any(type(p) is not int or p < 1 or p > 65535 for p in approved):
        raise Unavailable("invalid approved port policy")
    allowed = set(approved)
    values = []
    for row in rows:
        try:
            nid = get(row, "id", str)
            _nsg_rules(row)  # malformed or omitted NSG rule sets cannot pass
            matched = [p for p in paths if get(p, "parent_id", str).casefold() == nid.casefold()]
            for path in matched:
                props = get(path, "properties", dict)
                protocol = get(props, "protocol", str)
                port = get(props, "destinationPort", int)
                if protocol not in ("Tcp", "Udp") or not 1 <= port <= 65535:
                    raise Unavailable("invalid effective Internet path")
                if not get(props, "worldSource", bool) or not get(props, "allowed", bool):
                    raise Unavailable("effective Internet path is not a world Allow")
            values.append(any(get(p, "properties.destinationPort", int) not in allowed for p in matched))
        except Unavailable:
            values.append(None)
    return _verdict(values)


@_signed("azure.other.nsg_port_protocol_assignment", "network", "nsg", "Internet ingress uses approved protocol and port pairs", "medium", "Validate the measured service on every exposed protocol and port against the IANA registry.", ["nsg", "nsg_effective_internet_path", "nsg_service_measurement"], empty_applicability_dependencies=("nsg",))
def nsg_service_pairs(item, index):
    # These are supplied authoritative inventory records, not service discovery.
    # Approval is an upstream trust boundary; hashes bind bytes, not signatures.
    def supplied_observation(measurement, nsg, path, protocol, port, actual):
        from hashlib import sha256
        import json
        def digest(value):
            return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        context = get(index, 'context', dict)
        scope = _scope(index, item)
        current = _time(get(context, 'created_at', str))
        authority = _policy(index, 'serviceObservationAuthority', dict)
        if (get(authority, 'scope', str).casefold() != scope.casefold()
                or get(authority, 'checkId', str) != 'azure.other.nsg_port_protocol_assignment'
                or not get(authority, 'documentId', str).strip()
                or not get(authority, 'authorizedBy', str).strip()):
            raise Unavailable('service inventory approval scope unresolved')
        if not _time(get(authority, 'approvedAt', str)) <= current <= _time(get(authority, 'expiresAt', str)):
            raise Unavailable('service inventory approval not current')
        age = get(authority, 'maxAgeSeconds', int)
        if type(age) is not int or not 1 <= age <= 86400:
            raise Unavailable('service inventory freshness bound invalid')
        observation = get(measurement, 'properties.observation', dict)
        source = get(observation, 'sourceId', str)
        method = get(observation, 'method', str)
        if (source not in _names(get(authority, 'approvedSourceIds', list))
                or method != 'passive-service-inventory'
                or method not in _names(get(authority, 'approvedMethods', list))
                or get(observation, 'readOnly', bool) is not True):
            raise Unavailable('service inventory source or passive method not approved')
        observed = _time(get(observation, 'observedAt', str))
        if not current - timedelta(seconds=age) <= observed <= current:
            raise Unavailable('service inventory observation stale or future')
        for field, expected in (('scope', scope), ('nsgId', get(nsg, 'id', str)), ('pathId', get(path, 'id', str))):
            if get(observation, field, str).casefold() != expected.casefold():
                raise Unavailable('service inventory resource binding differs')
        if (get(observation, 'checkId', str) != 'azure.other.nsg_port_protocol_assignment'
                or get(observation, 'protocol', str) != protocol
                or type(get(observation, 'port', int)) is not int
                or get(observation, 'port', int) != port
                or get(observation, 'service', str) != actual):
            raise Unavailable('service inventory protocol/port/service binding differs')
        # Bind the exact current independently approved snapshot facts, including
        # customer/credential capture identities when the snapshot supplies them.
        capture = {'scope': scope, 'created_at': get(context, 'created_at', str)}
        metadata = get(context, 'metadata', dict)
        for field in ('credential_context_id', 'customer_context_id'):
            if field in metadata:
                capture[field] = get(metadata, field, str)
        if get(observation, 'capture', dict) != capture:
            raise Unavailable('service inventory capture differs')
        snapshot_digest = digest({'nsg': nsg, 'path': path, 'capture': capture})
        if (get(observation, 'snapshotSha256', str) != snapshot_digest
                or snapshot_digest not in _names(get(authority, 'approvedSnapshotSha256s', list))):
            raise Unavailable('service inventory snapshot not independently approved')
        if not re.fullmatch(r'[0-9a-f]{64}', get(observation, 'artifactSha256', str)):
            raise Unavailable('service inventory artifact binding unresolved')
        if digest(observation) not in _names(get(authority, 'approvedObservationSha256s', list)):
            raise Unavailable('service inventory exact observation not independently approved')
    nsgs = _rows(index, item, "nsg")
    if not nsgs:
        return "NOT_APPLICABLE", {"reason": "no NSGs in complete inventory"}
    paths = _rows(index, item, "nsg_effective_internet_path")
    measured = _rows(index, item, "nsg_service_measurement")
    known = {get(row, "id", str).casefold() for row in nsgs}
    by_path = {get(path, "id", str).casefold(): path for path in paths}
    if any(get(path, "parent_id", str).casefold() not in known for path in paths):
        raise Unavailable("effective path refers to an uncollected NSG")
    for measurement in measured:
        pid = get(measurement, "path_id", str).casefold()
        if pid not in by_path or get(measurement, "parent_id", str).casefold() != get(by_path[pid], "parent_id", str).casefold():
            raise Unavailable("service measurement refers to an uncollected path")
    from peaso.collectors.iana_service_assignments import assigned_services, SOURCE_URL, SOURCE_SHA256
    if not paths:
        return result(False, exposed_paths=0)
    values = []
    for nsg in nsgs:
        nid = get(nsg, "id", str)
        try:
            _nsg_rules(nsg)
            exposed = [p for p in paths if get(p, "parent_id", str).casefold() == nid.casefold()]
            for path in exposed:
                try:
                    pid = get(path, "id", str)
                    props_path = get(path, "properties", dict)
                    protocol = get(props_path, "protocol", str)
                    port = get(props_path, "destinationPort", int)
                    if protocol not in ("Tcp", "Udp") or not 1 <= port <= 65535 or not get(props_path, "worldSource", bool) or not get(props_path, "allowed", bool):
                        raise Unavailable("malformed effective world ingress path")
                    matches = [m for m in measured if get(m, "path_id", str).casefold() == pid.casefold()]
                    if len(matches) != 1:
                        values.append(None)
                        continue
                    props = get(matches[0], "properties", dict)
                    if get(props, "protocol", str) != protocol or get(props, "port", int) != port:
                        values.append(None)
                        continue
                    actual = get(props, "measuredService", str)
                    claimed = get(props, "ianaAssignedService", str)
                    if not actual.strip() or not claimed.strip():
                        values.append(None)
                        continue
                    supplied_observation(matches[0], nsg, path, protocol, port, actual)
                    official = assigned_services(protocol, port)
                    if not official:
                        values.append(None)
                    elif actual.casefold() not in official:
                        values.append(True)
                    elif claimed.casefold() not in official:
                        values.append(None)
                    else:
                        values.append(False)
                except Unavailable:
                    values.append(None)
        except Unavailable:
            values.append(None)
    status, evidence = _verdict(values, empty="UNKNOWN")
    evidence.update(iana_source=SOURCE_URL, iana_source_sha256=SOURCE_SHA256)
    return status, evidence
