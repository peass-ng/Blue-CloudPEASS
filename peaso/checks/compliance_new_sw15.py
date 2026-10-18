"""Signed Azure compliance slice sw15; pure evaluators over captured facts.

Evidence records described in sw15-collector-requests.md are intentionally
required where configuration cannot establish the signed behavioral claim.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone, timedelta
from ipaddress import IPv4Address
import re
from urllib.parse import urlsplit

from . import CHECKS, register as _register, result, unknown
from .facts import Unavailable, complete_items, get, optional, list_of_objects

from .compliance_new_sw15_specs import IDS, SPECS, SPEC_SHA256
CHECK_BY_ID = {}

# register() currently admits only the five native operational categories.
# Preserve the signed category on our own frozen Check after using its normal
# safe evaluator wrapper. No existing registration is changed.
def register(check_id, *, dependencies, target="resource"):
    spec = SPECS[check_id]
    category = {"identity": "least_privilege", "encryption": "hardening",
                "logging": "hardening", "recovery": "hardening",
                "monitoring": "least_privilege"}.get(spec["category"], spec["category"])
    def decorate(fn):
        _register(check_id, spec["provider"], category, spec["resource_kind"],
                  spec["title"], spec["severity"], "CM-6", spec["remediation_hint"],
                  dependencies=dependencies, target=target)(fn)
        position = next(i for i, check in enumerate(CHECKS) if check.id == check_id)
        CHECKS[position] = replace(CHECKS[position], category=spec["category"])
        CHECK_BY_ID[check_id] = CHECKS[position]
        return fn
    return decorate


_SUB = re.compile(r"/subscriptions/[^/?#]+\Z", re.I)
_ARM = re.compile(r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/[^/?#]+/[^/?#]+/[^/?#]+(?:/[^/?#]+/[^/?#]+)*\Z", re.I)
_SUB_RESOURCE = re.compile(r"/subscriptions/[^/?#]+/providers/[^/?#]+/[^/?#]+/[^/?#]+(?:/[^/?#]+/[^/?#]+)*\Z", re.I)
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z", re.I)


def _scope(index):
    context = get(index, "context", dict)
    scope = get(context, "scope", str)
    if get(context, "provider", str) != "azure" or not _SUB.fullmatch(scope):
        raise Unavailable("Azure subscription authority unavailable")
    return scope


def _arm(value, scope=None):
    if not isinstance(value, str) or not (_ARM.fullmatch(value) or _SUB.fullmatch(value) or _SUB_RESOURCE.fullmatch(value)):
        raise Unavailable("malformed ARM identity")
    if scope and value.casefold() != scope.casefold() and not value.casefold().startswith(scope.casefold() + "/"):
        raise Unavailable("foreign ARM identity")
    return value.casefold()


def _rows(index, kind, scope=None):
    scope = _scope(index) if scope is None else scope
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or not envelopes:
        raise Unavailable("inventory unavailable: " + kind)
    native, envelope_scopes = [], set()
    for envelope in envelopes:
        actual = get(envelope, "scope", str)
        if actual.casefold() != scope.casefold() or get(envelope, "type", str) != kind:
            raise Unavailable("foreign collection: " + kind)
        if actual.casefold() in envelope_scopes:
            raise Unavailable("duplicate collection scope: " + kind)
        envelope_scopes.add(actual.casefold())
        values = list_of_objects(get(envelope, "items", list))
        status = get(envelope, "status", str)
        if status not in ("collected", "empty") or (status == "empty") != (not values):
            raise Unavailable("incomplete or contradictory inventory: " + kind)
        native.extend(values)
    rows = complete_items(index, kind)
    wrappers = get(index, kind, list)
    if len(rows) != len(native) or len(wrappers) != len(native):
        raise Unavailable("inventory projection differs: " + kind)
    seen = set()
    for wrapper, row, original in zip(wrappers, rows, native):
        if (get(wrapper, "type", str) != kind or get(wrapper, "scope", str).casefold() != scope.casefold()
                or row != original):
            raise Unavailable("foreign or inconsistent resource projection")
        identity = _arm(get(row, "id", str), _scope(index))
        native_types = {
            "web_app": r"/microsoft\.web/sites/[^/]+$",
            "function_app": r"/microsoft\.web/sites/[^/]+$",
            "vault": r"/microsoft\.keyvault/vaults/[^/]+$",
            "key_vault_secret": r"/microsoft\.keyvault/vaults/[^/]+/secrets/[^/]+$",
            "vault_secret": r"/microsoft\.keyvault/vaults/[^/]+/secrets/[^/]+$",
            "action_group": r"/microsoft\.insights/actiongroups/[^/]+$",
            "monitor_log_profile": r"/providers/microsoft\.insights/logprofiles/[^/]+$",
            "storage_service": r"/microsoft\.storage/storageaccounts/[^/]+/blobservices/default$",
            "vm": r"/microsoft\.compute/virtualmachines/[^/]+$",
            "vm_scale_set": r"/microsoft\.compute/virtualmachinescalesets/[^/]+$",
            "nic": r"/microsoft\.network/networkinterfaces/[^/]+$",
            "mysql_flexible_server": r"/microsoft\.dbformysql/flexibleservers/[^/]+$",
            "postgresql_flexible_server": r"/microsoft\.dbforpostgresql/flexibleservers/[^/]+$",
            "sql_server": r"/microsoft\.sql/servers/[^/]+$",
            "build_agent": r"/(?:microsoft\.devopsinfrastructure/pools|microsoft\.compute/virtualmachines)/[^/]+$",
        }
        if kind == "subscription" and identity != _scope(index).casefold():
            raise Unavailable("foreign subscription record")
        if kind in native_types and not re.search(native_types[kind], identity):
            raise Unavailable("resource native type differs from snapshot kind")
        if identity in seen:
            raise Unavailable("duplicate resource identity")
        seen.add(identity)
    return rows


def _member(item, index, kind):
    rid = _arm(get(item, "id", str), _scope(index))
    if sum(row == item for row in _rows(index, kind)) != 1:
        raise Unavailable("resource not uniquely bound to collected inventory")
    return rid



def _policy_copy(container, key):
    coverage = container.get("_coverage", {})
    if not isinstance(coverage, dict):
        raise Unavailable("policy namespace coverage malformed")
    if key in coverage:
        entry = coverage[key]
        if not isinstance(entry, dict) or entry.get("status") != "collected":
            raise Unavailable("declared policy copy unavailable or contradictory")
    return get(container, key, dict)


def _policy(index):
    metadata = get(index, "context.metadata", dict)
    coverage = metadata.get("_coverage", {})
    if not isinstance(coverage, dict):
        raise Unavailable("policy namespace coverage malformed")
    legacy_declared = "sw15" in metadata or "sw15" in coverage
    modern_declared = "compliance_policy" in metadata or "compliance_policy" in coverage
    candidates = []
    if legacy_declared:
        candidates.append(_policy_copy(metadata, "sw15"))
    if modern_declared:
        modern = _policy_copy(metadata, "compliance_policy")
        modern_coverage = modern.get("_coverage", {})
        if not isinstance(modern_coverage, dict):
            raise Unavailable("modern policy namespace coverage malformed")
        if "sw15" in modern or "sw15" in modern_coverage:
            candidates.append(_policy_copy(modern, "sw15"))
    if not candidates or len(candidates) == 2 and candidates[0] != candidates[1]:
        raise Unavailable("approved SW15 policy namespace absent or contradictory")
    policy = candidates[0]
    if get(policy, "status", str) != "collected" or _arm(get(policy, "scope", str)) != _scope(index).casefold():
        raise Unavailable("approved subscription-bound policy unavailable")
    return policy


def _strings(value):
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value) or len(value) != len(set(value)):
        raise Unavailable("malformed string list")
    return value


def _positive(value):
    if type(value) is not int or value <= 0:
        raise Unavailable("invalid positive integer")
    return value


def _time(value):
    if not isinstance(value, str):
        raise Unavailable("missing UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("malformed UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise Unavailable("timestamp is not UTC")
    return parsed


def _now(index):
    return _time(get(index, "context.created_at", str))


def _epoch(value, index):
    if type(value) is not int or value < 0:
        raise Unavailable("invalid Unix timestamp")
    instant = datetime.fromtimestamp(value, timezone.utc)
    if instant > _now(index):
        raise Unavailable("future timestamp")
    return instant


def _dated(record, index):
    policy = _policy(index)
    start, end = _time(get(policy, "observationStart", str)), _time(get(policy, "observationEnd", str))
    observed, now = _time(get(record, "observed_at", str)), _now(index)
    if not start <= observed <= now <= end:
        raise Unavailable("evidence outside approved current observation window")


def _evidence(item, field, index, *, dated=False):
    record = get(item, field, dict)
    if get(record, "status", str) != "collected" or _arm(get(record, "resource_id", str)) != _arm(get(item, "id", str)):
        raise Unavailable("unavailable or foreign evidence: " + field)
    if dated:
        _dated(record, index)
    return record


def _embedded(item, field, suffix):
    status = get(item, "_coverage." + field + ".status", str)
    values = list_of_objects(get(item, field, list))
    if status not in ("collected", "empty") or (status == "empty") != (not values):
        raise Unavailable("incomplete embedded inventory: " + field)
    parent = _arm(get(item, "id", str))
    seen = set()
    for value in values:
        child = _arm(get(value, "id", str))
        if (not child.startswith(parent + "/" + suffix.casefold() + "/") or child in seen
                or _arm(get(value, "parent_id", str)) != parent):
            raise Unavailable("foreign or duplicate child: " + field)
        seen.add(child)
    return values


def _full(item):
    if get(item, "_provenance.representation", str) != "full":
        raise Unavailable("complete API representation unavailable")


def _aggregate(rows, evaluator, *, empty_na=False):
    uncertain, failures, applicable = [], [], 0
    for row in rows:
        try:
            status, evidence = evaluator(row)
        except Unavailable as exc:
            uncertain.append(str(exc))
            continue
        if status == "FAIL":
            failures.append(evidence)
        elif status == "UNKNOWN":
            uncertain.append(evidence.get("reason", "unresolved evidence"))
        elif status == "PASS":
            applicable += 1
    if failures:
        return result(True, violations=failures, unresolved_count=len(uncertain))
    if uncertain:
        return unknown("required evidence unresolved", reasons=uncertain)
    if empty_na and not applicable:
        return "NOT_APPLICABLE", {"reason": "no applicable resources in complete inventory"}
    return result(False, evaluated_count=applicable)


def _sink(props, keys):
    sinks = []
    for key in keys:
        value = get(props, key)
        if value is None:
            continue
        if not isinstance(value, str) or not value:
            raise Unavailable("malformed configured destination")
        _arm(value)
        expected = {"workspaceId": "/microsoft.operationalinsights/workspaces/",
                    "storageAccountId": "/microsoft.storage/storageaccounts/",
                    "serviceBusRuleId": "/microsoft.servicebus/namespaces/"}[key]
        if expected not in value.casefold() or key == "serviceBusRuleId" and "/authorizationrules/" not in value.casefold():
            raise Unavailable("destination type unresolved")
        sinks.append(value.casefold())
    return sinks


def _log_export(item, index, required, allowed_keys):
    settings = _embedded(item, "diagnosticSettings", "providers/Microsoft.Insights/diagnosticSettings")
    supported = _strings(get(_evidence(item, "diagnosticCategories", index), "categories", list))
    if not set(required) <= set(supported):
        raise Unavailable("required diagnostic category support unresolved")
    policy = _policy(index)
    approved = {_arm(v) for v in _strings(get(policy, "approvedSinkIds", list))}
    resolved = {_arm(v) for v in _strings(get(policy, "resolvedSinkIds", list))}
    covered = set()
    for setting in settings:
        props = get(setting, "properties", dict)
        destinations = _sink(props, allowed_keys)
        for log in list_of_objects(get(props, "logs", list)):
            enabled = get(log, "enabled", bool)
            if "categoryGroup" in log:
                group = get(log, "categoryGroup", str)
                if group not in ("allLogs", "audit"):
                    raise Unavailable("diagnostic category group unresolved")
                # Group expansion requires measured membership rather than assumptions.
                categories = _strings(get(log, "resolvedCategories", list))
            else:
                categories = [get(log, "category", str)]
            if enabled:
                if not set(categories) <= set(supported):
                    raise Unavailable("enabled diagnostic category absent from measured support")
                if any(sink not in resolved for sink in destinations):
                    raise Unavailable("configured sink does not resolve")
                if any(sink in approved for sink in destinations):
                    covered.update(categories)
    return result(not set(required) <= covered, required_categories=sorted(required), exported_categories=sorted(covered))


@register(IDS[0], dependencies=["mysql_flexible_server"])
def mysql_audit_export(item, index):
    _member(item, index, "mysql_flexible_server")
    configs = _embedded(item, "configurations", "configurations")
    matching = [row for row in configs if get(row, "name", str) == "audit_log_enabled"]
    if len(matching) != 1:
        return unknown("audit_log_enabled configuration missing or ambiguous")
    value = get(matching[0], "properties.value", str)
    if value not in ("ON", "OFF"):
        return unknown("unrecognized audit_log_enabled value")
    if value == "OFF":
        return result(True, audit_log_enabled="OFF")
    return _log_export(item, index, {"MySqlAuditLogs"}, ("workspaceId",))


@register(IDS[14], dependencies=["servicebus_namespace"])
def servicebus_logs(item, index):
    _member(item, index, "servicebus_namespace")
    sku = get(item, "sku.name", str)
    if sku not in ("Basic", "Standard", "Premium"):
        return unknown("unknown Service Bus SKU")
    required = {"OperationalLogs"}
    if sku == "Premium" and get(_policy(index), "requireServiceBusDataPlaneAudit", bool):
        required.add("RuntimeAuditLogs")
    return _log_export(item, index, required, ("workspaceId", "storageAccountId"))


@register(IDS[3], dependencies=["web_app"])
def app_managed_identity(item, index):
    _member(item, index, "web_app")
    kind = get(item, "kind", str)
    tokens = set(kind.casefold().split(","))
    if not tokens or not tokens <= {"app", "linux", "container", "functionapp", "workflowapp"}:
        return unknown("unresolved App Service kind")
    _full(item)
    identity = optional(item, "identity", None)
    if identity is None:
        return result(True, identity_type="None")
    mode = get(identity, "type", str)
    if mode not in ("None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"):
        return unknown("unresolved managed identity state")
    principal = optional(identity, "principalId", None)
    user = optional(identity, "userAssignedIdentities", {}, dict)
    if mode == "None":
        if principal or user:
            return unknown("conflicting absent managed identity")
        return result(True, identity_type=mode)
    if "SystemAssigned" in mode and principal is not None and not (isinstance(principal, str) and _UUID.fullmatch(principal)):
        return unknown("malformed system-assigned principal")
    for rid, detail in user.items():
        _arm(rid)
        if "/microsoft.managedidentity/userassignedidentities/" not in rid.casefold() or not isinstance(detail, dict):
            raise Unavailable("unresolved user-assigned attachment")
    if "UserAssigned" not in mode and user:
        return unknown("identity type conflicts with attached identities")
    if "SystemAssigned" in mode and principal or "UserAssigned" in mode and user:
        return result(False, identity_type=mode)
    return unknown("managed identity attachment unresolved")


def _profiles(item, index):
    _member(item, index, "subscription")
    if get(item, "id", str).casefold() != _scope(index).casefold():
        raise Unavailable("subscription subject mismatch")
    rows = _rows(index, "monitor_log_profile")
    prefix = _scope(index).casefold() + "/providers/microsoft.insights/logprofiles/"
    for row in rows:
        if not get(row, "id", str).casefold().startswith(prefix):
            raise Unavailable("foreign log profile")
    return rows


@register(IDS[5], dependencies=["subscription", "monitor_log_profile"])
def profile_categories(item, index):
    profiles = _profiles(item, index)
    covered = set()
    for profile in profiles:
        props = get(profile, "properties", dict)
        categories = _strings(get(props, "categories", list))
        if not set(categories) <= {"Write", "Delete", "Action"}:
            raise Unavailable("unrecognized log profile category")
        if _sink(props, ("storageAccountId", "serviceBusRuleId")):
            covered.update(categories)
    return result(not {"Write", "Delete", "Action"} <= covered, exported_categories=sorted(covered))


@register(IDS[6], dependencies=["subscription", "monitor_log_profile"])
def profile_retention(item, index):
    def assess(profile):
        props = get(profile, "properties", dict)
        enabled = get(props, "retentionPolicy.enabled", bool)
        days = get(props, "retentionPolicy.days", int)
        if days < 0:
            raise Unavailable("invalid retention days")
        if enabled and days > 0:
            return result(days < 365, profile_id=get(profile, "id", str), days=days)
        evidence = _evidence(profile, "destinationRetention", index, dated=True)
        sink = _arm(get(evidence, "sink_id", str))
        if sink not in _sink(props, ("storageAccountId", "serviceBusRuleId")):
            raise Unavailable("retention evidence belongs to another destination")
        unlimited = get(evidence, "unlimited", bool)
        if days == 0 and unlimited:
            return result(False, retention="verified unlimited")
        if not enabled and (unlimited or get(evidence, "days", int) >= 365):
            return result(False, retention="verified destination")
        return unknown("disabled or zero-day retention not verified sufficient")
    return _aggregate(_profiles(item, index), assess, empty_na=True)


def _secret_uri(value):
    if not isinstance(value, str):
        raise Unavailable("missing secret URI")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not re.fullmatch(r"[A-Za-z0-9-]{3,24}\.vault\.azure\.net", parsed.hostname or "")
            or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.query or parsed.fragment
            or not re.fullmatch(r"/secrets/[A-Za-z0-9-]{1,127}(?:/[A-Za-z0-9-]+)?", parsed.path)):
        raise Unavailable("malformed secret URI")
    parts = parsed.path.split("/")
    return (parsed.hostname.casefold(), parts[2].casefold()), (parts[3] if len(parts) == 4 else None)


def _secret(item, index, kind):
    _member(item, index, kind)
    parent = _arm(get(item, "parent_id", str), _scope(index))
    if not _arm(get(item, "id", str)).startswith(parent + "/secrets/"):
        raise Unavailable("secret parent mismatch")
    candidates = [row for row in _rows(index, "vault") if _arm(get(row, "id", str)) == parent]
    if len(candidates) != 1:
        raise Unavailable("vault scope unresolved")
    uri = get(candidates[0], "properties.vaultUri", str)
    identity, version = _secret_uri(get(item, "data_plane_id", str))
    if (version is not None or uri.rstrip("/").casefold() != "https://" + identity[0]
            or get(item, "id", str).rsplit("/", 1)[1].casefold() != identity[1]):
        raise Unavailable("secret native URI does not match vault/name")
    return identity


def _arm_current_version(item, index, identity, current):
    """Additive exact ARM metadata binding; the legacy data-plane branch stays intact."""
    parent = _arm(get(item, "parent_id", str), _scope(index))
    rid = _arm(get(item, "id", str), _scope(index))
    expected_request = "https://management.azure.com" + rid
    current_identity, version = _secret_uri(get(current, "id", str))
    if current_identity != identity or version is None:
        raise Unavailable("ARM current version identity unresolved")
    proof = get(current, "_provenance", dict)
    if (get(proof, "attributes_source_operation", str) != "Secrets_ListVersions"
            or get(proof, "attributes_api_version", str) != "2025-07-01"):
        raise Unavailable("current attributes are not exact list-version metadata")
    attribute_request = get(proof, "attributes_request_uri", str)
    if not attribute_request.endswith("/versions") or _secret_uri(attribute_request[:-9]) != (identity, None):
        raise Unavailable("current attribute inventory target differs")
    observed = []
    records = []
    for field in ("armCurrentMetadataBefore", "armCurrentMetadata"):
        if get(item, "_coverage." + field + ".status", str) != "collected":
            raise Unavailable("ARM current observation incomplete")
        record = get(item, field, dict)
        if (_arm(get(record, "id", str), _scope(index)) != rid
                or _arm(get(record, "parent_id", str), _scope(index)) != parent
                or get(record, "type", str).casefold() != "microsoft.keyvault/vaults/secrets"
                or get(record, "name", str).casefold() != rid.rsplit("/", 1)[-1]):
            raise Unavailable("ARM current resource differs from secret/vault")
        source = get(record, "_provenance", dict)
        for key, expected in (("endpoint", "arm/secrets/get"), ("source_operation", "Secrets_Get"),
                              ("api_version", "2023-07-01"), ("read_only", True), ("values_omitted", True)):
            if source.get(key) != expected or (type(expected) is bool and type(source.get(key)) is not bool):
                raise Unavailable("ARM current operation provenance differs")
        if get(source, "request_uri", str).casefold() != expected_request:
            raise Unavailable("ARM current request does not name this exact secret")
        stamp = _time(get(source, "observed_at", str))
        if not 0 <= (_now(index) - stamp).total_seconds() <= 900:
            raise Unavailable("ARM current observation stale or future")
        observed.append(stamp)
        properties = get(record, "properties", dict)
        if set(properties) != {"secretUri", "secretUriWithVersion", "attributes"}:
            raise Unavailable("unexpected ARM current metadata fields")
        if (_secret_uri(get(properties, "secretUri", str)) != (identity, None)
                or _secret_uri(get(properties, "secretUriWithVersion", str)) != (identity, version)):
            raise Unavailable("ARM version pointer not bound to native vault/name/version")
        attributes = get(properties, "attributes", dict)
        if not set(attributes) <= {"enabled", "created", "updated", "exp", "nbf"}:
            raise Unavailable("unexpected ARM lifecycle attributes")
        get(attributes, "enabled", bool)
        _epoch(get(attributes, "created", int), index)
        for key in ("updated", "exp", "nbf"):
            if key in attributes and (type(attributes[key]) is not int or attributes[key] < 0):
                raise Unavailable("ARM lifecycle epoch malformed")
        exact = get(current, "attributes", dict)
        if any(key not in exact or exact[key] != value or type(exact[key]) is not type(value) for key, value in attributes.items()):
            raise Unavailable("ARM lifecycle attributes conflict with exact listed version")
        records.append(properties)
    if records[0] != records[1] or observed[0] > observed[1]:
        raise Unavailable("ARM current changed around version inventory")
    after = get(item, "armCurrentMetadata._provenance", dict)
    if any(proof.get(key) != value or type(proof.get(key)) is not type(value) for key, value in after.items()):
        raise Unavailable("current version provenance not bound to ARM observation")


def _versions(item, index, identity):
    status = get(item, "_coverage.versions.status", str)
    versions = list_of_objects(get(item, "versions", list))
    if status != "collected" or not versions:
        raise Unavailable("complete secret version list unavailable")
    current = get(item, "currentVersion", dict)
    if get(item, "_coverage.currentVersion.status", str) != "collected":
        raise Unavailable("current secret metadata unavailable")
    if get(current, "_provenance.endpoint", str) == "arm/secrets/get":
        _arm_current_version(item, index, identity, current)
    else:
        if get(current, "_provenance.endpoint", str) != "secrets/get" or get(current, "_provenance.read_only", bool) is not True:
            raise Unavailable("current secret GET provenance unavailable")
        request_identity, request_version = _secret_uri(get(current, "_provenance.request_uri", str))
        if request_identity != identity or request_version is not None:
            raise Unavailable("current metadata was not read from the unversioned secret endpoint")
    current_identity, current_id = _secret_uri(get(current, "id", str))
    if current_identity != identity or current_id is None:
        raise Unavailable("current secret version foreign or unresolved")
    seen, selected = set(), None
    for version in versions:
        base, version_id = _secret_uri(get(version, "id", str))
        if base != identity or version_id is None or version_id in seen:
            raise Unavailable("foreign or duplicate secret version")
        seen.add(version_id)
        _epoch(get(version, "attributes.created", int), index)
        get(version, "attributes.enabled", bool)
        if version_id == current_id:
            selected = version
    if selected is None or get(selected, "attributes", dict) != get(current, "attributes", dict):
        raise Unavailable("current version not consistently present in version inventory")
    return current, versions


@register(IDS[1], dependencies=["key_vault_secret", "vault"])
def recent_secret_use(item, index):
    identity = _secret(item, index, "key_vault_secret")
    if not get(item, "properties.attributes.enabled", bool):
        return "NOT_APPLICABLE", {"reason": "base secret is disabled"}
    days = _positive(get(_policy(index), "unusedForDays", int))
    start, end = _now(index) - timedelta(days=days), _now(index)
    history = _evidence(item, "auditHistory", index)
    if (_time(get(history, "window_start", str)) > start or _time(get(history, "window_end", str)) < end
            or _time(get(history, "retention_start", str)) > start
            or not get(history, "route_enabled", bool) or not get(history, "identifiers_comparable", bool)):
        raise Unavailable("audit route/retention/query does not cover policy window")
    success = _strings(get(history, "success_values", list))
    failures = _strings(get(history, "failure_values", list))
    if set(success) & set(failures):
        raise Unavailable("ambiguous audit success semantics")
    if not success:
        raise Unavailable("audit success semantics unavailable")
    used = False
    for event in list_of_objects(get(history, "events", list)):
        operation = get(event, "OperationName", str)
        if operation != "SecretGet":
            continue
        base, _ = _secret_uri(get(event, "SecretUri", str))
        timestamp = _time(get(event, "TimeGenerated", str))
        status = get(event, "ResultType", str)
        if status not in set(success) | set(failures) or timestamp > end or base[0] != identity[0]:
            raise Unavailable("foreign or incomparable audit record")
        used |= base == identity and start <= timestamp <= end and status in success
    return result(not used, successful_recent_secret_get=used, unused_for_days=days,
                  semantics="All versions matched by vault and base secret name")


@register(IDS[2], dependencies=["key_vault_secret", "vault"])
def secret_rotation(item, index):
    identity = _secret(item, index, "key_vault_secret")
    days = _positive(get(_policy(index), "maxDaysSinceRotation", int))
    current, _ = _versions(item, index, identity)
    if not get(current, "attributes.enabled", bool):
        return "NOT_APPLICABLE", {"reason": "authoritative current version is disabled"}
    created = _epoch(get(current, "attributes.created", int), index)
    return result(created < _now(index) - timedelta(days=days), current_version=get(current, "id", str),
                  max_days_since_rotation=days)


@register(IDS[9], dependencies=["vault_secret", "vault"])
def outdated_secret_denial(item, index):
    identity = _secret(item, index, "vault_secret")
    days = _positive(get(_policy(index), "approvedRotationDays", int))
    current, versions = _versions(item, index, identity)
    current_id = get(current, "id", str)
    current_created = _epoch(get(current, "attributes.created", int), index)
    old = []
    for version in versions:
        created = _epoch(get(version, "attributes.created", int), index)
        if get(version, "id", str) != current_id and created <= current_created and created < _now(index) - timedelta(days=days):
            old.append(version)
    def assess(version):
        evidence = get(version, "accessEvidence", dict)
        if get(evidence, "status", str) != "collected" or get(evidence, "version_id", str) != get(version, "id", str):
            raise Unavailable("version denial evidence unavailable or foreign")
        _dated(evidence, index)
        method = get(evidence, "method", str)
        if method not in ("authorized_read_test", "effective_authorization") or not get(evidence, "authorized", bool):
            raise Unavailable("controlled version access evidence unavailable")
        outcome = get(evidence, "outcome", str)
        if outcome not in ("readable", "denied"):
            raise Unavailable("access outcome does not establish denial")
        return result(outcome == "readable", version_id=get(version, "id", str), outcome=outcome)
    return _aggregate(old, assess, empty_na=True)


@register(IDS[4], dependencies=["web_app"])
def workload_keyvault_storage(item, index):
    _member(item, index, "web_app")
    evidence = _evidence(item, "workloadSecrets", index, dated=True)
    for field in ("inventory_complete", "classification_complete", "sites_slots_complete", "locations_complete"):
        if not get(evidence, field, bool):
            raise Unavailable("workload-wide secret coverage unresolved: " + field)
    approved = set(_strings(get(_policy(index), "approvedVaultUris", list)))
    for uri in approved:
        _secret_uri(uri.rstrip("/") + "/secrets/validation")
    secrets = list_of_objects(get(evidence, "secrets", list))
    seen = set()
    for secret in secrets:
        name = get(secret, "secret_id", str)
        if not name or name in seen:
            raise Unavailable("missing or duplicate classified secret identity")
        seen.add(name)
    def assess(secret):
        required, present = get(secret, "required", bool), get(secret, "present", bool)
        if not present:
            if required:
                return result(True, secret_id=get(secret, "secret_id", str), reason="required secret missing")
            return "NOT_APPLICABLE", {"reason": "optional secret absent"}
        location = get(secret, "storage", str)
        if location == "literal_outside_key_vault":
            return result(True, secret_id=get(secret, "secret_id", str), reason="classified literal secret")
        if location != "key_vault":
            raise Unavailable("unmeasured secret storage location")
        uri = get(secret, "secret_uri", str)
        base, _ = _secret_uri(uri)
        if "https://" + base[0] not in {v.rstrip("/").casefold() for v in approved}:
            return result(True, secret_id=get(secret, "secret_id", str), reason="unauthorized Key Vault")
        if get(secret, "app_service_setting", bool):
            site_id = _arm(get(secret, "site_id", str))
            parent = _arm(get(item, "id", str))
            if site_id != parent and not site_id.startswith(parent + "/slots/"):
                raise Unavailable("secret setting belongs to another site/slot")
            reference = get(secret, "reference", str)
            # Values remain transient; the only persisted value is the URI reference.
            match = re.fullmatch(r"@Microsoft\.KeyVault\(SecretUri=(https://[^()\s;]+)\)", reference)
            if not match or _secret_uri(match.group(1)) != _secret_uri(uri):
                raise Unavailable("Key Vault reference syntax or target unresolved")
            status = get(secret, "resolution_status", str)
            if status in {"AccessToKeyVaultDenied", "SecretNotFound", "VaultNotFound", "MSINotEnabled", "InvalidSyntax", "OtherReasons"}:
                return result(True, secret_id=get(secret, "secret_id", str), resolution_status=status)
            if status != "Resolved":
                raise Unavailable("current Key Vault reference resolution unmeasured")
        return result(False, secret_id=get(secret, "secret_id", str))
    return _aggregate(secrets, assess, empty_na=True)


@register(IDS[8], dependencies=["action_group"])
def alert_ack_authorization(item, index):
    _member(item, index, "action_group")
    evidence = _evidence(item, "ackAuthorization", index, dated=True)
    approved = {value.casefold() for value in _strings(get(_policy(index), "approvedResponders", list))}
    for principal in approved:
        if not _UUID.fullmatch(principal):
            raise Unavailable("unresolved approved responder principal")
    workflows = list_of_objects(get(evidence, "workflows", list))
    if not get(evidence, "workflow_inventory_complete", bool):
        raise Unavailable("alert workflow inventory incomplete")
    def assess(workflow):
        workflow_id = get(workflow, "workflow_id", str)
        if not workflow_id:
            raise Unavailable("workflow identity missing")
        coverage = get(workflow, "coverage", dict)
        for field in ("action_mapping", "scopes", "ancestors", "groups", "pim", "conditions", "external_systems"):
            if not get(coverage, field, bool):
                raise Unavailable("effective authorization unresolved: " + field)
        grants = list_of_objects(get(workflow, "effective_grants", list))
        unsafe = []
        for grant in grants:
            principal = get(grant, "principal_id", str)
            if not _UUID.fullmatch(principal):
                raise Unavailable("effective principal unresolved")
            action = get(grant, "action", str)
            if action not in ("Microsoft.AlertsManagement/alerts/changeState/action", "external/acknowledge", "external/silence"):
                raise Unavailable("actual acknowledgment action unresolved")
            if action.startswith("external/") and not get(grant, "system_id", str):
                raise Unavailable("external workflow system unresolved")
            _arm(get(grant, "scope", str), _scope(index))
            if get(grant, "effective", bool) and principal.casefold() not in approved:
                unsafe.append(principal)
        return result(bool(unsafe), workflow_id=workflow_id, unapproved_principals=unsafe)
    return _aggregate(workflows, assess, empty_na=True)


@register(IDS[10], dependencies=["build_agent"])
def build_external_access(item, index):
    _member(item, index, "build_agent")
    evidence = _evidence(item, "externalAccess", index, dated=True)
    policy = _policy(index)
    approved = set(_strings(get(policy, "approvedBuildSourceIds", list)))
    for field in ("endpoints_complete", "hosts_complete", "nics_complete", "firewalls_complete", "effective_routes_complete"):
        if not get(evidence, field, bool):
            raise Unavailable("build network evidence incomplete: " + field)
    endpoints = _strings(get(evidence, "endpoint_ids", list))
    probes = list_of_objects(get(evidence, "probes", list))
    # Authority, identity, and endpoint universe apply to every probe before
    # any independent receipt can establish an unsafe outcome.
    validated = []
    for probe in probes:
        endpoint = get(probe, "endpoint_id", str)
        if endpoint not in endpoints:
            raise Unavailable("probe endpoint outside complete build inventory")
        if not get(probe, "authorized_test", bool) or not get(probe, "external_source", bool):
            raise Unavailable("authorized external probe unavailable")
        source = get(probe, "source_id", str)
        if not source:
            raise Unavailable("external probe source identity unavailable")
        validated.append((probe, endpoint, source))
    tested, unsafe, unusable = set(), [], None
    for probe, endpoint, source in validated:
        try:
            _dated(probe, index)
            outcome = get(probe, "outcome", str)
            if outcome not in ("allowed", "denied"):
                raise Unavailable("external probe outcome unresolved")
            if source not in approved:
                tested.add(endpoint)
                if outcome == "allowed":
                    unsafe.append(endpoint)
        except Unavailable as exc:
            unusable = exc
    if unsafe:
        return result(True, externally_accessible_endpoints=unsafe)
    if unusable is not None:
        raise unusable
    if tested != set(endpoints):
        return unknown("not every build endpoint has a current unauthorized-source probe")
    if not endpoints:
        return unknown("no probed build endpoints identified")
    return result(False, tested_endpoints=sorted(tested))


@register(IDS[7], dependencies=["storage_service"])
def storage_immutability(item, index):
    _member(item, index, "storage_service")
    evidence = _evidence(item, "immutabilityEvidence", index, dated=True)
    if not get(evidence, "container_inventory_complete", bool):
        raise Unavailable("object and audit-log container scope incomplete")
    required = _positive(get(_policy(index), "requiredRetentionDays", int))
    containers = list_of_objects(get(evidence, "containers", list))
    parent, seen = _arm(get(item, "id", str)), set()
    for container in containers:
        cid = _arm(get(container, "id", str))
        if not cid.startswith(parent + "/containers/") or cid in seen:
            raise Unavailable("foreign or duplicate immutable container")
        seen.add(cid)
    def assess(container):
        for field in ("default_retention_measured", "inheritance_resolved", "object_overrides_resolved"):
            if not get(container, field, bool):
                raise Unavailable("effective container retention unresolved: " + field)
        active = get(container, "default_retention_active", bool)
        days = get(container, "retention_days", int)
        if days < 0:
            raise Unavailable("invalid immutable retention duration")
        mode = get(container, "protection", str)
        if mode not in ("Locked", "Unlocked", "Absent", "ImmutableVersionLevel"):
            raise Unavailable("unrecognized immutable protection")
        if not active or days < required or mode in ("Unlocked", "Absent"):
            return result(True, container_id=get(container, "id", str), protection=mode, retention_days=days)
        if not get(container, "all_objects_evaluated", bool):
            raise Unavailable("object-level enforcement inventory incomplete")
        objects = _strings(get(container, "object_ids", list))
        operations = list_of_objects(get(container, "enforcement", list))
        observed = set()
        bad = []
        for operation in operations:
            _dated(operation, index)
            if not get(operation, "authorized", bool) or not get(operation, "premature", bool):
                raise Unavailable("premature-change evidence not controlled or applicable")
            action = get(operation, "operation", str)
            if action not in ("delete", "modify"):
                raise Unavailable("object operation unresolved")
            target = get(operation, "object_id", str)
            if target not in objects or not get(operation, "container_id", str).casefold() == get(container, "id", str).casefold():
                raise Unavailable("enforcement target foreign or missing")
            outcome = get(operation, "outcome", str)
            if outcome not in ("allowed", "denied"):
                raise Unavailable("object enforcement outcome unresolved")
            observed.add((target, action))
            if outcome == "allowed":
                bad.append(target)
        if bad:
            return result(True, premature_changes=bad)
        if not objects or observed != {(target, action) for target in objects for action in ("delete", "modify")}:
            raise Unavailable("delete and modification denial both require evidence")
        return result(False, container_id=get(container, "id", str))
    return _aggregate(containers, assess, empty_na=True)


@register(IDS[11], dependencies=["function_app"])
def function_invocation_limit(item, index):
    from xml.etree import ElementTree
    _member(item, index, "function_app")
    if "functionapp" not in get(item, "kind", str).casefold().split(","):
        raise Unavailable("Function App kind unresolved")
    evidence = _evidence(item, "invocationEvidence", index, dated=True)
    for field in ("operations_complete", "function_mapping_complete", "policy_tree_complete", "inheritance_resolved"):
        if not get(evidence, field, bool):
            raise Unavailable("Function/APIM coverage unresolved: " + field)
    policy = _policy(index)
    max_calls = _positive(get(policy, "maxCalls", int))
    max_window = _positive(get(policy, "maxRenewalPeriodSeconds", int))
    stable_keys = set(_strings(get(policy, "stableCounterKeys", list)))
    operations = list_of_objects(get(evidence, "operations", list))
    seen = set()
    for operation in operations:
        oid = _arm(get(operation, "operation_id", str), _scope(index))
        if "/microsoft.apimanagement/service/" not in oid or "/operations/" not in oid or oid in seen:
            raise Unavailable("unresolved or duplicate APIM operation identity")
        seen.add(oid)
        if not _arm(get(operation, "function_id", str)).startswith(_arm(get(item, "id", str)) + "/functions/"):
            raise Unavailable("foreign Function operation mapping")
    def assess(operation):
        if not get(operation, "exposed", bool):
            return "NOT_APPLICABLE", {"reason": "operation is not exposed"}
        if not get(operation, "expressions_resolved", bool):
            raise Unavailable("effective policy expressions unresolved")
        xml = get(operation, "effective_policy_xml", str)
        if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
            raise Unavailable("unsupported policy XML declaration")
        try:
            root = ElementTree.fromstring(xml)
        except ElementTree.ParseError as exc:
            raise Unavailable("malformed effective policy XML") from exc
        if root.tag != "policies" or root.find("inbound") is None or root.findall(".//base"):
            raise Unavailable("effective policy inheritance unresolved")
        # Conditional choose/when policies cannot establish a covering limit.
        limits = root.findall("./inbound/rate-limit-by-key")
        if not limits:
            if root.findall(".//rate-limit-by-key"):
                raise Unavailable("conditional effective rate limit unresolved")
            return result(True, operation_id=get(operation, "operation_id", str), reason="complete policy has no effective per-caller limit")
        if len(limits) != 1:
            raise Unavailable("multiple effective rate-limit counters unresolved")
        limit = limits[0]
        if (not re.fullmatch(r"[1-9][0-9]*", limit.get("calls", "")) or
                not re.fullmatch(r"[1-9][0-9]*", limit.get("renewal-period", "")) or
                set(limit.attrib) - {"calls", "renewal-period", "counter-key", "id"}):
            raise Unavailable("dynamic threshold or conditional counter unresolved")
        calls, window = int(limit.attrib["calls"]), int(limit.attrib["renewal-period"])
        key = limit.get("counter-key")
        if calls > max_calls or window > max_window or key not in stable_keys:
            raise Unavailable("threshold/window or stable caller counter is not approved")
        probe = get(operation, "probe", dict)
        _dated(probe, index)
        if not get(probe, "authorized", bool) or get(probe, "operation_id", str) != get(operation, "operation_id", str):
            raise Unavailable("authorized same-operation rate test unavailable")
        if get(probe, "counter_key", str) != key or not get(probe, "fresh_counter", bool):
            raise Unavailable("probe counter does not match effective policy")
        caller = get(probe, "caller_id", str)
        if not caller:
            raise Unavailable("stable tested caller unavailable")
        attempts = list_of_objects(get(probe, "attempts", list))
        previous, first, allowed, beyond = None, None, 0, None
        for number, attempt in enumerate(attempts, 1):
            if get(attempt, "sequence", int) != number or get(attempt, "caller_id", str) != caller:
                raise Unavailable("probe sequence or same-entity identity unresolved")
            _dated(attempt, index)
            instant = _time(get(attempt, "observed_at", str))
            first = instant if first is None else first
            if previous is not None and instant < previous or instant - first >= timedelta(seconds=window):
                raise Unavailable("probe not contained in the effective rate window")
            previous = instant
            code = get(attempt, "status_code", int)
            if not 100 <= code <= 599 or number > calls + 1:
                raise Unavailable("probe HTTP outcome or length malformed")
            if number <= calls:
                allowed += 200 <= code < 300
            else:
                beyond = code
        if beyond is not None and 200 <= beyond < 300:
            return result(True, operation_id=get(operation, "operation_id", str), reason="same-caller beyond-threshold invocation succeeded")
        if allowed != calls or beyond != 429 or not get(attempts[-1], "policy_denial", bool):
            raise Unavailable("allowed-threshold success and additional-call rate denial unproven")
        return result(False, operation_id=get(operation, "operation_id", str), calls=calls, renewal_period=window)
    return _aggregate(operations, assess, empty_na=True)


@register(IDS[12], dependencies=["sql_server", "mysql_flexible_server", "postgresql_flexible_server"], target="scope")
def database_firewalls(item, index):
    scope = _scope(index)
    if get(item, "scope", str).casefold() != scope.casefold():
        raise Unavailable("foreign scope subject")
    servers = []
    for kind in ("sql_server", "mysql_flexible_server", "postgresql_flexible_server"):
        values = _rows(index, kind)
        for server in values:
            rid = _arm(get(server, "id", str))
            expected = {"sql_server": "/microsoft.sql/servers/", "mysql_flexible_server": "/microsoft.dbformysql/flexibleservers/",
                        "postgresql_flexible_server": "/microsoft.dbforpostgresql/flexibleservers/"}[kind]
            if expected not in rid:
                raise Unavailable("unsupported or foreign database generation")
        servers.extend(values)
    if not servers:
        return "NOT_APPLICABLE", {"reason": "no servers in complete inventories"}
    def assess(server):
        native = server.get("_database_native", {}).get("schema") == "native-database-arm-v1"
        field = "properties.network.publicNetworkAccess" if native and "/providers/microsoft.sql/servers/" not in server["id"].casefold() else "properties.publicNetworkAccess"
        access = get(server, field, str)
        if access not in ("Enabled", "Disabled"):
            raise Unavailable("effective public-access state unresolved")
        rules = _embedded(server, "firewallRules", "firewallRules")
        violations = []
        for rule in rules:
            native_rule = native and rule.get("_provenance", {}).get("native_database_schema") == "native-database-arm-v1"
            classification = "Custom" if native_rule else get(rule, "classification", str)
            if classification not in ("Custom", "Default"):
                raise Unavailable("default-rule classification unresolved")
            try:
                low = IPv4Address(get(rule, "properties.startIpAddress", str))
                high = IPv4Address(get(rule, "properties.endIpAddress", str))
            except ValueError as exc:
                raise Unavailable("malformed firewall IPv4 range") from exc
            if low > high:
                raise Unavailable("reversed firewall range")
            if classification == "Custom" and int(low) == 0 and int(high) == 2**32 - 1:
                violations.append(get(rule, "id", str))
            if int(low) == int(high) == 0:
                if not get(_policy(index), "allowAzureServices", bool):
                    violations.append(get(rule, "id", str))
        return result(bool(violations), server_id=get(server, "id", str), unrestricted_rules=violations)
    return _aggregate(servers, assess)


@register(IDS[13], dependencies=["vm", "nic", "vm_scale_set"], target="scope")
def compute_public_ips(item, index):
    scope = _scope(index)
    if get(item, "scope", str).casefold() != scope.casefold():
        raise Unavailable("foreign scope subject")
    vms, nics, scales = _rows(index, "vm"), _rows(index, "nic"), _rows(index, "vm_scale_set")
    nic_by_id = {_arm(get(nic, "id", str)): nic for nic in nics}
    def assess_vm(vm):
        _full(vm)
        references = list_of_objects(get(vm, "properties.networkProfile.networkInterfaces", list))
        if not references:
            raise Unavailable("VM NIC references unavailable")
        seen, violations = set(), []
        for reference in references:
            rid = _arm(get(reference, "id", str), scope)
            if rid in seen or "/microsoft.network/networkinterfaces/" not in rid:
                raise Unavailable("duplicate or malformed VM NIC reference")
            seen.add(rid)
            nic = nic_by_id.get(rid)
            if nic is None:
                raise Unavailable("VM NIC reference unresolved")
            _full(nic)
            configs = list_of_objects(get(nic, "properties.ipConfigurations", list))
            if not configs:
                raise Unavailable("VM NIC IP configurations missing")
            for config in configs:
                props = get(config, "properties", dict)
                public = optional(props, "publicIPAddress", None)
                if public is not None:
                    pid = _arm(get(public, "id", str), scope)
                    if "/microsoft.network/publicipaddresses/" not in pid:
                        raise Unavailable("public IP reference malformed")
                    violations.append(pid)
        return result(bool(violations), vm_id=get(vm, "id", str), public_ip_ids=violations)
    def assess_scale(scale):
        _full(scale)
        configs = list_of_objects(get(scale, "properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations", list))
        if not configs:
            raise Unavailable("VMSS NIC templates missing")
        violations = []
        for config in configs:
            ip_configs = list_of_objects(get(config, "properties.ipConfigurations", list))
            if not ip_configs:
                raise Unavailable("VMSS template IP configurations missing")
            for ip_config in ip_configs:
                public = optional(get(ip_config, "properties", dict), "publicIPAddressConfiguration", None)
                if public is not None:
                    if not get(public, "name", str):
                        raise Unavailable("VMSS public IP template malformed")
                    get(public, "properties", dict)
                    violations.append(get(public, "name", str))
        return result(bool(violations), vm_scale_set_id=get(scale, "id", str), public_ip_templates=violations)
    rows = [("vm", vm) for vm in vms] + [("scale", scale) for scale in scales]
    return _aggregate(rows, lambda row: assess_vm(row[1]) if row[0] == "vm" else assess_scale(row[1]))
