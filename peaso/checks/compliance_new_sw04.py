"""Signed legacy Azure database checks over complete, scoped ARM inventories.

The collector keeps legacy Single Server reads distinct from Flexible Server.
These evaluators accept only complete native reads and preserve UNKNOWN when
required facts are unavailable. They never substitute flexible-server settings.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from . import register, result, unknown
from .facts import Unavailable, complete_items, get


# Generated metadata from the ten-field signed new_checks entries.
SPECS = {'azure.cis.postgresql_single_connection_throttling': {'category': 'hardening',
                                                       'description': 'Checks the legacy PostgreSQL '
                                                                      'single-server connection_throttling '
                                                                      'configuration.',
                                                       'proposed_spec_sha256': '6d447958a90581c1f35a116eb56ec56380cc4a471704cc13945920158e2d6dfa',
                                                       'provider': 'azure',
                                                       'remediation_hint': 'For any remaining PostgreSQL '
                                                                           'Single Server, set '
                                                                           'connection_throttling=ON through '
                                                                           'server parameters, then migrate '
                                                                           'the retired server to Flexible '
                                                                           'Server.',
                                                       'resource_kind': 'postgresql_single_server',
                                                       'severity': 'medium',
                                                       'title': 'Ensure server parameter '
                                                                "'connection_throttling' is set to 'ON' for "
                                                                'PostgreSQL Database Server'},
 'azure.cis.postgresql_single_log_checkpoints': {'category': 'hardening',
                                                 'description': 'Checks checkpoint logging on legacy '
                                                                'PostgreSQL Single Server.',
                                                 'proposed_spec_sha256': 'd4400f7daf90760872e55528123811e75015ab06bbf88e63e17ecb8667a4d3e1',
                                                 'provider': 'azure',
                                                 'remediation_hint': 'For each legacy PostgreSQL Single '
                                                                     'Server, open Server parameters and set '
                                                                     'log_checkpoints to ON.',
                                                 'resource_kind': 'postgresql_single_server',
                                                 'severity': 'medium',
                                                 'title': "Ensure Server Parameter 'log_checkpoints' is set "
                                                          "to 'ON' for PostgreSQL Database Server"},
 'azure.cis.postgresql_single_log_connections': {'category': 'hardening',
                                                 'description': 'Checks the legacy PostgreSQL single-server '
                                                                'log_connections parameter.',
                                                 'proposed_spec_sha256': '6e3492ca0ce562827a7fb76f196fbd9026bdfa550510d2ffd40aaf6e6bdc845d',
                                                 'provider': 'azure',
                                                 'remediation_hint': 'Azure portal > legacy Azure Database '
                                                                     'for PostgreSQL server > Server '
                                                                     'parameters: set log_connections to ON, '
                                                                     'save, and migrate retired Single '
                                                                     'Server where possible.',
                                                 'resource_kind': 'postgresql_single_server',
                                                 'severity': 'medium',
                                                 'title': 'Legacy PostgreSQL single server logs connections'},
 'azure.cis.postgresql_single_log_disconnections': {'category': 'hardening',
                                                    'description': 'Enable PostgreSQL Single Server '
                                                                   'disconnection logging. A finding is '
                                                                   'raised for an applicable legacy Single '
                                                                   'Server when value is off.',
                                                    'proposed_spec_sha256': 'cb13b60213390e824b9571d17c738307b626f548a94a9c8319ebd3dd05dc5e08',
                                                    'provider': 'azure',
                                                    'remediation_hint': 'For each legacy PostgreSQL Single '
                                                                        'Server, set server parameter '
                                                                        'log_disconnections=on in Azure '
                                                                        'portal > Server parameters; plan '
                                                                        'migration to Flexible Server.',
                                                    'resource_kind': 'postgresql_single_server',
                                                    'severity': 'medium',
                                                    'title': 'Enable PostgreSQL Single Server disconnection '
                                                             'logging'},
 'azure.cis.postgresql_single_no_azure_services_rule': {'category': 'hardening',
                                                        'description': 'Detects the Azure services firewall '
                                                                       'exception on legacy PostgreSQL '
                                                                       'Single Server; 0.0.0.0 is a service '
                                                                       'sentinel, not the whole internet.',
                                                        'proposed_spec_sha256': '55f2014d533de648cbe7891b49c4b7f663c25fb1862ecaf7f691eeee3fa1302a',
                                                        'provider': 'azure',
                                                        'remediation_hint': 'Delete the 0.0.0.0 '
                                                                            'Azure-services firewall rule on '
                                                                            'each legacy PostgreSQL Single '
                                                                            'Server, then use scoped '
                                                                            'firewall or private '
                                                                            'connectivity.',
                                                        'resource_kind': 'postgresql_single_server',
                                                        'severity': 'medium',
                                                        'title': "Ensure 'Allow access to Azure services' "
                                                                 'for PostgreSQL Database Server is '
                                                                 'disabled'},
 'azure.cis.public_network_access_should_mariadb_servers': {'category': 'network',
                                                            'description': 'Assesses the explicit public '
                                                                           'network access switch on legacy '
                                                                           'Azure Database for MariaDB only.',
                                                            'proposed_spec_sha256': 'ebcd6b48c5741b15e80e0e77709883f30716adc25d3537c673000833319f39e6',
                                                            'provider': 'azure',
                                                            'remediation_hint': 'For legacy MariaDB, disable '
                                                                                'Public network access in '
                                                                                'Connection security where '
                                                                                'supported; otherwise '
                                                                                'migrate to a service with '
                                                                                'private networking.',
                                                            'resource_kind': 'mariadb_server',
                                                            'severity': 'high',
                                                            'title': 'Public network access should be '
                                                                     'disabled for MariaDB servers'},
 'azure.gap.kubernetes_cluster_https_enabled': {'category': 'hardening',
                                                'description': 'AKS normally serves its API over HTTPS on '
                                                               'TCP 443; an actual protocol probe is needed '
                                                               'for a meaningful failure signal.',
                                                'proposed_spec_sha256': '01960fa562f1ae8a1d95d59696cc26e749da8d75873fd56e59fd84a37585d2d5',
                                                'provider': 'azure',
                                                'remediation_hint': 'Azure portal > Kubernetes services > '
                                                                    'Networking: Investigate any plaintext '
                                                                    'HTTP endpoint or proxy forwarding to '
                                                                    'the AKS API; require HTTPS.',
                                                'resource_kind': 'aks_cluster',
                                                'severity': 'medium',
                                                'title': 'AKS API server rejects plaintext HTTP'},
 'azure.other.ml_compute_file_download_restricted': {'category': 'hardening',
                                                     'description': 'Checks whether sensitive MLDE file '
                                                                    'downloads are disabled using '
                                                                    'application or data-plane evidence; ARM '
                                                                    'compute inventory alone is '
                                                                    'insufficient.',
                                                     'proposed_spec_sha256': 'ce42179286015d078f676f61b89abf9f6bd2b97ee21f1a8d4e9b69c3680200e4',
                                                     'provider': 'azure',
                                                     'remediation_hint': 'Disable file-download '
                                                                         'functionality on each sensitive '
                                                                         'MLDE instance and verify through '
                                                                         'its application/data plane that '
                                                                         'downloads are blocked for all '
                                                                         'users.',
                                                     'resource_kind': 'ml_compute',
                                                     'severity': 'high',
                                                     'title': 'Sensitive Azure ML artifact downloads are '
                                                              'limited to approved identities'},
 'azure.other.ml_sensitive_root_disabled': {'category': 'hardening',
                                            'description': 'Disable SSH on sensitive Azure ML compute. A '
                                                           'finding is raised when a sensitive compute '
                                                           'instance has enableSshAccess=true where SSH is '
                                                           'prohibited.',
                                            'proposed_spec_sha256': 'b6b34d06e3a50117088074ec7dec945d5ac554ae1889284c475810a90c7d5b88',
                                            'provider': 'azure',
                                            'remediation_hint': 'Disable root login and root-capable access '
                                                                'paths on each sensitive MLDE instance under '
                                                                'the approved guest/host policy; collect '
                                                                'current host evidence to verify the '
                                                                'setting.',
                                            'resource_kind': 'ml_compute',
                                            'severity': 'high',
                                            'title': 'Disable SSH on sensitive Azure ML compute'},
 'azure.other.ml_sensitive_terminal_disabled': {'category': 'hardening',
                                                'description': 'Checks public node IP and SSH configuration '
                                                               'on supported Azure ML compute types; browser '
                                                               'terminal authorization requires separate '
                                                               'evidence.',
                                                'proposed_spec_sha256': 'd012ed859102527b0f1d984bb3ed5be2bb4df86e1feca57d73935b0c3229d0a9',
                                                'provider': 'azure',
                                                'remediation_hint': 'Disable terminal and SSH access for the '
                                                                    'sensitive AML instance through the '
                                                                    'supported compute and Studio controls; '
                                                                    'restrict private-network paths and '
                                                                    'verify the terminal cannot be opened.',
                                                'resource_kind': 'ml_compute',
                                                'severity': 'high',
                                                'title': 'Sensitive Azure ML compute has no public SSH '
                                                         'access'}}

_KINDS = {
    "postgresql_single_server": "Microsoft.DBforPostgreSQL/servers",
    "mysql_single_server": "Microsoft.DBforMySQL/servers",
    "mariadb_server": "Microsoft.DBforMariaDB/servers",
    "ml_compute": "Microsoft.MachineLearningServices/workspaces",
}
_ARM_ID = re.compile(r"^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/([^/]+/[^/]+)/([^/]+)$", re.I)


def _scope(index):
    context = index.get("context")
    if not isinstance(context, dict) or context.get("provider") != "azure":
        raise Unavailable("Azure snapshot context unavailable")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"/subscriptions/[^/]+", scope, re.I):
        raise Unavailable("Azure subscription scope malformed")
    return scope


def _servers(index, kind):
    scope = _scope(index)
    envelopes = index.get("collections", {}).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("legacy server inventory missing or ambiguous")
    envelope = envelopes[0]
    if not isinstance(envelope, dict) or envelope.get("type") != kind or get(envelope, "scope", str).casefold() != scope.casefold():
        raise Unavailable("legacy server inventory has foreign scope")
    rows = complete_items(index, kind)
    raw = index.get(kind)
    if not isinstance(raw, list) or len(raw) != len(rows):
        raise Unavailable("legacy server resource index malformed")
    for wrapper in raw:
        if not isinstance(wrapper, dict) or wrapper.get("type") != kind or wrapper.get("scope", "").casefold() != scope.casefold():
            raise Unavailable("legacy server resource has foreign scope")
    declared = get(envelope, "items", list)
    if len(declared) != len(rows) or (envelope.get("status") == "empty") != (not rows):
        raise Unavailable("legacy server inventory item count conflicts with envelope")
    seen = set()
    for row, native in zip(rows, declared):
        rid = get(row, "id", str)
        match = _ARM_ID.fullmatch(rid)
        if (not match or not match.group(1) or not match.group(2) or not match.group(4)
                or match.group(3).casefold() != _KINDS[kind].casefold()
                or ("/subscriptions/" + match.group(1)).casefold() != scope.casefold()
                or not isinstance(native, dict) or get(native, "id", str).casefold() != rid.casefold()
                or native != row
                or rid.casefold() in seen):
            raise Unavailable("legacy server identity missing, duplicate, or foreign")
        seen.add(rid.casefold())
        provenance = get(row, "_provenance", dict)
        if get(provenance, "source_operation", str) != "GET" or get(provenance, "read_only", bool) is not True:
            raise Unavailable("legacy server full GET provenance unavailable")
    return rows


def _children(server, field, child_kind):
    status = get(server, "_coverage." + field + ".status", str)
    if status not in ("collected", "empty"):
        raise Unavailable("legacy server " + field + " pages incomplete")
    children = get(server, field, list)
    if (status == "empty") != (not children):
        raise Unavailable("legacy server " + field + " coverage conflicts with child count")
    parent = get(server, "id", str)
    prefix = parent.rstrip("/") + "/" + child_kind + "/"
    names = set()
    for child in children:
        cid = get(child, "id", str)
        name = get(child, "name", str)
        if (not cid.casefold().startswith(prefix.casefold()) or not name
                or cid[len(prefix):].casefold() != name.casefold()
                or "/" in name or name.casefold() in names):
            raise Unavailable("legacy server " + field + " child identity malformed")
        names.add(name.casefold())
    return children


def _configuration(server, name):
    matches = [row for row in _children(server, "configurations", "configurations")
               if get(row, "name", str).casefold() == name.casefold()]
    if not matches:
        return None
    return get(matches[0], "properties.value", str)


def _enum(server, field, good, bad):
    value = get(server, "properties." + field, str)
    if value == good:
        return False
    if value == bad:
        return True
    raise Unavailable("unrecognized " + field + " enum")


def _on_off(server, name, *, missing_fail=False, non_on_fail=False, casefold=False):
    value = _configuration(server, name)
    if value is None:
        if missing_fail:
            return True
        raise Unavailable(name + " configuration absent")
    normalized = value.casefold() if casefold else value
    on, off = ("on", "off") if casefold else ("ON", "OFF")
    if normalized == on:
        return False
    if normalized == off or non_on_fail:
        return True
    raise Unavailable("unrecognized " + name + " value")


def _retention(server):
    value = _configuration(server, "log_retention_days")
    if value is None or not re.fullmatch(r"[0-9]+", value):
        raise Unavailable("log retention integer unavailable")
    return int(value) <= 3


def _azure_services_rule(server):
    found, uncertain = False, False
    for rule in _children(server, "firewallRules", "firewallRules"):
        try:
            start = get(rule, "properties.startIpAddress", str)
            end = get(rule, "properties.endIpAddress", str)
            first, last = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
            if first > last:
                raise Unavailable("reversed PostgreSQL firewall range")
            found |= first == last == ipaddress.IPv4Address("0.0.0.0")
        except (ipaddress.AddressValueError, Unavailable):
            uncertain = True
    if found:
        return True
    if uncertain:
        raise Unavailable("one or more PostgreSQL firewall addresses unavailable")
    return False


def _audit_events(server):
    enabled = _configuration(server, "audit_log_enabled")
    events = _configuration(server, "audit_log_events")
    # This signed control treats a confirmed absent setting as a failure.
    if enabled is None or events is None:
        return True
    if enabled not in ("ON", "OFF"):
        raise Unavailable("unrecognized audit_log_enabled value")
    if not events or any(not token.strip() for token in events.split(",")):
        raise Unavailable("malformed audit_log_events value")
    return enabled == "OFF" or "CONNECTION" not in {token.strip() for token in events.split(",")}


_RULES = {
    "azure.cis.postgresql_single_connection_throttling": lambda s: _on_off(s, "connection_throttling", missing_fail=True, non_on_fail=True),
    "azure.cis.postgresql_single_log_checkpoints": lambda s: _on_off(s, "log_checkpoints", missing_fail=True),
    "azure.cis.postgresql_single_log_connections": lambda s: _on_off(s, "log_connections", casefold=True),
    "azure.cis.postgresql_single_log_disconnections": lambda s: _on_off(s, "log_disconnections", casefold=True),
    "azure.cis.postgresql_single_no_azure_services_rule": _azure_services_rule,
    "azure.cis.public_network_access_should_mariadb_servers": lambda s: _enum(s, "publicNetworkAccess", "Disabled", "Enabled"),
}


def _evaluate(check_id, index):
    spec = SPECS[check_id]
    servers = _servers(index, spec["resource_kind"])
    if not servers:
        return "NOT_APPLICABLE", {"reason": "complete legacy server inventory is empty"}
    failed, uncertain = [], []
    for server in servers:
        rid = get(server, "id", str)
        try:
            if _RULES[check_id](server):
                failed.append(rid)
        except Unavailable as exc:
            uncertain.append({"id": rid, "reason": str(exc)})
    if failed:
        return result(True, server_ids=failed, uncertain_servers=uncertain,
                      semantics="Complete ARM declaration or configuration evidence; live behavior untested")
    if uncertain:
        return unknown("one or more legacy server settings unavailable", uncertain_servers=uncertain)
    return result(False, assessed_server_count=len(servers),
                  semantics="Complete ARM declaration or configuration evidence; live behavior untested")


_ML_IDS = (
    "azure.other.ml_compute_file_download_restricted",
    "azure.other.ml_sensitive_root_disabled",
    "azure.other.ml_sensitive_terminal_disabled",
)
_ML_COMPUTE_ID = re.compile(
    r"^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/"
    r"Microsoft\.MachineLearningServices/workspaces/[^/]+/computes/[^/]+$", re.I)


def _instant(value):
    if not isinstance(value, str):
        raise Unavailable("evidence instant absent or malformed")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if instant.utcoffset() is None:
            raise ValueError("timezone absent")
        return instant
    except ValueError as exc:
        raise Unavailable("evidence instant absent or malformed") from exc


def _current(fact, captured):
    if get(fact, "status", str) != "collected":
        raise Unavailable("ML evidence incomplete")
    age = get(fact, "max_age_seconds", int)
    if not 0 < age <= 3600:
        raise Unavailable("ML evidence freshness bound invalid")
    elapsed = (captured - _instant(get(fact, "observed_at", str))).total_seconds()
    if not 0 <= elapsed <= age:
        raise Unavailable("ML evidence stale or future")


def _ml_inventory(index):
    scope = _scope(index)
    kind = "ml_compute"
    envelopes = index.get("collections", {}).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("ML compute inventory absent or ambiguous")
    envelope = envelopes[0]
    if not isinstance(envelope, dict) or envelope.get("type") != kind or get(envelope, "scope", str).casefold() != scope.casefold():
        raise Unavailable("ML compute inventory has foreign scope")
    rows = complete_items(index, kind)
    raw = index.get(kind)
    declared = get(envelope, "items", list)
    if (not isinstance(raw, list) or len(raw) != len(rows) or len(declared) != len(rows)
            or (envelope.get("status") == "empty") != (not rows)):
        raise Unavailable("ML compute inventory item count inconsistent")
    seen = set()
    for wrapper, row, native in zip(raw, rows, declared):
        rid = get(row, "id", str)
        if (not isinstance(wrapper, dict) or wrapper.get("scope", "").casefold() != scope.casefold()
                or wrapper.get("type") != kind or not _ML_COMPUTE_ID.fullmatch(rid)
                or not rid.casefold().startswith(scope.casefold() + "/")
                or not isinstance(native, dict) or get(native, "id", str).casefold() != rid.casefold()
                or native != row
                or rid.casefold() in seen):
            raise Unavailable("ML compute identity malformed, duplicate, or foreign")
        seen.add(rid.casefold())
        provenance = get(row, "_provenance", dict)
        if get(provenance, "source_operation", str) != "LIST" or get(provenance, "read_only", bool) is not True:
            raise Unavailable("ML compute paged LIST provenance unavailable")
    return rows


def _ml_classification(index, rows):
    context = get(index, "context", dict)
    captured = _instant(get(context, "created_at", str))
    policy = get(context, "metadata.ml_compute_classification", dict)
    _current(policy, captured)
    if get(policy, "source", str) != "owner_approved_classification" or get(policy, "read_only", bool) is not True:
        raise Unavailable("ML sensitivity classification is not owner approved")
    assignments = get(policy, "assignments", list)
    labels = {}
    for assignment in assignments:
        rid = get(assignment, "resource_id", str).casefold()
        classification = get(assignment, "classification", str)
        if rid in labels or classification not in ("sensitive", "non_sensitive"):
            raise Unavailable("ML classification duplicate or unrecognized")
        labels[rid] = classification
    native = {get(row, "id", str).casefold() for row in rows}
    if set(labels) != native:
        raise Unavailable("ML classification does not cover exact compute inventory")
    return labels, captured


def _ml_observation(server, field, captured):
    evidence = get(server, "securityObservations." + field, dict)
    _current(evidence, captured)
    source = get(evidence, "source", str)
    expected = "mlde_data_plane" if field == "fileDownload" else "mlde_guest_host"
    if source != expected or get(evidence, "read_only", bool) is not True:
        raise Unavailable("ML evidence source not authoritative for " + field)
    return evidence


def _ml_paths(server, field, captured, required):
    evidence = _ml_observation(server, field, captured)
    paths = get(evidence, "paths", list)
    observed = {}
    for path in paths:
        name = get(path, "name", str)
        enabled = get(path, "enabled", bool)
        if name in observed or not name:
            raise Unavailable("ML access path duplicate or malformed")
        observed[name] = enabled
    if any(observed.values()):
        return True
    if get(evidence, "complete_paths", bool) is not True or not required <= set(observed):
        raise Unavailable("ML access path missing")
    return any(observed.values())


def _ml_download(server, captured):
    evidence = _ml_observation(server, "fileDownload", captured)
    # A successful probe or an explicitly enabled setting proves a violation.
    # A clean result requires both observations plus all-user disablement.
    values = []
    for field in ("verified_successful_download", "configuration_enabled"):
        try:
            values.append(get(evidence, field, bool))
        except Unavailable:
            values.append(None)
    success, enabled = values
    if success is True or enabled is True:
        return True
    if success is not False or enabled is not False:
        raise Unavailable("ML download result missing or malformed")
    if get(evidence, "all_users_disabled", bool) is not True:
        raise Unavailable("ML all-user download disablement unproven")
    return False


_ML_RULES = {
    _ML_IDS[0]: lambda row, captured: _ml_download(row, captured),
    _ML_IDS[1]: lambda row, captured: _ml_paths(row, "rootAccess", captured,
                                                  {"console", "ssh", "local_privilege"}),
    _ML_IDS[2]: lambda row, captured: _ml_paths(row, "terminalAccess", captured,
                                                  {"studio_terminal", "private_ssh"}),
}

AKS_HTTPS_ID = "azure.gap.kubernetes_cluster_https_enabled"
_AKS_ID = re.compile(
    r"^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/"
    r"Microsoft\.ContainerService/managedClusters/[^/]+$", re.I)


def _aks_inventory(index):
    scope = _scope(index)
    kind = "aks_cluster"
    envelopes = index.get("collections", {}).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("AKS cluster inventory absent or ambiguous")
    envelope = envelopes[0]
    if not isinstance(envelope, dict) or envelope.get("type") != kind or get(envelope, "scope", str).casefold() != scope.casefold():
        raise Unavailable("AKS inventory foreign scope")
    rows = complete_items(index, kind)
    raw = index.get(kind)
    declared = get(envelope, "items", list)
    if (not isinstance(raw, list) or len(raw) != len(rows) or len(declared) != len(rows)
            or (envelope.get("status") == "empty") != (not rows)):
        raise Unavailable("AKS inventory count conflicts with envelope")
    seen = set()
    for wrapper, row, native in zip(raw, rows, declared):
        rid = get(row, "id", str)
        if (not isinstance(wrapper, dict) or wrapper.get("type") != kind
                or wrapper.get("scope", "").casefold() != scope.casefold()
                or not _AKS_ID.fullmatch(rid) or not rid.casefold().startswith(scope.casefold() + "/")
                or rid.casefold() in seen or not isinstance(native, dict) or native != row):
            raise Unavailable("AKS identity duplicate, malformed, or foreign")
        seen.add(rid.casefold())
    return rows


def _aks_transport(row, captured):
    properties = get(row, "properties", dict)
    fqdn = get(properties, "fqdn", (str, type(None)))
    private = get(properties, "privateFQDN", (str, type(None)))
    expected = {value.casefold() for value in (fqdn, private) if isinstance(value, str) and value}
    if not expected or any("/" in name or ":" in name or " " in name for name in expected):
        raise Unavailable("AKS API endpoint names unresolved")
    evidence = get(row, "securityObservations.apiTransport", dict)
    _current(evidence, captured)
    if get(evidence, "source", str) != "authorized_api_probe" or get(evidence, "read_only", bool) is not True:
        raise Unavailable("AKS transport probe source unavailable")
    probes = get(evidence, "probes", list)
    observed, accepted, uncertain = set(), False, False
    for probe in probes:
        name = get(probe, "endpoint_fqdn", str).casefold()
        if name not in expected or name in observed:
            raise Unavailable("AKS probe endpoint duplicate or foreign")
        observed.add(name)
        if not get(probe, "vantage_id", str) or get(probe, "dns_proxy_unambiguous", bool) is not True:
            uncertain = True
            continue
        http_completed = get(probe, "http_probe_completed", bool)
        http_accepted = get(probe, "http_api_request_accepted", bool)
        if http_completed and http_accepted:
            accepted = True
        elif not http_completed or http_accepted:
            uncertain = True
        try:
            if get(probe, "https_authenticated_api_success", bool) is not True:
                uncertain = True
        except Unavailable:
            uncertain = True
    if accepted:
        return True
    if observed != expected or get(evidence, "complete_endpoints", bool) is not True:
        raise Unavailable("AKS API endpoint probe missing or incomplete")
    if uncertain:
        raise Unavailable("AKS HTTP rejection or authenticated HTTPS success unproven")
    return False


def _aks_evaluate(index):
    rows = _aks_inventory(index)
    if not rows:
        return "NOT_APPLICABLE", {"reason": "complete AKS cluster inventory is empty"}
    captured = _instant(get(index, "context.created_at", str))
    failed, uncertain = [], []
    for row in rows:
        rid = get(row, "id", str)
        try:
            if _aks_transport(row, captured):
                failed.append(rid)
        except Unavailable as exc:
            uncertain.append({"id": rid, "reason": str(exc)})
    if failed:
        return result(True, cluster_ids=failed, uncertain_clusters=uncertain,
                      semantics="Authorized Kubernetes API transport probes from one vantage per endpoint")
    if uncertain:
        return unknown("one or more AKS endpoint probes unresolved", uncertain_clusters=uncertain)
    return result(False, assessed_cluster_count=len(rows),
                  semantics="Authenticated HTTPS success and HTTP API rejection observed from the same vantage")


def _ml_evaluate(check_id, index):
    rows = _ml_inventory(index)
    labels, captured = _ml_classification(index, rows)
    sensitive = [row for row in rows if labels[get(row, "id", str).casefold()] == "sensitive"]
    if not sensitive:
        return "NOT_APPLICABLE", {"reason": "complete classified ML compute inventory has no sensitive instances"}
    failed, uncertain = [], []
    for row in sensitive:
        rid = get(row, "id", str)
        try:
            if _ML_RULES[check_id](row, captured):
                failed.append(rid)
        except Unavailable as exc:
            uncertain.append({"id": rid, "reason": str(exc)})
    if failed:
        return result(True, compute_ids=failed, uncertain_computes=uncertain,
                      semantics="Current authoritative ML application or guest observation")
    if uncertain:
        return unknown("one or more sensitive ML compute observations unavailable", uncertain_computes=uncertain)
    return result(False, assessed_compute_count=len(sensitive),
                  semantics="Current authoritative ML application or guest observation")


def _register(check_id, spec):
    @register(check_id, spec["provider"], spec["category"], spec["resource_kind"],
              spec["title"], spec["severity"], "CM-6", spec["remediation_hint"],
              target="scope", dependencies=[spec["resource_kind"]])
    def evaluate(item, index):
        if not isinstance(item, dict) or item.get("scope") != _scope(index):
            raise Unavailable("scope subject differs from Azure inventory context")
        if check_id in _ML_RULES:
            return _ml_evaluate(check_id, index)
        if check_id == AKS_HTTPS_ID:
            return _aks_evaluate(index)
        return _evaluate(check_id, index)
    evaluate.__name__ = check_id.replace(".", "_")
    return evaluate


EVALUATORS = {check_id: _register(check_id, SPECS[check_id]) for check_id in (*_RULES, *_ML_RULES, AKS_HTTPS_ID)}
IDS = (*_RULES, *_ML_RULES, AKS_HTTPS_ID)
