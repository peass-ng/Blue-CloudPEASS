"""Shared strict helpers for the claude_azure partition predicates.

Every helper raises ``Unavailable`` (-> UNKNOWN) on a missing, denied, malformed
or unrecognized native fact. A helper never turns absence into a FAIL.
"""
from __future__ import annotations
import re
from . import register, result, unknown
from .facts import get, list_of_objects, optional, complete_items, Unavailable
from .fixtures import CASES, nest

PREFIX = "azure.claude."
CHECK_IDS = []
DEFAULT_REMEDIATION = ("Review the declared configuration for the intended workload and configure the setting through "
                       "ARM/Bicep/Terraform or the portal; collected settings do not establish runtime enforcement.")


def claude(slug, kind, title, *, severity="medium", control="CM-6", remediation=None, category="hardening",
           target="resource", dependencies=None):
    """Register ``azure.claude.<slug>``; dependencies default to the evaluated kind."""
    cid = PREFIX + slug
    CHECK_IDS.append(cid)
    return register(cid, "azure", category, kind, title, severity, control, remediation or DEFAULT_REMEDIATION,
                    target=target, dependencies=list(dependencies or [kind]))


def cid(slug):
    return PREFIX + slug


def enum(item, path, values):
    value = get(item, path, str)
    if value not in values:
        raise Unavailable("unrecognized provider enum: " + path)
    return value


def nullable_string(item, path):
    """Present-but-null is an explicit API statement; absence stays UNKNOWN."""
    value = get(item, path)
    if value is not None and (not isinstance(value, str) or not value):
        raise Unavailable("malformed nullable provider identifier: " + path)
    return value


PRIVATE_LINK_STATES = ("Approved", "Pending", "Rejected", "Disconnected")


def private_link_states(item, path="properties.privateEndpointConnections"):
    connections = list_of_objects(get(item, path, list))
    states = [get(connection, "properties.privateLinkServiceConnectionState.status", str) for connection in connections]
    if any(state not in PRIVATE_LINK_STATES for state in states):
        raise Unavailable("unrecognized private endpoint connection status")
    return states


def approved_private_link_case():
    return {"properties": {"privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]}}


def setting(slug, kind, path, good, bad, title, *, expected=None, severity="medium", control="CM-6", remediation=None,
            extra_cases=None):
    """Strict declarative predicate: value in ``good`` -> PASS, in ``bad`` -> FAIL, otherwise UNKNOWN."""
    good = tuple(good) if isinstance(good, (tuple, list)) else (good,)
    bad = tuple(bad) if isinstance(bad, (tuple, list)) else (bad,)
    expected = expected or type(good[0])

    @claude(slug, kind, title, severity=severity, control=control, remediation=remediation)
    def evaluate(item, index):
        value = get(item, path, expected)
        if value in good:
            return result(False, field=path, configured=value)
        if value in bad:
            return result(True, field=path, configured=value)
        return unknown("unrecognized setting value", field=path, configured=value)
    evaluate.__name__ = "claude_" + slug
    malformed = {"unexpected": True}
    CASES[cid(slug)] = {"pass": nest(path, good[0]), "fail": nest(path, bad[0]), "missing": {}, "malformed": nest(path, malformed),
                        **(extra_cases or {})}
    return evaluate


# --- Network security group rule normalization -------------------------------------------------------------

INTERNET_SOURCES = ("*", "0.0.0.0", "0.0.0.0/0", "Internet", "any", "<nw>/0", "/0")


def _strings(properties, plural, singular):
    many = optional(properties, plural, None)
    if many is not None and (not isinstance(many, list) or any(not isinstance(x, str) for x in many)):
        raise Unavailable("malformed NSG rule " + plural)
    if many:
        return list(many)
    one = optional(properties, singular, None)
    if one is None:
        return []
    if not isinstance(one, str):
        raise Unavailable("malformed NSG rule " + singular)
    return [one]


def nsg_sources(properties):
    sources = _strings(properties, "sourceAddressPrefixes", "sourceAddressPrefix")
    if sources:
        if any(not source.strip() for source in sources):
            raise Unavailable("empty NSG source prefix")
        return sources
    groups = list_of_objects(optional(properties, "sourceApplicationSecurityGroups", [], list))
    if not groups:
        raise Unavailable("NSG source address or application security group selector unavailable")
    identifiers = [get(group, "id", str) for group in groups]
    pattern = r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/applicationSecurityGroups/[^/]+"
    if any(not re.fullmatch(pattern, identifier, re.IGNORECASE) for identifier in identifiers):
        raise Unavailable("malformed NSG application security group source")
    return ["asg:" + identifier for identifier in identifiers]


def nsg_protocol(properties):
    protocol = get(properties, "protocol", str)
    if protocol.lower() not in {"tcp", "udp", "icmp", "esp", "ah", "*"}:
        raise Unavailable("unrecognized Azure NSG protocol")
    return protocol


def nsg_rules(item, include_default=False):
    rules = list_of_objects(get(item, "properties.securityRules", list))
    if include_default:
        rules = rules + list_of_objects(get(item, "properties.defaultSecurityRules", list))
    normalized = []
    for rule in rules:
        p = get(rule, "properties", dict)
        direction, access, protocol = get(p, "direction", str), get(p, "access", str), nsg_protocol(p)
        if direction not in ("Inbound", "Outbound") or access not in ("Allow", "Deny") or not isinstance(protocol, str):
            raise Unavailable("malformed NSG rule direction, access or protocol")
        ports = _strings(p, "destinationPortRanges", "destinationPortRange")
        if not ports and protocol.lower() in {"tcp", "udp", "*"}:
            raise Unavailable("NSG TCP/UDP destination port declaration unavailable")
        normalized.append({"name": rule.get("name"), "priority": p.get("priority"), "direction": direction, "access": access,
                           "protocol": protocol, "sources": nsg_sources(p),
                           "ports": ports})
    return normalized


def port_range(spec):
    """Return (low, high) for '*', 'n' or 'a-b'; malformed text is UNKNOWN."""
    spec = spec.strip()
    if spec == "*":
        return 0, 65535
    if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", spec):
        raise Unavailable("malformed NSG port specification: " + spec)
    try:
        if "-" in spec:
            low, high = (int(x) for x in spec.split("-", 1))
        else:
            low = high = int(spec)
    except ValueError:
        raise Unavailable("malformed NSG port specification: " + spec)
    if not 0 <= low <= high <= 65535:
        raise Unavailable("NSG port range outside ordered 0-65535 domain")
    return low, high


def internet_allow_rules(item, *, direction="Inbound", protocols=("tcp", "*"), port=None, ports=None, all_ports=False,
                         include_default=False, exact_range=None):
    """Allow rules from an internet source that cover the requested port(s)/protocols."""
    hits = []
    for rule in nsg_rules(item, include_default):
        if rule["direction"] != direction or rule["access"] != "Allow":
            continue
        if protocols is not None and rule["protocol"].lower() not in protocols:
            continue
        if not any(source in INTERNET_SOURCES for source in rule["sources"]):
            continue
        matched = False
        for spec in rule["ports"]:
            low, high = port_range(spec)
            if all_ports:
                matched = matched or spec.strip() == "*" or (low, high) == (0, 65535)
            elif exact_range is not None:
                matched = matched or spec.strip() == "*" or (low, high) == exact_range
            else:
                wanted = list(ports or ([] if port is None else [port]))
                matched = matched or any(low <= p <= high for p in wanted)
        if matched:
            hits.append({k: rule[k] for k in ("name", "priority", "protocol", "sources", "ports")})
    return hits


def nsg_rule(name, protocol, sources, ports, direction="Inbound", access="Allow"):
    """Fixture builder for one NSG rule."""
    props = {"direction": direction, "access": access, "protocol": protocol}
    props["sourceAddressPrefixes" if isinstance(sources, list) else "sourceAddressPrefix"] = sources
    props["destinationPortRanges" if isinstance(ports, list) else "destinationPortRange"] = ports
    props["sourcePortRange"] = "*"
    return {"name": name, "properties": props}


def nsg_case(*rules, defaults=None):
    data = {"properties": {"securityRules": list(rules)}}
    if defaults is not None:
        data["properties"]["defaultSecurityRules"] = list(defaults)
    return data


# --- Embedded diagnostic settings ------------------------------------------------------------------------
# The collector gathers diagnostic settings as a child collection scoped by the parent resource id, which
# the engine does not expose to a subscription-scoped resource evaluation. These predicates therefore read
# an embedded ``diagnosticSettings`` list (Microsoft.Insights/diagnosticSettings list result for the
# resource) and stay UNKNOWN until that fact is embedded by the collector.

def diagnostic_settings(item):
    return list_of_objects(get(item, "diagnosticSettings", list))


def diagnostic_logs(setting_item):
    return list_of_objects(get(setting_item, "properties.logs", list))


def diag_log(category=None, enabled=True, group=None, retention=None):
    log = {"enabled": enabled}
    if category is not None:
        log["category"] = category
    if group is not None:
        log["categoryGroup"] = group
    if retention is not None:
        log["retentionPolicy"] = retention
    return log


def diag_case(*logs, **properties):
    return {"diagnosticSettings": [{"name": "d", "properties": {"logs": list(logs), **properties}}]}



def subscription_builtin_assignments(index, scope):
    """Bind complete unfiltered subscription List rows, including inherited MG rows."""
    rows = []
    seen = set()
    mg = r'/providers/Microsoft\.Management/managementGroups/[^/?#]+'
    for row in scoped(index, 'policy_assignment'):
        if get(row, 'name', str) != 'SecurityCenterBuiltIn':
            continue
        rid = get(row, 'id', str)
        declared = get(row, 'properties.scope', str)
        match = re.fullmatch(r'(.+)/providers/Microsoft\.Authorization/policyAssignments/([^/?#]+)', rid, re.I)
        if (match is None or match.group(2).casefold() != 'securitycenterbuiltin'
                or declared.casefold() != match.group(1).casefold()):
            raise Unavailable('SecurityCenterBuiltIn assignment identity or declared scope inconsistent')
        assigned_scope = match.group(1)
        identity = rid.casefold()
        if identity in seen:
            raise Unavailable('duplicate SecurityCenterBuiltIn assignment identity')
        seen.add(identity)
        child = re.fullmatch(re.escape(scope) +
            r'/(?:resourceGroups/[^/?#]+(?:/providers/[^/?#]+(?:/[^/?#]+/[^/?#]+)+)?|'
            r'providers/[^/?#]+(?:/[^/?#]+/[^/?#]+)+)', assigned_scope, re.I)
        inherited = re.fullmatch(mg, assigned_scope, re.I)
        if assigned_scope.casefold() != scope.casefold() and child is None and inherited is None:
            raise Unavailable('SecurityCenterBuiltIn assignment ancestry or foreign scope unproved')
        if child is not None:
            continue
        if inherited is not None:
            proof = get(row, '_native_policy_assignment_list', dict)
            expected = {'source_operation': 'PolicyAssignments_List', 'api_version': '2023-04-01',
                        'read_only': True, 'selected_scope': scope, 'filter': None,
                        'request_path': scope + '/providers/Microsoft.Authorization/policyAssignments'}
            if proof != expected:
                raise Unavailable('inherited SecurityCenterBuiltIn List source binding unavailable')
        properties = get(row, 'properties', dict)
        for key in ('notScopes', 'resourceSelectors', 'overrides'):
            if optional(properties, key, [], list):
                raise Unavailable('conditional SecurityCenterBuiltIn applicability requires review')
        rows.append(row)
    return rows

def scoped(index, kind):
    """Complete scoped inventory or UNKNOWN."""
    return complete_items(index, kind)


def scope_index(kind_items):
    """Fixture builder for a scope-target index: {kind: [items]} with complete envelopes."""
    index = {"collections": {}}
    for kind, items in kind_items.items():
        index["collections"][kind] = [{"scope": "/subscriptions/s", "status": "collected" if items else "empty"}]
        index[kind] = [{"data": item} for item in items]
    return index


__all__ = ["claude", "cid", "enum", "nullable_string", "private_link_states", "approved_private_link_case", "setting",
           "INTERNET_SOURCES", "nsg_rules", "port_range", "internet_allow_rules", "nsg_rule", "nsg_case",
           "diagnostic_settings", "diagnostic_logs", "diag_log", "diag_case", "scoped", "scope_index",
           "get", "list_of_objects", "optional", "complete_items", "Unavailable", "result", "unknown", "CASES", "nest",
           "CHECK_IDS", "PREFIX", "subscription_builtin_assignments"]
