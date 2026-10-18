"""Signed Azure detection and publication predicates for sw12.

Pure snapshot evaluation. Reviewed policy binds complete KQL and trigger
semantics; string fragments alone never establish detection. The normalized
telemetry/test/publication contracts are documented in sw12-collector-requests.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import hashlib
import json
import math
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects, optional

SPECS = {'azure.other.attack_t1525': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'Alert on configured ATT&CK T1525 event pattern',
                              'remediation_hint': 'Route ACR image or repository events to the '
                                                  'approved workspace and create the reviewed T1525 '
                                                  'scheduled query rule with the approved evaluation '
                                                  'window, threshold and enabled action group.',
                              'proposed_spec_sha256': '323307b1f61d693522bacdee1e949659b67252e05dcde6dd0216304b02793e43'},
 'azure.other.attack_t1526': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'ATT&CK T1526 has an Azure detection rule',
                              'remediation_hint': 'Create an enabled scheduled query alert for the '
                                                  'approved T1526 event pattern and attach an action '
                                                  'group.',
                              'proposed_spec_sha256': '200d838601c91cde317fe2f129cf6d57654218e6eae335fa0391d634bfed3169'},
 'azure.other.attack_t1537': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'Enabled Azure Monitor detection for ATT&CK T1537',
                              'remediation_hint': 'Create an Azure Monitor scheduled-query alert for '
                                                  'the approved T1537 pattern over StorageBlobLogs, '
                                                  'scope each required Log Analytics workspace, set '
                                                  'the approved evaluation window, enable its action '
                                                  'group and test with a known event.',
                              'proposed_spec_sha256': '09abc3bd8b6f7afd7d35a7d377a7d6faa7fa8473f5efcef0b13be73a1479131d'},
 'azure.other.attack_t1546': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'ATT&CK T1546 automation or event subscription changes '
                                       'detection is configured',
                              'remediation_hint': 'In Azure Monitor > Alerts, create a scheduled query '
                                                  'rule for AzureActivity with the approved t1546 '
                                                  'query, scope, evaluation window, and enabled action '
                                                  'group.',
                              'proposed_spec_sha256': 'f34f437fe98428c426b90a44ffba77f9e27397e2a83456ae85d47d0da8410dbe'},
 'azure.other.attack_t1552': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'Alert on configured ATT&CK T1552 event pattern',
                              'remediation_hint': 'Azure portal > Monitor > Alerts > Create alert '
                                                  'rule: Create an enabled scheduled query alert for '
                                                  'the configured KeyVaultAuditEvents event pattern '
                                                  'and route it to an action group.',
                              'proposed_spec_sha256': '4b0f3b7f52b8457bf0ba42ee51d0bfa06739e6d48d2128731b63be0636ef8443'},
 'azure.other.attack_t1562': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'ATT&CK T1562 has an Azure detection rule',
                              'remediation_hint': 'Azure Monitor > Alerts > Create > Log search alert: '
                                                  'configure the approved T1562 query against the '
                                                  'approved workspace, enable it and attach an '
                                                  'approved action group.',
                              'proposed_spec_sha256': 'b6cb6fe2967047fb4b41158cacbaff5607567c83b8ab7a041d937712ced75a7b'},
 'azure.other.attack_t1578': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'Enabled Azure Monitor detection for ATT&CK T1578',
                              'remediation_hint': 'Create an enabled AzureActivity scheduled query '
                                                  'alert for each approved T1578 event pattern and '
                                                  'workspace, set its approved window and threshold, '
                                                  'and attach an enabled action group.',
                              'proposed_spec_sha256': '00220e01543e89bb7ade1edc450047347d8057ce34e8e201423222418ca203bf'},
 'azure.other.attack_t1580': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'ATT&CK T1580 resource discovery detection is configured',
                              'remediation_hint': 'In Azure Monitor > Alerts, create or fix a '
                                                  'scheduled query rule over AzureActivity with the '
                                                  'approved detection query, scope, evaluation window '
                                                  'and enabled action group.',
                              'proposed_spec_sha256': 'c9fdc54d9ce14e065ec29ff33df8cb6a7f888f5c028b4cf812b5315c31f6b00f'},
 'azure.other.attack_t1606': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'Alert on configured ATT&CK T1606 event pattern',
                              'remediation_hint': 'Azure portal > Monitor > Alerts: export Entra '
                                                  'SignInLogs to the workspace and create the approved '
                                                  'T1606 scheduled-query rule and action group.',
                              'proposed_spec_sha256': '3a341815ae9d91e19a06cb6553e452c9a054f302f901ff446c362cff988b8a77'},
 'azure.other.attack_t1614': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'ATT&CK T1614 has an Azure detection rule',
                              'remediation_hint': 'Route the required location-discovery event source '
                                                  'to the approved workspace and deploy the reviewed '
                                                  'T1614 query with approved timing, threshold and '
                                                  'enabled action group.',
                              'proposed_spec_sha256': '6af395a987d4db816a5292f8b22c11115d367c01b69f8ec49abd16c862860932'},
 'azure.other.attack_t1619': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'Enabled Azure Monitor detection for ATT&CK T1619',
                              'remediation_hint': 'Enable StorageBlobLogs export and verify ingestion, '
                                                  'then deploy the reviewed T1619 alert with an '
                                                  'approved evaluation window and working action '
                                                  'group.',
                              'proposed_spec_sha256': '29a8a7b95b55fe95bafa4d1059777b9a58883445b3b3a860d6e20bcf8641164f'},
 'azure.other.attack_t1621': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'ATT&CK T1621 MFA challenge abuse detection is configured',
                              'remediation_hint': 'In Azure Monitor > Alerts, create a scheduled query '
                                                  'rule for SigninLogs with the approved t1621 query, '
                                                  'scope, evaluation window, and enabled action group.',
                              'proposed_spec_sha256': '6600155407a6a6be4262af2f0e475493306965973a8debcffdc74bc900b8fd45'},
 'azure.other.attack_t1648': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'Alert on configured ATT&CK T1648 event pattern',
                              'remediation_hint': 'Create and test a scheduled query alert over '
                                                  'serverless execution telemetry for the approved '
                                                  'T1648 pattern, with a bounded window and enabled '
                                                  'action group.',
                              'proposed_spec_sha256': '1980e828c34a3a562dd84e86988aca34ea718ba2efea949a59f90287cec8d8c9'},
 'azure.other.attack_t1651': {'provider': 'azure',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'category': 'monitoring',
                              'title': 'ATT&CK T1651 has an Azure detection rule',
                              'remediation_hint': 'Azure Monitor > Alerts > Create > Log search alert: '
                                                  'configure the approved T1651 query against the '
                                                  'approved workspace, enable it and attach an '
                                                  'approved action group.',
                              'proposed_spec_sha256': 'd9d0b67de7cae15d0eda1082fc0851fc48034780a1ff408bcd927b6821036808'},
 'azure.other.enumeration_alert': {'provider': 'azure',
                                   'resource_kind': 'scheduled_query_rule',
                                   'severity': 'medium',
                                   'category': 'monitoring',
                                   'title': 'Alert on the configured enumeration pattern',
                                   'remediation_hint': 'Instrument enumeration detection and publish '
                                                       'each detected event with client identity, time '
                                                       'and activity nature to the approved monitored '
                                                       'channel; validate delivery with a test event.',
                                   'proposed_spec_sha256': '2c6d4ae21cd2b142c77c853b36e161c1ec48138ee2fd893ef8e3af54b98e529b'}}
IDS = tuple(SPECS)
PROPOSED_SPEC_SHA256 = {cid: spec["proposed_spec_sha256"] for cid, spec in SPECS.items()}

_SUB = re.compile(r"/subscriptions/[A-Za-z0-9-]+\Z", re.I)
_ARM = re.compile(r"/subscriptions/[A-Za-z0-9-]+/resourceGroups/[A-Za-z0-9._()-]+/providers/[A-Za-z0-9.]+/[A-Za-z0-9]+/[A-Za-z0-9._()-]+(?:/[A-Za-z0-9]+/[A-Za-z0-9._()-]+)*\Z", re.I)
_DURATION = re.compile(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_OPERATORS = {"Equals", "GreaterThan", "GreaterThanOrEqual", "LessThan", "LessThanOrEqual"}
_AGGREGATIONS = {"Average", "Count", "Maximum", "Minimum", "Total"}
_NORMALIZATION = "kql-lf-trim-v1"
_ENUM = "azure.other.enumeration_alert"
_ANY_WORKSPACE = {"azure.other.attack_t1614", "azure.other.attack_t1651"}
_FIXED_TABLE = {"attack_t1525": "ContainerRegistryRepositoryEvents",
                "attack_t1537": "StorageBlobLogs", "attack_t1578": "AzureActivity",
                "attack_t1606": "SigninLogs", "attack_t1619": "StorageBlobLogs",
                "attack_t1621": "SigninLogs"}


def query_digest(query):
    """Only normalize line endings and outer whitespace, preserving KQL literals.

    Deliberately do not fold case, strip comments, or collapse internal whitespace.
    A different byte sequence requires its own policy review; no KQL parser is claimed.
    """
    if not isinstance(query, str) or not query.strip() or "\x00" in query:
        raise Unavailable("query cannot be normalized")
    return hashlib.sha256(query.replace("\r\n", "\n").replace("\r", "\n").strip().encode()).hexdigest()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _text(value):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise Unavailable("missing or malformed identity/text")
    return value


def _strings(value, *, nonempty=False):
    if not isinstance(value, list):
        raise Unavailable("string array unavailable")
    values = [_text(v) for v in value]
    if len(values) != len(set(values)) or (nonempty and not values):
        raise Unavailable("empty or duplicate policy/identity array")
    return values


def _arm(value, scope, native_type=None):
    value = _text(value)
    if not _ARM.fullmatch(value) or not value.casefold().startswith(scope.casefold() + "/"):
        raise Unavailable("malformed or foreign Azure resource identity")
    if native_type and value.casefold().split("/providers/", 1)[1].rsplit("/", 1)[0] != native_type.casefold():
        raise Unavailable("Azure resource type differs from identity")
    return value.casefold()


def _source(value, scope):
    value = _text(value)
    # Tenant feeds are structurally distinct from ARM resources. Actual tenant,
    # subscription and credential authority is checked on the measured row.
    if re.fullmatch(r"/tenants/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value, re.I):
        return value.casefold()
    return _arm(value, scope) if value.startswith("/") else value


def _instant(value):
    value = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    if value.tzinfo is None or value.utcoffset() is None:
        raise Unavailable("timestamp timezone unavailable")
    return value


def _positive(item, key, *, zero=False):
    value = get(item, key, int)
    if value < (0 if zero else 1):
        raise Unavailable("invalid timing bound: " + key)
    return value


def _seconds(value, *, zero=False):
    match = _DURATION.fullmatch(_text(value))
    if not match or not any(v is not None for v in match.groups()):
        raise Unavailable("unsupported ISO 8601 duration")
    days, hours, minutes, seconds = (int(v or 0) for v in match.groups())
    total = days * 86400 + hours * 3600 + minutes * 60 + seconds
    if total < (0 if zero else 1):
        raise Unavailable("nonpositive evaluation duration")
    return total


def _scope(item, index):
    context = get(index, "context", dict)
    scope = get(context, "scope", str)
    if (get(context, "provider", str) != "azure" or not _SUB.fullmatch(scope)
            or get(item, "scope", str).casefold() != scope.casefold()
            or get(item, "provider", str) != "azure"):
        raise Unavailable("subscription subject authority unavailable")
    return scope, context


def _inventory(index, kind, scope, *, native_type=None):
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("one complete subscription inventory required: " + kind)
    envelope = envelopes[0]
    if (get(envelope, "type", str) != kind
            or get(envelope, "scope", str).casefold() != scope.casefold()):
        raise Unavailable("foreign collection scope or kind: " + kind)
    rows = complete_items(index, kind)
    native, wrapped = get(envelope, "items", list), get(index, kind, list)
    if (get(envelope, "status", str) == "empty") != (not rows):
        raise Unavailable("collection status contradicts contents: " + kind)
    if len(native) != len(wrapped) or len(native) != len(rows):
        raise Unavailable("collection/index cardinality differs: " + kind)
    seen = set()
    for row, raw, wrapper in zip(rows, native, wrapped):
        if (get(wrapper, "type", str) != kind
                or get(wrapper, "scope", str).casefold() != scope.casefold() or row != raw):
            raise Unavailable("foreign or inconsistent indexed fact: " + kind)
        identity = _arm(get(row, "id", str), scope, native_type) if native_type else _text(get(row, "id", str))
        if identity.casefold().startswith("/subscriptions/") and not identity.casefold().startswith(scope.casefold() + "/"):
            raise Unavailable("foreign normalized evidence identity: " + kind)
        if identity in seen:
            raise Unavailable("duplicate identity: " + kind)
        seen.add(identity)
        guard(row)
    return rows, envelope


def _provenance(row, operation):
    provenance = get(row, "_provenance", dict)
    if (get(provenance, "source_operation", str) != operation
            or get(provenance, "read_only", bool) is not True
            or get(provenance, "native_response_complete", bool) is not True):
        raise Unavailable("read-only complete source provenance unavailable")
    return provenance


def _policy(context, cid):
    root = get(context, "metadata.compliance_policy.sw12", dict)
    if (get(root, "status", str) != "collected"
            or get(root, "scope", str).casefold() != context["scope"].casefold()):
        raise Unavailable("reviewed subscription policy unavailable")
    age = (_instant(get(context, "created_at", str)) - _instant(get(root, "observed_at", str))).total_seconds()
    if not 0 <= age <= _positive(root, "max_age_seconds"):
        raise Unavailable("reviewed policy stale or future")
    # Check IDs contain dots, so the final map key must be read literally.
    checks = get(root, "checks", dict)
    if cid not in checks:
        raise Unavailable("per-check detection policy absent")
    selected = {"value": checks[cid]}
    if cid in checks.get("_coverage", {}):
        selected["_coverage"] = {"value": checks["_coverage"][cid]}
    policy = get(selected, "value", dict)
    guard(policy)
    return policy


def _native_optional(row, props, key, default, expected=None):
    # Native omission defaults are available only on a full ARM representation.
    _provenance(row, "scheduled_query_rules_list_by_subscription")
    return optional(props, key, default, expected)


def _condition(condition, *, policy=False):
    guard(condition)
    qhash = get(condition, "query_sha256", str) if policy else query_digest(get(condition, "query", str))
    if not _HASH.fullmatch(qhash):
        raise Unavailable("reviewed query digest malformed")
    operator, aggregation = get(condition, "operator", str), get(condition, "timeAggregation", str)
    threshold = get(condition, "threshold")
    if (operator not in _OPERATORS or aggregation not in _AGGREGATIONS
            or type(threshold) not in (int, float) or not math.isfinite(threshold)):
        raise Unavailable("unresolved trigger operator/aggregation/threshold")
    dimensions = list_of_objects(optional(condition, "dimensions", [], list))
    normalized = []
    names = set()
    for dimension in dimensions:
        name = _text(get(dimension, "name", str))
        op = get(dimension, "operator", str)
        values = _strings(get(dimension, "values", list), nonempty=True)
        if name in names or op not in {"Include", "Exclude"}:
            raise Unavailable("unresolved trigger dimensions")
        names.add(name)
        normalized.append({"name": name, "operator": op, "values": sorted(values)})
    failing = optional(condition, "failingPeriods", {"numberOfEvaluationPeriods": 1, "minFailingPeriodsToAlert": 1}, dict)
    periods = _positive(failing, "numberOfEvaluationPeriods")
    minimum = _positive(failing, "minFailingPeriodsToAlert")
    if minimum > periods:
        raise Unavailable("invalid failing-period trigger")
    columns = {}
    for key in ("metricMeasureColumn", "resourceIdColumn"):
        value = optional(condition, key, None)
        if value is not None:
            _text(value)
        columns[key] = value
    return {"query_sha256": qhash, "operator": operator, "timeAggregation": aggregation,
            "threshold": threshold, "dimensions": sorted(normalized, key=lambda d: d["name"]),
            "failingPeriods": {"numberOfEvaluationPeriods": periods, "minFailingPeriodsToAlert": minimum},
            **columns}


def _criteria(conditions, *, policy=False):
    conditions = list_of_objects(conditions)
    if not conditions:
        raise Unavailable("empty alert criteria cannot establish semantics")
    # All AND conditions must be reviewed together; a matching first condition
    # cannot hide a suppressing second condition or dimension.
    signatures = [_condition(c, policy=policy) for c in conditions]
    return sorted(signatures, key=_digest)


def _rules(index, scope):
    rows, _ = _inventory(index, "scheduled_query_rule", scope,
                         native_type="Microsoft.Insights/scheduledQueryRules")
    validated = []
    for row in rows:
        _provenance(row, "scheduled_query_rules_list_by_subscription")
        props = get(row, "properties", dict)
        kind = optional(row, "kind", "LogAlert", str)  # documented ARM default on full reads
        legacy_kind = optional(props, "kind", kind, str)
        if kind != legacy_kind or kind not in {"LogAlert", "LogToMetric"}:
            raise Unavailable("unrecognized or contradictory scheduled rule kind")
        if get(row, "type", str).casefold() != "microsoft.insights/scheduledqueryrules":
            raise Unavailable("scheduled rule type unavailable")
        enabled = get(props, "enabled", bool)
        scopes = [_arm(s, scope) for s in _strings(get(props, "scopes", list), nonempty=True)]
        if len(scopes) != len(set(scopes)):
            raise Unavailable("duplicate rule scopes")
        if kind == "LogToMetric":
            validated.append({"id": row["id"].casefold(), "kind": kind, "enabled": enabled, "scopes": scopes})
            continue
        conditions = get(props, "criteria.allOf", list)
        signature = _criteria(conditions)
        frequency = _seconds(get(props, "evaluationFrequency", str))
        window = _seconds(get(props, "windowSize", str))
        override = _native_optional(row, props, "overrideQueryTimeRange", None)
        effective = _seconds(override) if override is not None else window
        mute = _seconds(_native_optional(row, props, "muteActionsDuration", "PT0S", str), zero=True)
        groups = [_arm(s, scope, "Microsoft.Insights/actionGroups")
                  for s in _strings(get(props, "actions.actionGroups", list))]
        if len(groups) != len(set(groups)):
            raise Unavailable("duplicate action group references")
        validated.append({"id": row["id"].casefold(), "kind": kind, "enabled": enabled, "scopes": scopes,
                          "criteria": signature, "queries": [get(c, "query", str) for c in conditions],
                          "frequency": frequency, "window": window, "effective_window": effective,
                          "mute": mute, "groups": groups,
                          "configuration_sha256": _digest({"criteria": signature, "frequency": frequency,
                              "window": window, "effective_window": effective, "mute": mute, "scopes": scopes, "groups": groups})})
    return validated


def _groups(index, scope):
    rows, _ = _inventory(index, "action_group", scope, native_type="Microsoft.Insights/actionGroups")
    found = {}
    for row in rows:
        proof = get(row, "_provenance", dict)
        # Native metadata deliberately excludes receiver URLs and credentials.
        # Enabled state needs only the individually attested field; delivery
        # checks below still require independent acknowledgement evidence.
        if (proof.get("source_operation") == "action_groups_list_by_subscription"
                and proof.get("read_only") is True
                and proof.get("complete_fields") == ["properties.enabled"]):
            pass
        else:
            _provenance(row, "action_groups_list_by_subscription")
        if get(row, "type", str).casefold() != "microsoft.insights/actiongroups":
            raise Unavailable("action group type unavailable")
        enabled = get(row, "properties.enabled", bool)
        delivery = optional(row, "_delivery", None)
        if delivery is not None:
            guard(delivery)
            state = get(delivery, "status", str)
            if state not in {"reachable", "unreachable", "unresolved"}:
                raise Unavailable("action group delivery state malformed")
            _instant(get(delivery, "observed_at", str))
            _text(get(delivery, "evidence_id", str))
            if get(delivery, "read_only", bool) is not True:
                raise Unavailable("action delivery evidence is not read-only")
            if get(delivery, "configuration_sha256", str) != _digest(get(row, "properties", dict)):
                raise Unavailable("action delivery evidence describes another configuration")
        found[row["id"].casefold()] = {"enabled": enabled, "delivery": delivery}
    return found


def _requirements(policy, cid, scope):
    if get(policy, "queryNormalization", str) != _NORMALIZATION:
        raise Unavailable("reviewed query normalization unresolved")
    workspaces = [_arm(w, scope, "Microsoft.OperationalInsights/workspaces")
                  for w in _strings(get(policy, "requiredWorkspaceIds", list), nonempty=True)]
    approved_groups = {_arm(g, scope, "Microsoft.Insights/actionGroups")
                       for g in _strings(get(policy, "requiredActionGroupIds", list), nonempty=True)}
    if len(set(workspaces)) != len(workspaces):
        raise Unavailable("duplicate required workspace identity")
    requirements, seen = [], set()
    for req in list_of_objects(get(policy, "requirements", list)):
        workspace = _arm(get(req, "workspace_id", str), scope, "Microsoft.OperationalInsights/workspaces")
        source, pattern, table = _source(get(req, "source_id", str), scope), _text(get(req, "pattern_id", str)), _text(get(req, "table", str))
        if (get(req, "semantics_reviewed", bool) is not True
                or get(req, "trigger_semantics_reviewed", bool) is not True
                or workspace not in workspaces or (workspace, source, pattern) in seen):
            raise Unavailable("pattern/scope/trigger review unresolved or duplicated")
        seen.add((workspace, source, pattern))
        fixed = _FIXED_TABLE.get(cid.rsplit(".", 1)[-1])
        if fixed and table != fixed:
            raise Unavailable("required technique event table differs from policy")
        fragments = _strings(get(req, "requiredQueryFragments", list), nonempty=True)
        configurations = [_criteria(config, policy=True) for config in get(req, "approvedCriteria", list)]
        if not configurations or len({_digest(c) for c in configurations}) != len(configurations):
            raise Unavailable("reviewed complete criteria set absent or duplicated")
        rejected = [_criteria(config, policy=True) for config in optional(req, "non_triggeringCriteria", [], list)]
        if rejected and (get(req, "non_triggering_semantics_reviewed", bool) is not True
                         or any(config in configurations for config in rejected)):
            raise Unavailable("non-triggering criteria review absent or contradictory")
        minimum, maximum = _positive(req, "min_window_seconds"), _positive(req, "max_window_seconds")
        frequency = _positive(req, "max_frequency_seconds")
        delay = _positive(req, "max_notification_delay_seconds", zero=True)
        if minimum > maximum or frequency > maximum:
            raise Unavailable("approved timing policy contradictory")
        operations = _strings(get(req, "required_operations", list), nonempty=True)
        if cid.endswith("attack_t1580"):
            read_list = get(req, "read_list_applicable", bool)
            if read_list and (not {"read", "list"} <= set(operations) or table == "AzureActivity"):
                raise Unavailable("resource discovery read/list audit coverage unresolved")
        if cid.endswith("attack_t1648") and table == "AzureActivity":
            raise Unavailable("serverless execution telemetry unresolved")
        age = _positive(req, "max_ingestion_age_seconds") if cid.endswith(("attack_t1537", "attack_t1619")) else None
        requirements.append({"workspace": workspace, "source": source, "pattern": pattern, "table": table,
            "fragments": fragments, "configurations": configurations, "rejected": rejected,
            "minimum": minimum, "maximum": maximum,
            "frequency": frequency, "delay": delay, "operations": operations, "ingestion_age": age})
    if not requirements or {r["workspace"] for r in requirements} != set(workspaces):
        raise Unavailable("nonempty required-workspace pattern policy unavailable")
    if cid.endswith("attack_t1552"):
        inventory = list_of_objects(get(policy, "credential_source_inventory", list))
        classes, required_sources, key_vault_sources = set(), set(), set()
        for entry in inventory:
            klass = get(entry, "source_class", str)
            if klass not in {"key_vault", "host_files", "application_repository", "os_repository"}:
                raise Unavailable("credential source classification unresolved")
            classes.add(klass)
            if get(entry, "reviewed", bool) is not True:
                raise Unavailable("credential source scope not reviewed")
            if get(entry, "in_scope", bool):
                source = _source(get(entry, "source_id", str), scope)
                if source in required_sources:
                    raise Unavailable("duplicate credential source scope")
                required_sources.add(source)
                if klass == "key_vault":
                    key_vault_sources.add(source)
            else:
                _text(get(entry, "exclusion_reason", str))
        if (classes != {"key_vault", "host_files", "application_repository", "os_repository"}
                or not key_vault_sources or required_sources != {r["source"] for r in requirements}
                or any(r["table"] not in {"KeyVaultAuditEvents", "AzureDiagnostics"}
                       for r in requirements if r["source"] in key_vault_sources)):
            raise Unavailable("full credential-discovery source coverage unresolved")
    if cid.endswith("attack_t1648"):
        services = {_arm(s, scope) for s in _strings(get(policy, "serverless_service_ids", list), nonempty=True)}
        if services != {r["source"] for r in requirements}:
            raise Unavailable("serverless service coverage unresolved")
        _positive(policy, "max_test_age_seconds")
    if cid.endswith(("attack_t1526", "attack_t1619")):
        _positive(policy, "max_action_delivery_age_seconds")
    return requirements, workspaces, approved_groups


def _telemetry(index, scope, context):
    rows, _ = _inventory(index, "azure_detection_telemetry", scope)
    found = {}
    captured = _instant(get(context, "created_at", str))
    for row in rows:
        if row.get('_provenance', {}).get('contract') == 'sw11-v1':
            continue
        cid = get(row, "check_id", str)
        if cid not in SPECS or cid == _ENUM:
            raise Unavailable("telemetry check identity unresolved")
        workspace = _arm(get(row, "workspace_id", str), scope, "Microsoft.OperationalInsights/workspaces")
        source, pattern, table = _source(get(row, "source_id", str), scope), _text(get(row, "pattern_id", str)), _text(get(row, "table", str))
        if source.startswith("/tenants/"):
            tenant = source.rsplit("/", 1)[-1]
            metadata, proof = get(context, "metadata", dict), get(row, "_provenance", dict)
            subscriptions = get(metadata, "subscription_tenants", dict)
            bound = next((v for k, v in subscriptions.items() if isinstance(k, str) and k.casefold() == scope.casefold()), None)
            if (get(metadata, "tenant_verified", bool) is not True or get(proof, "tenant_verified", bool) is not True
                    or get(metadata, "tenant_id", str).casefold() != tenant or get(proof, "tenant_id", str).casefold() != tenant
                    or not isinstance(bound, str) or bound.casefold() != tenant
                    or any(not get(metadata, field, str) or get(metadata, field, str) != get(proof, field, str)
                           for field in ("credential_context_id", "customer_context_id"))):
                raise Unavailable("tenant telemetry capture/subscription authority unresolved")
        key = (cid, workspace, source, pattern)
        if key in found:
            raise Unavailable("ambiguous telemetry coverage identity")
        observation, proof = row.get("_coverage", {}).get("observation"), get(row, "_provenance", dict)
        if (proof.get("contract") == "sw12-v1" and isinstance(observation, dict)
                and observation.get("status") in {"not_collected", "denied", "malformed", "timeout", "unknown", "partial"}):
            if (proof.get("source_operation") != "azure_detection_telemetry" or proof.get("read_only") is not True
                    or proof.get("native_response_complete") is not False):
                raise Unavailable("invalid unavailable telemetry provenance")
            found[key] = None
            continue
        _provenance(row, "azure_detection_telemetry")
        routing = get(row, "routing_enabled", bool)
        evidence = _strings(get(row, "routing_evidence_ids", list))
        if routing and not evidence:
            raise Unavailable("enabled telemetry route lacks configuration evidence")
        state = get(row, "event_feed_status", str)
        if state not in {"available", "unavailable", "unresolved"}:
            raise Unavailable("unrecognized event-feed state")
        start, end = _instant(get(row, "query_window.start", str)), _instant(get(row, "query_window.end", str))
        if not start < end <= captured:
            raise Unavailable("telemetry observation window invalid or future")
        count = _positive(row, "event_count", zero=True)
        latest = get(row, "latest_event_at")
        if latest is not None:
            latest = _instant(latest)
            if not start <= latest <= end or not count:
                raise Unavailable("ingestion timestamp contradicts query evidence")
        elif count:
            raise Unavailable("ingestion event timestamp unavailable")
        operations = _strings(get(row, "supported_operations", list))
        found[key] = {"table": table, "routing": routing, "feed": state, "latest": latest,
                      "start": start, "end": end, "operations": set(operations)}
    return found


def _tests(index, scope, context):
    rows, _ = _inventory(index, "azure_detection_test", scope)
    found = []
    captured = _instant(get(context, "created_at", str))
    for row in rows:
        _provenance(row, "azure_detection_test")
        if get(row, "check_id", str) != "azure.other.attack_t1648":
            raise Unavailable("serverless test check identity unavailable")
        rule = _arm(get(row, "rule_id", str), scope, "Microsoft.Insights/scheduledQueryRules")
        workspace = _arm(get(row, "workspace_id", str), scope, "Microsoft.OperationalInsights/workspaces")
        source = _source(get(row, "source_id", str), scope)
        pattern = _text(get(row, "pattern_id", str))
        config = get(row, "configuration_sha256", str)
        if not _HASH.fullmatch(config):
            raise Unavailable("serverless test configuration digest malformed")
        _text(get(row, "trigger_event_id", str))
        _text(get(row, "correlation_id", str))
        event, observed = _instant(get(row, "event_at", str)), _instant(get(row, "observed_at", str))
        if not event <= observed <= captured:
            raise Unavailable("serverless test timestamp unavailable or future")
        state = get(row, "status", str)
        if state not in {"delivered", "not_fired", "not_delivered", "pending"}:
            raise Unavailable("unrecognized serverless test status")
        group = _arm(get(row, "action_group_id", str), scope, "Microsoft.Insights/actionGroups")
        fired, delivered = get(row, "fired_at"), get(row, "delivered_at")
        fired = _instant(fired) if fired is not None else None
        delivered = _instant(delivered) if delivered is not None else None
        if (fired is not None and not event <= fired <= observed
                or delivered is not None and (fired is None or not fired <= delivered <= observed)
                or state == "delivered" and (fired is None or delivered is None)
                or state == "not_fired" and (fired is not None or delivered is not None)
                or state in {"not_delivered", "pending"} and delivered is not None):
            raise Unavailable("test status and correlation timing disagree")
        found.append({"rule": rule, "workspace": workspace, "source": source, "pattern": pattern,
                      "configuration": config, "group": group, "state": state, "event": event,
                      "observed": observed, "delivered": delivered})
    return found


def _action_state(cid, rule, groups, approved, policy, context):
    states = []
    captured = _instant(get(context, "created_at", str))
    for gid in rule["groups"]:
        if gid not in approved:
            states.append(False)
            continue
        group = groups.get(gid)
        if group is None:
            states.append(None)
            continue
        if not group["enabled"]:
            states.append(None if cid.endswith(("attack_t1546", "attack_t1621")) else False)
            continue
        if cid.endswith(("attack_t1526", "attack_t1619")):
            delivery = group["delivery"]
            if delivery is None:
                states.append(None)
                continue
            age = (captured - _instant(delivery["observed_at"])).total_seconds()
            if not 0 <= age <= _positive(policy, "max_action_delivery_age_seconds"):
                states.append(None)
                continue
            states.append(True if delivery["status"] == "reachable" else
                          False if delivery["status"] == "unreachable" else None)
        else:
            states.append(True)
    return True if True in states else None if None in states else False


def _assess(cid, requirement, rules, groups, approved, telemetry, tests, policy, context):
    req = requirement
    source = telemetry.get((cid, req["workspace"], req["source"], req["pattern"]))
    if source is None or source["table"] != req["table"]:
        return None
    if source["feed"] != "available" or not set(req["operations"]) <= source["operations"]:
        return None
    captured = _instant(get(context, "created_at", str))
    # Evidence must cover at least the approved observation interval and remain
    # recent enough for this requirement, even where an event need not occur.
    if (source["end"] - source["start"]).total_seconds() < req["minimum"] or (captured - source["end"]).total_seconds() > req["maximum"]:
        return None
    if not source["routing"]:
        return False
    if req["ingestion_age"] is not None:
        if source["latest"] is None or (captured - source["latest"]).total_seconds() > req["ingestion_age"]:
            return None  # no events cannot prove telemetry failure or freshness
    states = []
    known_hashes = {c["query_sha256"] for config in req["configurations"] + req["rejected"] for c in config}
    for rule in rules:
        if not rule["enabled"] or rule["kind"] != "LogAlert" or req["workspace"] not in rule["scopes"]:
            continue
        # An enabled unknown query can potentially satisfy the requirement;
        # without review, absence cannot be proven by a keyword mismatch.
        hashes = {c["query_sha256"] for c in rule["criteria"]}
        if not hashes <= known_hashes:
            states.append(None)
            continue
        if not any(rule["criteria"] == config for config in req["configurations"]):
            # A mismatch can still detect the signal. FAIL needs an explicit
            # review proving this entire AND configuration non-triggering.
            states.append(False if rule["criteria"] in req["rejected"] else None)
            continue
        if any(not any(fragment in query for query in rule["queries"]) for fragment in req["fragments"]):
            states.append(None)  # policy and reviewed KQL contradict one another
            continue
        if (not req["minimum"] <= rule["window"] <= req["maximum"]
                or not req["minimum"] <= rule["effective_window"] <= req["maximum"]
                or rule["frequency"] > req["frequency"]):
            states.append(False)
            continue
        # Notification delay includes failing-period latency and explicit mute.
        # The exact AND criteria are reviewed, rather than independently ORed.
        period_delay = max((c["failingPeriods"]["numberOfEvaluationPeriods"] - 1) * rule["frequency"]
                           for c in rule["criteria"])
        if rule["mute"] > req["delay"]:
            states.append(False)
            continue
        if rule["mute"] + period_delay > req["delay"]:
            states.append(None)
            continue
        state = _action_state(cid, rule, groups, approved, policy, context)
        if state is True and cid.endswith("attack_t1648"):
            matching = [t for t in tests if t["rule"] == rule["id"] and t["workspace"] == req["workspace"]
                and t["source"] == req["source"] and t["pattern"] == req["pattern"]
                and t["configuration"] == rule["configuration_sha256"] and t["group"] in rule["groups"]
                and t["group"] in approved and groups.get(t["group"], {}).get("enabled") is True
                and 0 <= (captured - t["observed"]).total_seconds() <= _positive(policy, "max_test_age_seconds")]
            state = True if any(t["state"] == "delivered" and
                (t["delivered"] - t["event"]).total_seconds() <= req["maximum"] + req["delay"]
                for t in matching) else None
        states.append(state)
    return True if True in states else None if None in states else False


def _detection(cid, item, index):
    scope, context = _scope(item, index)
    policy = _policy(context, cid)
    requirements, workspaces, approved = _requirements(policy, cid, scope)
    if cid.endswith("attack_t1525"):
        registries, _ = _inventory(index, "container_registry", scope,
                                  native_type="Microsoft.ContainerRegistry/registries")
        for registry in registries:
            get(registry, "properties", dict)
        if not registries:
            if get(policy, "empty_registry_scope_not_applicable", bool) is True:
                return "NOT_APPLICABLE", {"reason": "Complete empty ACR inventory under explicit scope policy"}
            return unknown("ACR applicability unresolved; explicit empty-scope policy required")
        if {r["source"] for r in requirements} != {r["id"].casefold() for r in registries}:
            return unknown("required ACR image-event source coverage unresolved")
    rules = _rules(index, scope)
    groups = _groups(index, scope)
    workspace_rows, _ = _inventory(index, "log_analytics_workspace", scope,
                                   native_type="Microsoft.OperationalInsights/workspaces")
    for workspace in workspace_rows:
        get(workspace, "properties", dict)
    if not set(workspaces) <= {w["id"].casefold() for w in workspace_rows}:
        return unknown("required workspace membership unresolved")
    telemetry = _telemetry(index, scope, context)
    tests = _tests(index, scope, context) if cid.endswith("attack_t1648") else []
    states = [(r, _assess(cid, r, rules, groups, approved, telemetry, tests, policy, context)) for r in requirements]
    by_workspace = {}
    for workspace in workspaces:
        values = [state for req, state in states if req["workspace"] == workspace]
        by_workspace[workspace] = None if None in values else all(values)
    evidence = {"required_workspace_count": len(workspaces), "required_pattern_count": len(requirements),
                "covered_pattern_count": sum(state is True for _, state in states),
                "uncovered_patterns": [{"workspace_id": r["workspace"], "source_id": r["source"], "pattern_id": r["pattern"]}
                                       for r, state in states if state is False],
                "unresolved_pattern_count": sum(state is None for _, state in states),
                "semantics": "Reviewed query and trigger configuration with snapshot telemetry evidence; detection quality beyond the reviewed pattern is not inferred"}
    if cid in _ANY_WORKSPACE:
        if True in by_workspace.values():
            return result(False, **evidence)
        if None in by_workspace.values():
            return unknown("approved workspace detection evidence unresolved", **evidence)
        return result(True, **evidence)
    if None in by_workspace.values():
        return unknown("required detection evidence unresolved", **evidence)
    return result(not all(by_workspace.values()), **evidence)


def _window(envelope, policy, *, delivery=False):
    window = get(envelope, "query_window", dict)
    start, end = _instant(get(window, "start", str)), _instant(get(window, "end", str))
    if (start != _instant(get(policy, "window_start", str)) or end != _instant(get(policy, "window_end", str))
            or get(window, "complete", bool) is not True):
        raise Unavailable("enumeration source/delivery window incomplete or different")
    if delivery:
        return _instant(get(window, "settled_through", str))
    if (get(window, "independent", bool) is not True
            or get(window, "query_sha256", str) != get(policy, "enumeration_query_sha256", str)):
        raise Unavailable("independent reviewed enumeration source unavailable")
    return None


def _enumeration(item, index):
    scope, context = _scope(item, index)
    policy = _policy(context, _ENUM)
    if get(policy, "semantics_reviewed", bool) is not True:
        raise Unavailable("enumeration query meaning unreviewed")
    query = get(policy, "enumeration_query", str)
    qhash = get(policy, "enumeration_query_sha256", str)
    fragments = _strings(get(policy, "enumerationEventQueryFragments", list), nonempty=True)
    if (get(policy, "queryNormalization", str) != _NORMALIZATION or query_digest(query) != qhash
            or any(fragment not in query for fragment in fragments)):
        raise Unavailable("enumeration policy query/hash/fragments disagree")
    channels = set(_strings(get(policy, "monitoredChannelIds", list), nonempty=True))
    start, end, captured = (
        _instant(get(policy, "window_start", str)), _instant(get(policy, "window_end", str)),
        _instant(get(context, "created_at", str)))
    delay = _positive(policy, "max_delivery_delay_seconds", zero=True)
    if not start < end <= captured or (captured - end).total_seconds() > _positive(policy, "max_window_age_seconds"):
        raise Unavailable("enumeration approved observation window stale or future")
    events, event_envelope = _inventory(index, "azure_enumeration_event", scope)
    deliveries, delivery_envelope = _inventory(index, "azure_enumeration_delivery", scope)
    _window(event_envelope, policy)
    settled = _window(delivery_envelope, policy, delivery=True)
    if not delay <= (settled - end).total_seconds() or settled > captured:
        raise Unavailable("enumeration delivery evidence has not settled through approved delay")
    by_event = {}
    for event in events:
        _provenance(event, "azure_enumeration_independent_query")
        if get(event, "query_sha256", str) != qhash:
            raise Unavailable("enumeration event query identity differs")
        timestamp = _instant(get(event, "timestamp", str))
        if not start <= timestamp < end:
            raise Unavailable("enumeration event outside approved window")
        by_event[event["id"]] = {"identity": _text(get(event, "client_identity", str)), "time": timestamp,
                                  "nature": _text(get(event, "activity_nature", str)),
                                  "correlation": _text(get(event, "correlation_id", str))}
    published = set()
    unresolved = set()
    for delivery in deliveries:
        _provenance(delivery, "azure_enumeration_destination_read")
        event_id = get(delivery, "event_id", str)
        if event_id not in by_event:
            raise Unavailable("publication refers to an unresolved enumeration event")
        event = by_event[event_id]
        correlation = _text(get(delivery, "correlation_id", str))
        if correlation != event["correlation"]:
            raise Unavailable("publication correlation identity differs")
        channel = _text(get(delivery, "channel_id", str))
        state = get(delivery, "publication_status", str)
        if state not in {"published", "failed"}:
            raise Unavailable("publication outcome unresolved")
        published_at = optional(delivery, "published_at", None)
        if published_at is not None:
            published_at = _instant(published_at)
            if not event["time"] <= published_at <= settled:
                raise Unavailable("publication timing contradicts event/delivery evidence")
        elif state == "published":
            raise Unavailable("publication timestamp unavailable")
        # Failed attempts are not publications and cannot contribute coverage.
        # Their identity and any supplied timing remain independently validated,
        # but a successful publication payload does not exist for a failure.
        if state == "failed":
            continue
        if get(delivery, "payload_complete", bool) is not True:
            # Only an otherwise eligible publication can defer this event's
            # verdict; unmonitored or late attempts prove no required delivery.
            if channel in channels and (published_at - event["time"]).total_seconds() <= delay:
                unresolved.add(event_id)
            continue
        payload = get(delivery, "payload", dict)
        fields = {}
        for key in ("client_identity", "timestamp", "activity_nature"):
            value = optional(payload, key, None)
            if value is not None and not isinstance(value, str):
                raise Unavailable("publication payload field malformed")
            fields[key] = value
        # An authoritative complete payload with absent/empty required fields
        # is positive evidence of missing required publication content.
        good_fields = (fields["client_identity"] == event["identity"] and
                       fields["activity_nature"] == event["nature"] and bool(fields["timestamp"]))
        if fields["timestamp"]:
            good_fields = good_fields and _instant(fields["timestamp"]) == event["time"]
        if (state == "published" and channel in channels and good_fields
                and (published_at - event["time"]).total_seconds() <= delay):
            published.add(event_id)
    if not events:
        coverage, _ = _inventory(index, "azure_enumeration_coverage", scope)
        if len(coverage) != 1:
            return unknown("empty enumeration event set lacks continuous-window evidence")
        row = coverage[0]
        _provenance(row, "azure_enumeration_continuous_coverage")
        if (get(row, "query_sha256", str) != qhash
                or _instant(get(row, "window_start", str)) != start
                or _instant(get(row, "window_end", str)) != end
                or set(_strings(get(row, "monitoredChannelIds", list), nonempty=True)) != channels):
            raise Unavailable("continuous enumeration coverage scope/window differs")
        if not (get(row, "detection_continuous", bool) and get(row, "delivery_continuous", bool)):
            return unknown("empty enumeration set without continuous detection and delivery coverage")
        return result(False, event_count=0, continuous_window_coverage=True,
                      semantics="No detected events in a proven continuously monitored observation window")
    unresolved -= published
    missing = sorted(set(by_event) - published - unresolved)
    evidence = {"event_count": len(events), "published_event_count": len(published),
                "unpublished_or_incomplete_event_ids": missing,
                "semantics": "Destination publication of identity, time and activity nature for independently detected events"}
    if missing:
        return result(True, **evidence)
    if unresolved:
        return unknown("publication payload incomplete", unresolved_event_ids=sorted(unresolved), **evidence)
    return result(False, **evidence)


CHECK_OBJECTS = {}


def _signed(cid):
    spec = SPECS[cid]
    def decorate(function):
        # The native register's category validator predates signed monitoring.
        # Preserve its defensive safe wrapper, then restore only signed metadata.
        register(cid, spec["provider"], "hardening", spec["resource_kind"], spec["title"],
                 spec["severity"], "SI-4", spec["remediation_hint"], target="scope",
                 dependencies=_dependencies(cid))(function)
        CHECKS[-1] = replace(CHECKS[-1], category=spec["category"])
        CHECK_OBJECTS[cid] = CHECKS[-1]
        return function
    return decorate


def _dependencies(cid):
    if cid == _ENUM:
        return ["azure_enumeration_event", "azure_enumeration_delivery"]
    kinds = ["scheduled_query_rule", "action_group", "log_analytics_workspace", "azure_detection_telemetry"]
    if cid.endswith("attack_t1525"):
        kinds.append("container_registry")
    if cid.endswith("attack_t1648"):
        kinds.append("azure_detection_test")
    return kinds


EVALUATORS = {}
for _id in IDS:
    @_signed(_id)
    def _evaluate(item, index, _cid=_id):
        return _enumeration(item, index) if _cid == _ENUM else _detection(_cid, item, index)
    _evaluate.__name__ = _id.replace(".", "_")
    EVALUATORS[_id] = _evaluate
