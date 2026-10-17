"""Signed Azure ATT&CK detection coverage, evaluated only from snapshot facts.

KQL is never executed. An operator review binds a conservative text digest to
fully resolved detection semantics, exact scopes and approved firing settings.
Scope targets retain the signed resource kind and can grade an empty rule list.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import replace
from datetime import datetime

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, memoized, optional

SPECS = {'azure.other.attack_t1049': {'category': 'monitoring',
                              'proposed_spec_sha256': 'a4dc1114f6adf3be967fe41e4f688ce214159e5e73210c131f07bb6f2195e4ee',
                              'provider': 'azure',
                              'remediation_hint': 'Create an enabled T1049 scheduled-query alert '
                                                  'with approved network-connection telemetry, '
                                                  'scope and evaluation window; attach an enabled '
                                                  'action group and test a representative event.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'ATT&CK T1049 has an Azure detection rule'},
 'azure.other.attack_t1069': {'category': 'monitoring',
                              'proposed_spec_sha256': '7dd07da811d75dd7217fa93609d9f35c185b4babe4d45878b0b7b2d5493793b8',
                              'provider': 'azure',
                              'remediation_hint': 'Create an Azure Monitor scheduled-query alert '
                                                  'for the approved T1069 pattern over AuditLogs, '
                                                  'scope each required Log Analytics workspace, '
                                                  'set the approved evaluation window, enable its '
                                                  'action group and test with a known event.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'Enabled Azure Monitor detection for ATT&CK T1069'},
 'azure.other.attack_t1074': {'category': 'monitoring',
                              'proposed_spec_sha256': '503d37340bb792c9456e57cb10ebf27c3eb6c94ee5ce9cb7a113efcfe7338995',
                              'provider': 'azure',
                              'remediation_hint': 'In Azure Monitor > Alerts, create a scheduled '
                                                  'query rule for StorageBlobLogs with the '
                                                  'approved t1074 query, scope, evaluation window, '
                                                  'and enabled action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'ATT&CK T1074 staging writes detection is configured'},
 'azure.other.attack_t1082': {'category': 'monitoring',
                              'proposed_spec_sha256': 'd4be640c743e6e763a20368662661501cde587a9c9ed0f3b30c63a34f5716955',
                              'provider': 'azure',
                              'remediation_hint': 'Azure portal > Monitor > Alerts > Create alert '
                                                  'rule: Create an enabled scheduled query alert '
                                                  'over the approved workspace using the policy '
                                                  'T1082 KQL fragments, a bounded window and a '
                                                  'live action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'Alert on configured ATT&CK T1082 event pattern'},
 'azure.other.attack_t1087': {'category': 'monitoring',
                              'proposed_spec_sha256': '0a898e2e51f2030a1fbd079b47527b9a27ae1e9d75fd2a84654ffa87f6a477d6',
                              'provider': 'azure',
                              'remediation_hint': 'Azure Monitor > Alerts: route required '
                                                  'account-enumeration events to the approved '
                                                  'workspace and deploy the reviewed T1087 query '
                                                  'with approved timing, trigger and enabled '
                                                  'action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'ATT&CK T1087 has an Azure detection rule'},
 'azure.other.attack_t1110': {'category': 'monitoring',
                              'proposed_spec_sha256': '5a8020e419fd64fcf6a9f30f952e468e2fdd7105fe75d0aa65286e49868b5118',
                              'provider': 'azure',
                              'remediation_hint': 'Deploy and test an enabled SigninLogs '
                                                  'scheduled-query rule matching the approved '
                                                  'T1110 fragments and route it to an enabled '
                                                  'action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'Enabled Azure Monitor detection for ATT&CK T1110'},
 'azure.other.attack_t1119': {'category': 'monitoring',
                              'proposed_spec_sha256': '0a34f6c15ee9bebe106e2a5d30d5644e005fced256d66951b1019ae198e74d7a',
                              'provider': 'azure',
                              'remediation_hint': 'In Azure Monitor > Alerts, create or fix a '
                                                  'scheduled query rule over StorageBlobLogs with '
                                                  'the approved detection query, scope, evaluation '
                                                  'window and enabled action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'ATT&CK T1119 bulk object reads detection is configured'},
 'azure.other.attack_t1136': {'category': 'monitoring',
                              'proposed_spec_sha256': '653b4573e26b6ce3b6d2d9f6b9edab4e8e055ee8e3945d202081b4af732b2bae',
                              'provider': 'azure',
                              'remediation_hint': 'Azure portal > Monitor > Alerts > Create alert '
                                                  'rule: scope the audit workspace, use the '
                                                  'approved account-creation query and window, and '
                                                  'attach an enabled action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'Alert on configured ATT&CK T1136 event pattern'},
 'azure.other.attack_t1199': {'category': 'monitoring',
                              'proposed_spec_sha256': 'a5a412cadb632591df1647125ef5355f8e1530747763a5740877a69fd0bb1a09',
                              'provider': 'azure',
                              'remediation_hint': 'Ingest trusted-third-party access events, '
                                                  'deploy the reviewed T1199 detection query with '
                                                  'the approved window, attach an enabled action '
                                                  'group, and validate with a known event.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'ATT&CK T1199 has an Azure detection rule'},
 'azure.other.attack_t1201': {'category': 'monitoring',
                              'proposed_spec_sha256': '68650468b7d946347c997ab46a2e419d59e5a5f068dd833e4479c7f4ba871d9e',
                              'provider': 'azure',
                              'remediation_hint': 'Create an Azure Monitor scheduled-query alert '
                                                  'for the approved T1201 pattern over AuditLogs, '
                                                  'scope each required Log Analytics workspace, '
                                                  'set the approved evaluation window, enable its '
                                                  'action group and test with a known event.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'Enabled Azure Monitor detection for ATT&CK T1201'},
 'azure.other.attack_t1213': {'category': 'monitoring',
                              'proposed_spec_sha256': '955172a9f930b3f53355e692d11906142a285869f6f8d845ba46bd5b90032521',
                              'provider': 'azure',
                              'remediation_hint': 'Enable repository/database data-plane read logs '
                                                  'and create a scheduled query alert for bulk '
                                                  'read volume in the approved time window with an '
                                                  'enabled response action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'ATT&CK T1213 bulk repository or database reads detection '
                                       'is configured'},
 'azure.other.attack_t1491': {'category': 'monitoring',
                              'proposed_spec_sha256': 'c151d3cd71bf5543578b6ab1339b4939bf113178bc8053da0a40a55d2dc50e56',
                              'provider': 'azure',
                              'remediation_hint': 'Azure portal > Monitor > Alerts > Create alert '
                                                  'rule: Create an enabled scheduled query alert '
                                                  'for the configured AppServiceHTTPLogs event '
                                                  'pattern and route it to an action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'Alert on configured ATT&CK T1491 event pattern'},
 'azure.other.attack_t1496': {'category': 'monitoring',
                              'proposed_spec_sha256': '976584a0a8b6e06cef8f3ff82d35e1a62dbaf5cc87d4143e1b71327d54ff5b07',
                              'provider': 'azure',
                              'remediation_hint': 'Azure Monitor > Alerts > Create > Log search '
                                                  'alert: configure the approved T1496 query '
                                                  'against the approved workspace, enable it and '
                                                  'attach an approved action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'ATT&CK T1496 has an Azure detection rule'},
 'azure.other.attack_t1499': {'category': 'monitoring',
                              'proposed_spec_sha256': '3ec2c3273893f0d3530e607f67ead107dee5602668e752b25f8898af8f54321e',
                              'provider': 'azure',
                              'remediation_hint': 'Deploy and test an enabled '
                                                  'FrontDoorWebApplicationFirewallLog '
                                                  'scheduled-query rule matching the approved '
                                                  'T1499 fragments and route it to an enabled '
                                                  'action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'Enabled Azure Monitor detection for ATT&CK T1499'},
 'azure.other.attack_t1518': {'category': 'monitoring',
                              'proposed_spec_sha256': '5984dfd2621f2d60bcff8b2ddf9295108776f99f5f1f71a92b51f11c134c0fae',
                              'provider': 'azure',
                              'remediation_hint': 'In Azure Monitor > Alerts, create or fix a '
                                                  'scheduled query rule over DeviceProcessEvents '
                                                  'with the approved detection query, scope, '
                                                  'evaluation window and enabled action group.',
                              'resource_kind': 'scheduled_query_rule',
                              'severity': 'medium',
                              'title': 'ATT&CK T1518 software discovery detection is configured'}}

IDS = tuple(SPECS)
SPEC_SHA256 = {key: value['proposed_spec_sha256'] for key, value in SPECS.items()}
NORMALIZATION = 'sha256-kql-text-v1'
EXISTENTIAL = {'1087', '1496'}
NO_TELEMETRY = {'1074', '1496'}
FRAGMENTS = {'1069', '1074'}
TRIGGERS = {'1082', '1087', '1110', '1119', '1136', '1201', '1213', '1491', '1499', '1518'}
DELAY = {'1082', '1110', '1119'}
APPROVED_ACTIONS = {'1082', '1087', '1201', '1213', '1491', '1496', '1499', '1518'}
TABLES = {'1069': 'AuditLogs', '1074': 'StorageBlobLogs', '1110': 'SigninLogs',
          '1119': 'StorageBlobLogs', '1201': 'AuditLogs',
          '1499': 'FrontDoorWebApplicationFirewallLog', '1518': 'DeviceProcessEvents'}
ARM_TYPES = {'scheduled_query_rule': 'Microsoft.Insights/scheduledQueryRules',
             'action_group': 'Microsoft.Insights/actionGroups',
             'log_analytics_workspace': 'Microsoft.OperationalInsights/workspaces'}
_SUBSCRIPTION = re.compile(r'/subscriptions/[A-Za-z0-9._-]{1,128}\Z', re.I)
_ARM = re.compile(r'/subscriptions/[A-Za-z0-9._-]{1,128}/resourceGroups/[^/?#%\x00-\x20]+/providers/[A-Za-z0-9.]+(?:/[^/?#%\x00-\x20]+){2,}\Z', re.I)
_DURATION = re.compile(r'P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?\Z')
_OPERATORS = {'Equals', 'GreaterThan', 'GreaterThanOrEqual', 'LessThan', 'LessThanOrEqual'}
_AGGREGATIONS = {'Count', 'Average', 'Minimum', 'Maximum', 'Total'}


def normalized_query_hash(query):
    """Only normalize line endings and outer whitespace; preserve KQL literals.

    No case folding, comment removal or whitespace collapsing is safe inside
    string literals. Reviews using a different normalizer remain unavailable.
    """
    if not isinstance(query, str) or not query.strip() or '\x00' in query:
        raise Unavailable('KQL text missing or malformed')
    return hashlib.sha256(query.replace('\r\n', '\n').replace('\r', '\n').strip().encode()).hexdigest()


def _seconds(value, *, zero=False):
    if not isinstance(value, str) or not (match := _DURATION.fullmatch(value)) or not any(match.groups()) or 'T' in value and not any(match.groups()[1:]):
        raise Unavailable('ISO duration malformed')
    seconds = sum(float(x or 0) * unit for x, unit in zip(match.groups(), (86400, 3600, 60, 1)))
    if not math.isfinite(seconds) or seconds < 0 or seconds == 0 and not zero:
        raise Unavailable('duration must be bounded and positive')
    return seconds


def _instant(value):
    if not isinstance(value, str):
        raise Unavailable('timestamp missing or malformed')
    try:
        at = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError('timezone absent')
        return at
    except ValueError as exc:
        raise Unavailable('timestamp malformed or timezone absent') from exc


def _strings(value, *, empty=False):
    if (not isinstance(value, list) or not value and not empty or len(value) > 256
            or any(not isinstance(x, str) or not x.strip() for x in value)
            or len(value) != len(set(value))):
        raise Unavailable('string set missing, malformed or duplicated')
    return value


def _resource_id(value, scope, arm_type=None):
    if not isinstance(value, str) or not _ARM.fullmatch(value) or not value.casefold().startswith(scope.casefold() + '/'):
        raise Unavailable('malformed or foreign ARM resource identity')
    if arm_type:
        tail = '/providers/' + arm_type + '/'
        folded = value.casefold()
        if tail.casefold() not in folded or '/' in folded.split(tail.casefold(), 1)[1]:
            raise Unavailable('unexpected ARM resource type')
    return value.casefold()


def _source_id(value, index, scope, proof=None):
    # Directory audit feeds are tenant-wide; a subscription must be explicitly
    # bound to that verified tenant and the same credential/customer capture.
    if isinstance(value, str) and value.casefold() == scope.casefold():
        return scope.casefold()
    if isinstance(value, str) and re.fullmatch(r'/tenants/[A-Za-z0-9._-]{1,128}', value, re.I):
        metadata = get(get(index, 'context', dict), 'metadata', dict)
        tenant = value.rsplit('/', 1)[1]
        subscriptions = get(metadata, 'subscription_tenants', dict)
        bound = next((v for k, v in subscriptions.items() if isinstance(k, str) and k.casefold() == scope.casefold()), None)
        if (get(metadata, 'tenant_verified', bool) is not True
                or get(metadata, 'tenant_id', str).casefold() != tenant.casefold()
                or not isinstance(bound, str) or bound.casefold() != tenant.casefold()):
            raise Unavailable('source tenant/subscription authority unresolved')
        for field in ('credential_context_id', 'customer_context_id'):
            expected = get(metadata, field, str)
            if not expected or proof is not None and get(proof, field, str) != expected:
                raise Unavailable('source capture/customer authority unresolved')
        if proof is not None and (get(proof, 'tenant_verified', bool) is not True
                or get(proof, 'tenant_id', str).casefold() != tenant.casefold()):
            raise Unavailable('telemetry tenant authority unresolved')
        return value.casefold()
    return _resource_id(value, scope)


def _scope_ids(value, scope):
    values = _strings(value)
    normalized = [scope.casefold() if x.casefold() == scope.casefold() else _resource_id(x, scope) for x in values]
    if len(normalized) != len(set(normalized)):
        raise Unavailable('duplicate effective scope identity')
    return set(normalized)


def _scope(item, index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'azure':
        raise Unavailable('Azure snapshot authority unavailable')
    scope = get(context, 'scope', str)
    if not _SUBSCRIPTION.fullmatch(scope) or get(item, 'scope', str).casefold() != scope.casefold():
        raise Unavailable('foreign or malformed subscription scope target')
    if 'provider' in item and get(item, 'provider', str) != 'azure':
        raise Unavailable('foreign scope provider')
    return scope


def _inventory(index, kind, scope):
    def build():
        envelopes = get(index, 'collections', dict).get(kind)
        if (not isinstance(envelopes, list) or len(envelopes) != 1
                or get(envelopes[0], 'type', str) != kind
                or get(envelopes[0], 'scope', str).casefold() != scope.casefold()):
            raise Unavailable('collection scope or cardinality unresolved: ' + kind)
        rows = complete_items(index, kind)
        envelope = envelopes[0]
        if get(envelope, 'status', str) == 'empty' and rows:
            raise Unavailable('empty collection contradicts inventory')
        if 'items' in envelope and get(envelope, 'items', list) != rows:
            raise Unavailable('collection and indexed resources disagree')
        wrappers = get(index, kind, list) if rows else index.get(kind, [])
        if not isinstance(wrappers, list) or len(wrappers) != len(rows):
            raise Unavailable('malformed indexed inventory')
        found = {}
        for wrapper, row in zip(wrappers, rows):
            if (get(wrapper, 'provider', str) != 'azure' or get(wrapper, 'type', str) != kind
                    or get(wrapper, 'scope', str).casefold() != scope.casefold()):
                raise Unavailable('foreign resource wrapper')
            identity = get(row, 'id', str)
            if get(wrapper, 'native_id', str).casefold() != identity.casefold():
                raise Unavailable('indexed native identity mismatch')
            key = _resource_id(identity, scope, ARM_TYPES[kind]) if kind in ARM_TYPES else identity
            if not key or key in found:
                raise Unavailable('missing or duplicate native identity')
            found[key] = row
        return found
    return memoized(index, ('sw11.inventory', kind, scope.casefold()), build)


def _full_default(row, key, default):
    if key in row or key in row.get('_coverage', {}):
        return get(row, key)
    if get(row, '_provenance.representation', str) != 'full':
        raise Unavailable('optional field omitted from partial representation: ' + key)
    return default


def _trigger(condition, *, full=False):
    allowed = {'query', 'timeAggregation', 'operator', 'threshold', 'failingPeriods',
               'dimensions', 'metricMeasureColumn', 'resourceIdColumn', '_coverage', '_provenance'}
    if set(condition) - allowed:
        raise Unavailable('unresolved criterion fields')
    aggregation = get(condition, 'timeAggregation', str)
    operator = get(condition, 'operator', str)
    threshold = get(condition, 'threshold')
    if (aggregation not in _AGGREGATIONS or operator not in _OPERATORS
            or type(threshold) not in (int, float) or not math.isfinite(threshold)):
        raise Unavailable('criterion operator, aggregation or threshold malformed')
    if full and 'failingPeriods' not in condition and 'failingPeriods' not in condition.get('_coverage', {}):
        periods = {'numberOfEvaluationPeriods': 1, 'minFailingPeriodsToAlert': 1}
    else:
        periods = get(condition, 'failingPeriods', dict)
    total = get(periods, 'numberOfEvaluationPeriods', int)
    minimum = get(periods, 'minFailingPeriodsToAlert', int)
    if not 0 < minimum <= total or set(periods) - {'numberOfEvaluationPeriods', 'minFailingPeriodsToAlert', '_coverage'}:
        raise Unavailable('failing periods malformed')
    if full and 'dimensions' not in condition and 'dimensions' not in condition.get('_coverage', {}):
        dimensions = []
    else:
        dimensions = get(condition, 'dimensions', list)
    names = set()
    for dimension in dimensions:
        name = get(dimension, 'name', str)
        if not name or name in names or get(dimension, 'operator', str) not in ('Include', 'Exclude'):
            raise Unavailable('criterion dimensions malformed')
        _strings(get(dimension, 'values', list))
        if set(dimension) != {'name', 'operator', 'values'}:
            raise Unavailable('unresolved dimension fields')
        names.add(name)
    fields = {}
    for key in ('metricMeasureColumn', 'resourceIdColumn'):
        if key in condition or key in condition.get('_coverage', {}):
            value = get(condition, key)
        elif full:
            value = None
        else:
            raise Unavailable('criterion optional column unresolved')
        if value is not None and (not isinstance(value, str) or not value):
            raise Unavailable('criterion column malformed')
        fields[key] = value
    return {'timeAggregation': aggregation, 'operator': operator, 'threshold': threshold,
            'failingPeriods': {'numberOfEvaluationPeriods': total, 'minFailingPeriodsToAlert': minimum},
            'dimensions': dimensions, **fields}


def _policy(index, check_id, scope):
    context = get(index, 'context', dict)
    policy = get(context, 'metadata.compliance_policy.azure_attack_detection', dict)
    if get(policy, 'status', str) != 'collected' or get(policy, 'subscription_scope', str).casefold() != scope.casefold():
        raise Unavailable('detection review policy unavailable or foreign')
    if 'observed_at' in policy or 'max_age_seconds' in policy:
        elapsed = (_instant(get(context, 'created_at', str)) - _instant(get(policy, 'observed_at', str))).total_seconds()
        maximum = get(policy, 'max_age_seconds', int)
        if maximum <= 0 or not 0 <= elapsed <= maximum:
            raise Unavailable('detection review policy stale or future')
    checks = get(policy, 'checks', dict)
    entry = get({'entry': checks[check_id]}, 'entry', dict) if check_id in checks else None
    # Check IDs contain dots; use a one-key object rather than a dotted accessor.
    if entry is None:
        raise Unavailable('check-specific detection policy absent')
    requirements = get(entry, 'requirements', list)
    if not requirements or len(requirements) > 256:
        raise Unavailable('nonempty bounded detection policy required')
    technique = check_id.rsplit('t', 1)[1]
    seen = set()
    for requirement in requirements:
        workspace = _resource_id(get(requirement, 'workspace_id', str), scope, ARM_TYPES['log_analytics_workspace'])
        pattern = get(requirement, 'pattern_id', str)
        if not pattern.strip() or (workspace, pattern) in seen:
            raise Unavailable('pattern identity missing or duplicated')
        seen.add((workspace, pattern))
        _scope_ids(get(requirement, 'scope_ids', list), scope)
        if technique in APPROVED_ACTIONS:
            groups = [_resource_id(x, scope, ARM_TYPES['action_group']) for x in _strings(get(requirement, 'approved_action_group_ids', list))]
            if len(groups) != len(set(groups)):
                raise Unavailable('duplicate approved action group')
        if technique in FRAGMENTS:
            _strings(get(requirement, 'required_fragments', list))
        if technique in DELAY and get(requirement, 'max_notification_delay_seconds', int) <= 0:
            raise Unavailable('notification delay policy unavailable')
        reviews = get(requirement, 'queries', list)
        if not reviews or len(reviews) > 256:
            raise Unavailable('nonempty reviewed query policy required')
        hashes = set()
        for review in reviews:
            digest = get(review, 'sha256', str)
            if not re.fullmatch('[0-9a-f]{64}', digest) or digest in hashes:
                raise Unavailable('reviewed digest malformed or duplicated')
            hashes.add(digest)
            if (get(review, 'normalization', str) != NORMALIZATION
                    or get(review, 'semantics_reviewed', bool) is not True
                    or get(review, 'fully_resolved', bool) is not True):
                raise Unavailable('reviewed effective KQL semantics unavailable')
            raw_effective = _strings(get(review, 'effective_workspace_ids', list))
            effective = {_resource_id(x, scope, ARM_TYPES['log_analytics_workspace']) for x in raw_effective}
            if len(raw_effective) != len(effective):
                raise Unavailable('duplicate reviewed workspace identity')
            if workspace not in effective:
                raise Unavailable('reviewed query does not cover required workspace')
            tables = _strings(get(review, 'source_tables', list))
            if any(not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', x) for x in tables):
                raise Unavailable('reviewed source table malformed')
            if technique in TABLES and TABLES[technique] not in tables:
                raise Unavailable('reviewed query uses wrong detection table')
            if technique == '1213' and set(tables) <= {'AzureActivity'}:
                raise Unavailable('control-plane activity cannot attest data-plane bulk reads')
            if technique != '1496':
                frequency = _seconds(get(review, 'evaluationFrequency', str))
                window = _seconds(get(review, 'windowSize', str))
                maximum = get(review, 'max_lookback_seconds', int)
                if frequency > window or maximum <= 0:
                    raise Unavailable('timing policy malformed or unbounded')
            if technique in TRIGGERS:
                if get(review, 'trigger_semantics_reviewed', bool) is not True:
                    raise Unavailable('approved trigger semantics unresolved')
                _trigger(get(review, 'trigger', dict), full=False)
            if technique in DELAY:
                delay = get(review, 'max_trigger_delay_seconds', int)
                if delay < 0 or delay > get(requirement, 'max_notification_delay_seconds', int):
                    raise Unavailable('reviewed trigger notification delay unresolved')
        if technique not in NO_TELEMETRY:
            sources = get(requirement, 'sources', list)
            if not sources or len(sources) > 256:
                raise Unavailable('required source telemetry policy absent')
            pairs = set()
            for source in sources:
                resource = _source_id(get(source, 'resource_id', str), index, scope)
                table = get(source, 'table', str)
                age = get(source, 'lookback_seconds', int)
                if not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', table) or age <= 0 or (resource, table) in pairs:
                    raise Unavailable('source telemetry policy malformed or duplicated')
                pairs.add((resource, table))
            if any(not set(get(review, 'source_tables', list)) <= {table for _, table in pairs} for review in reviews):
                raise Unavailable('query source tables lack ingestion policy')
    return requirements


def _rules(index, scope, technique):
    rules = _inventory(index, 'scheduled_query_rule', scope)
    parsed = []
    for identity, row in rules.items():
        props = get(row, 'properties', dict)
        # API 2021-08-01 documents LogAlert as the omitted-kind default.
        kind = _full_default(row, 'kind', 'LogAlert')
        if kind not in ('LogAlert', 'LogToMetric'):
            raise Unavailable('unrecognized scheduled query rule kind')
        enabled = get(props, 'enabled', bool)
        scopes = _scope_ids(get(props, 'scopes', list), scope)
        if kind == 'LogToMetric':
            continue
        criteria = get(props, 'criteria.allOf', list)
        if not criteria or any(not isinstance(x, dict) for x in criteria):
            raise Unavailable('scheduled query criteria malformed')
        # A multi-condition AND can suppress the reviewed signal. Until the
        # complete AND is reviewed, it cannot prove coverage or its absence.
        if len(criteria) != 1:
            raise Unavailable('multi-condition KQL/AND semantics unresolved')
        condition = criteria[0]
        query = get(condition, 'query', str)
        digest = normalized_query_hash(query)
        raw_groups = _strings(get(props, 'actions.actionGroups', list), empty=True)
        groups = {_resource_id(x, scope, ARM_TYPES['action_group']) for x in raw_groups}
        if len(groups) != len(raw_groups):
            raise Unavailable('duplicate native action group identity')
        trigger = None
        timing = None
        if technique != '1496':
            frequency = _seconds(get(props, 'evaluationFrequency', str))
            window = _seconds(get(props, 'windowSize', str))
            full = optional(row, '_provenance', {}, dict).get('representation') == 'full'
            if technique in TRIGGERS:
                trigger = _trigger(condition, full=full)
                periods = trigger['failingPeriods']['numberOfEvaluationPeriods']
            else:
                # Even timing-only policies need the effective query lookback.
                if 'failingPeriods' in condition or 'failingPeriods' in condition.get('_coverage', {}):
                    periods_row = get(condition, 'failingPeriods', dict)
                    periods = get(periods_row, 'numberOfEvaluationPeriods', int)
                    minimum = get(periods_row, 'minFailingPeriodsToAlert', int)
                    if not 0 < minimum <= periods:
                        raise Unavailable('failing periods malformed')
                elif full:
                    periods = 1
                else:
                    raise Unavailable('effective lookback unresolved')
            override = get(props, 'overrideQueryTimeRange') if 'overrideQueryTimeRange' in props or 'overrideQueryTimeRange' in props.get('_coverage', {}) else (None if full else _full_default(props, 'overrideQueryTimeRange', None))
            lookback = window * periods if override is None else _seconds(override)
            mute = 0
            if technique in DELAY:
                mute_value = get(props, 'muteActionsDuration') if 'muteActionsDuration' in props or 'muteActionsDuration' in props.get('_coverage', {}) else (None if full else _full_default(props, 'muteActionsDuration', None))
                mute = 0 if mute_value is None else _seconds(mute_value, zero=True)
            timing = (frequency, window, lookback, mute)
        parsed.append({'id': identity, 'enabled': enabled, 'scopes': scopes, 'query': query,
                       'sha256': digest, 'groups': groups, 'trigger': trigger, 'timing': timing})
    return parsed


def _groups(index, scope, technique):
    groups = _inventory(index, 'action_group', scope)
    for group in groups.values():
        props = get(group, 'properties', dict)
        if technique != '1496' or 'enabled' in props:
            get(props, 'enabled', bool)
        if technique == '1136':
            delivery = get(group, '_delivery_evidence', dict)
            if get(delivery, 'status', str) != 'collected':
                raise Unavailable('action group delivery evidence unavailable')
            get(delivery, 'reachable', bool)
            observed = _instant(get(delivery, 'observed_at', str))
            age = get(delivery, 'max_age_seconds', int)
            elapsed = (_instant(get(get(index, 'context', dict), 'created_at', str)) - observed).total_seconds()
            if age <= 0 or not 0 <= elapsed <= age or get(delivery, 'action_group_id', str).casefold() != get(group, 'id', str).casefold():
                raise Unavailable('action group delivery evidence stale or foreign')
    return groups


def _telemetry(index, scope, technique):
    rows = _inventory(index, 'azure_detection_telemetry', scope)
    parsed = {}
    for row in rows.values():
        if row.get('_provenance', {}).get('contract') == 'sw12-v1':
            continue
        workspace = _resource_id(get(row, 'workspace_id', str), scope, ARM_TYPES['log_analytics_workspace'])
        resource = _source_id(get(row, 'source_resource_id', str), index, scope, get(row, '_provenance', dict))
        table = get(row, 'table', str)
        if not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', table):
            raise Unavailable('telemetry table malformed')
        key = (workspace, resource, table)
        if key in parsed or get(row, 'id', str) != '|'.join(key):
            raise Unavailable('telemetry identity ambiguous or mismatched')
        observation = row.get('_coverage', {}).get('observation')
        if (row.get('_provenance', {}).get('contract') == 'sw11-v1' and isinstance(observation, dict)
                and observation.get('status') in {'not_collected', 'denied', 'malformed', 'timeout', 'unknown', 'partial'}):
            proof = get(row, '_provenance', dict)
            if (proof.get('source_operation') != 'azure_detection_telemetry' or proof.get('read_only') is not True
                    or proof.get('native_response_complete') is not False):
                raise Unavailable('invalid unavailable telemetry provenance')
            parsed[key] = None
            continue
        export_enabled = get(row, 'export_enabled', bool)
        get(row, 'routing_verified', bool)
        proof = get(row, '_provenance', dict)
        if not export_enabled and get(proof, 'source_operation', str) == 'diagnostic_settings.list':
            if (get(proof, 'read_only', bool) is not True
                    or get(proof, 'source_filter_verified', bool) is not True
                    or get(proof, 'export_inventory_status', str) not in ('collected', 'empty')):
                raise Unavailable('disabled data-plane export assessment incomplete')
            elapsed = (_instant(get(get(index, 'context', dict), 'created_at', str))
                       - _instant(get(proof, 'export_observed_at', str))).total_seconds()
            age = get(proof, 'export_max_age_seconds', int)
            if age <= 0 or not 0 <= elapsed <= age:
                raise Unavailable('disabled data-plane export assessment stale or future')
            parsed[key] = row
            continue
        query_at = _instant(get(row, 'queried_at', str))
        count = get(row, 'row_count', int)
        lookback = get(row, 'lookback_seconds', int)
        last = get(row, 'last_ingested_at')
        if count < 0 or lookback <= 0 or (last is None) != (count == 0):
            raise Unavailable('telemetry aggregate malformed')
        if last is not None and not 0 <= (query_at - _instant(last)).total_seconds() <= lookback:
            raise Unavailable('ingestion timestamp outside measured interval')
        capture = _instant(get(get(index, 'context', dict), 'created_at', str))
        if not 0 <= (capture - query_at).total_seconds() <= lookback:
            raise Unavailable('telemetry aggregate stale or future')
        proof = get(row, '_provenance', dict)
        if (get(proof, 'source_operation', str) != 'logs.query'
                or get(proof, 'read_only', bool) is not True
                or get(proof, 'source_filter_verified', bool) is not True):
            raise Unavailable('telemetry source filter or read authority unresolved')
        parsed[key] = row
    return parsed


def _feed(requirement, telemetry, technique, capture):
    workspace = requirement['workspace_id'].casefold()
    for source in requirement['sources']:
        key = (workspace, source['resource_id'].casefold(), source['table'])
        if key not in telemetry:
            return 'UNKNOWN'
        row = telemetry[key]
        if row is None:
            return 'UNKNOWN'
        if not row['export_enabled']:
            return 'FAIL' if technique == '1213' else 'UNKNOWN'
        if row['lookback_seconds'] < source['lookback_seconds']:
            return 'UNKNOWN'
        if not row['routing_verified']:
            return 'UNKNOWN'
        last = row['last_ingested_at']
        if last is None or (capture - _instant(last)).total_seconds() > source['lookback_seconds']:
            return 'FAIL' if technique == '1049' else 'UNKNOWN'
    return 'PASS'


def _coverage(requirement, rules, groups, technique):
    expected_scopes = {x.casefold() for x in requirement['scope_ids']}
    approved = {x.casefold() for x in requirement.get('approved_action_group_ids', [])}
    reviews = {row['sha256']: row for row in requirement['queries']}
    uncertain = False
    for rule in rules:
        if not rule['enabled'] or rule['scopes'] != expected_scopes:
            continue
        if technique in FRAGMENTS and (TABLES[technique] not in rule['query']
                or any(fragment not in rule['query'] for fragment in requirement['required_fragments'])):
            continue
        review = reviews.get(rule['sha256'])
        if review is None:
            # Fragment-based specs leave interpretation of a new query UNKNOWN;
            # exact approved-hash specs can positively reject an unapproved hash.
            uncertain |= technique in FRAGMENTS
            continue
        if technique != '1496':
            frequency, window, lookback, mute = rule['timing']
            if (frequency != _seconds(review['evaluationFrequency']) or window != _seconds(review['windowSize'])
                    or lookback > review['max_lookback_seconds']):
                continue
            if technique in DELAY:
                if mute + review['max_trigger_delay_seconds'] > requirement['max_notification_delay_seconds']:
                    continue
        if technique in TRIGGERS and rule['trigger'] != _trigger(review['trigger'], full=False):
            continue
        for group_id in rule['groups']:
            if technique in APPROVED_ACTIONS and group_id not in approved:
                continue
            group = groups.get(group_id)
            if group is None:
                uncertain |= technique == '1074'
                continue
            if technique == '1496':
                return 'PASS'
            if not group['properties']['enabled']:
                uncertain |= technique == '1074'
                continue
            if technique == '1136' and not group['_delivery_evidence']['reachable']:
                continue
            return 'PASS'
    return 'UNKNOWN' if uncertain else 'FAIL'


def _evaluate(check_id, item, index):
    scope = _scope(item, index)
    technique = check_id.rsplit('t', 1)[1]
    requirements = _policy(index, check_id, scope)
    workspaces = _inventory(index, 'log_analytics_workspace', scope)
    rules = _rules(index, scope, technique)
    groups = _groups(index, scope, technique)
    telemetry = {} if technique in NO_TELEMETRY else _telemetry(index, scope, technique)
    capture = None if technique in NO_TELEMETRY else _instant(get(get(index, 'context', dict), 'created_at', str))
    states, observations = [], []
    for requirement in requirements:
        required_workspaces = {requirement['workspace_id'].casefold()}
        required_workspaces.update(x.casefold() for review in requirement['queries'] for x in review['effective_workspace_ids'])
        if not required_workspaces <= workspaces.keys():
            states.append('UNKNOWN')
            observations.append({'pattern_id': requirement['pattern_id'], 'state': 'UNKNOWN', 'reason': 'workspace not resolved'})
            continue
        feed = 'PASS' if technique in NO_TELEMETRY else _feed(requirement, telemetry, technique, capture)
        state = _coverage(requirement, rules, groups, technique) if feed == 'PASS' else feed
        states.append(state)
        observations.append({'workspace_id': requirement['workspace_id'], 'pattern_id': requirement['pattern_id'], 'state': state})
    # Unknown requirements cannot establish absence. An existential match may
    # pass once its required feed is resolved; universal coverage needs every one.
    if technique in EXISTENTIAL:
        if 'PASS' in states:
            return result(False, coverage=observations, semantics='At least one approved workspace detection; no prevention assurance')
        if 'UNKNOWN' in states:
            return unknown('detection coverage unresolved', coverage=observations)
        return result(True, coverage=observations, semantics='No approved qualifying detection in complete inventories')
    if 'UNKNOWN' in states:
        return unknown('detection coverage or source telemetry unresolved', coverage=observations)
    return result('FAIL' in states, coverage=observations, semantics='Every required workspace/pattern; snapshot declarations and reviewed semantics only')


LOCAL_CHECKS = {}
EVALUATORS = {}
for _id, _spec in SPECS.items():
    _technique = _id.rsplit('t', 1)[1]
    _dependencies = ['scheduled_query_rule', 'action_group', 'log_analytics_workspace']
    if _technique not in NO_TELEMETRY:
        _dependencies.append('azure_detection_telemetry')

    @register(_id, _spec['provider'], 'hardening', _spec['resource_kind'],
              _spec['title'], _spec['severity'], 'SI-4', _spec['remediation_hint'],
              target='scope', dependencies=_dependencies)
    def _registered(item, index, check_id=_id):
        return _evaluate(check_id, item, index)

    # Copy the sw09 signed-category adapter: the older register validator only
    # admits five categories. Replace only the object just registered here.
    if CHECKS[-1].id != _id:
        raise RuntimeError('unexpected sw11 registry order')
    CHECKS[-1] = replace(CHECKS[-1], category=_spec['category'])
    LOCAL_CHECKS[_id] = CHECKS[-1]
    EVALUATORS[_id] = CHECKS[-1].evaluate
