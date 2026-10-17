"""Signed sw25 Azure predicates over complete, scope-bound offline evidence.

Collector contracts for absent evidence are in sw25-collector-requests.md.
No network calls or admission/delivery guarantees are inferred from configuration.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
import re

from . import result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects, optional, azure_directory_join_authorized

SPECS = {'azure_c5_ops_17_02b': {'provider': 'azure',
                         'resource_kind': 'activity_log_alert',
                         'severity': 'medium',
                         'category': 'monitoring',
                         'title': 'Critical Azure operations have Activity Log alerts',
                         'remediation_hint': 'Define the failures requiring escalation, configure '
                                             'activity-log or scheduled-query alerts to the responsible '
                                             'department, and verify prompt delivery with test failures.',
                         'proposed_spec_sha256': '986e5edc63ea10911632356c53c00d3ffda8fe622dcbf2ecd8061d15a3542d2a'},
 'azure_pci_10_2_1_1_8': {'provider': 'azure',
                          'resource_kind': 'activity_log_alert',
                          'severity': 'medium',
                          'category': 'hardening',
                          'title': 'Required Activity Log alerts route to approved action groups',
                          'remediation_hint': 'Attach an action group to each relevant Azure Monitor alert '
                                              'and configure the required state actions; match a specific '
                                              'action group only when one is supplied.',
                          'proposed_spec_sha256': 'f49f5b81d7785612ff17750424fdf138634a0e9a2598cf715819b3025c60e475'},
 'azure.cis.access_review_up_external_users_in_entra_privileged_identity_694482': {'provider': 'azure',
                                                                                   'resource_kind': 'access_review_definition',
                                                                                   'severity': 'high',
                                                                                   'category': 'least_privilege',
                                                                                   'title': 'Guest '
                                                                                            'privileged role '
                                                                                            'assignments '
                                                                                            'receive a '
                                                                                            'current access '
                                                                                            'review',
                                                                                   'remediation_hint': 'In '
                                                                                                       'Entra '
                                                                                                       'admin '
                                                                                                       'center '
                                                                                                       '> '
                                                                                                       'Identity '
                                                                                                       'Governance '
                                                                                                       '> '
                                                                                                       'Access '
                                                                                                       'reviews, '
                                                                                                       'create '
                                                                                                       'a '
                                                                                                       'recurring '
                                                                                                       'review '
                                                                                                       'covering '
                                                                                                       'each '
                                                                                                       'guest '
                                                                                                       'privileged '
                                                                                                       'role; '
                                                                                                       'complete '
                                                                                                       'a '
                                                                                                       'decision '
                                                                                                       'for '
                                                                                                       'every '
                                                                                                       'assigned '
                                                                                                       'guest.',
                                                                                   'proposed_spec_sha256': 'a6a3bf2c6f00e33a822a181f35f1cfb99af6974777be2b7544d98ccdcc2b5b3c'},
 'azure.cis.guest_users_reviewed_monthly_basis': {'provider': 'azure',
                                                  'resource_kind': 'access_review_definition',
                                                  'severity': 'medium',
                                                  'category': 'identity',
                                                  'title': 'Review every guest user monthly',
                                                  'remediation_hint': 'Microsoft Entra admin center > '
                                                                      'Identity Governance > Access reviews: '
                                                                      'create a recurring monthly guest '
                                                                      'review and complete each due guest '
                                                                      'decision before the review window '
                                                                      'ends.',
                                                  'proposed_spec_sha256': '1a42b6c6340cd0a8592d3781404ef3468ca51e97da65af376521fc6eba34ecf5'},
 'azure.cis.guest_users_reviewed_regular_basis': {'provider': 'azure',
                                                  'resource_kind': 'access_review_definition',
                                                  'severity': 'medium',
                                                  'category': 'identity',
                                                  'title': 'Ensure Guest Users Are Reviewed on a Regular '
                                                           'Basis',
                                                  'remediation_hint': 'In Entra admin center > Identity '
                                                                      'Governance > Access reviews, '
                                                                      'configure a recurring guest review '
                                                                      'and complete decisions for every '
                                                                      'guest within maxReviewAgeDays.',
                                                  'proposed_spec_sha256': '22654a8b78bd967b292615f13960ae92d376cd0673e40531fd6ddbc77e149148'},
 'azure.cis.non_privileged_role_assignments_periodically_reviewed': {'provider': 'azure',
                                                                     'resource_kind': 'access_review_definition',
                                                                     'severity': 'high',
                                                                     'category': 'least_privilege',
                                                                     'title': 'Review non-privileged '
                                                                              'directory role assignments',
                                                                     'remediation_hint': 'Entra admin center '
                                                                                         '> Identity '
                                                                                         'Governance > '
                                                                                         'Access reviews: '
                                                                                         'add a recurring '
                                                                                         'review for the '
                                                                                         'affected role '
                                                                                         'assignments and '
                                                                                         'complete overdue '
                                                                                         'principal '
                                                                                         'decisions.',
                                                                     'proposed_spec_sha256': 'c3564da30a32349c48e4934c203df9306d9eb1b67a3d029c97a4b27f3b41313a'},
 'azure.cis.privileged_role_assignments_periodically_reviewed': {'provider': 'azure',
                                                                 'resource_kind': 'access_review_definition',
                                                                 'severity': 'high',
                                                                 'category': 'least_privilege',
                                                                 'title': "Ensure that all 'privileged' role "
                                                                          'assignments are periodically '
                                                                          'reviewed',
                                                                 'remediation_hint': 'In Entra admin center '
                                                                                     '> Identity Governance '
                                                                                     '> Access reviews, '
                                                                                     'schedule '
                                                                                     'privileged-role '
                                                                                     'reviews and finish a '
                                                                                     'decision for each '
                                                                                     'assignment within '
                                                                                     'maxReviewAgeDays.',
                                                                 'proposed_spec_sha256': '1961ce6dbc0daff66d5c3e6224ebb77dd5bfde2f391e00477ba955578d8b4c60'},
 'azure.cis.tenant_creator_role_assignments_periodically_reviewed': {'provider': 'azure',
                                                                     'resource_kind': 'access_review_definition',
                                                                     'severity': 'medium',
                                                                     'category': 'least_privilege',
                                                                     'title': "Ensure 'Tenant Creator' role "
                                                                              'assignments are periodically '
                                                                              'reviewed',
                                                                     'remediation_hint': 'Azure portal > '
                                                                                         'Microsoft Entra ID '
                                                                                         '> Identity '
                                                                                         'Governance > '
                                                                                         'Access reviews: '
                                                                                         'Schedule a '
                                                                                         'recurring Tenant '
                                                                                         'Creator access '
                                                                                         'review and '
                                                                                         'complete a '
                                                                                         'decision for each '
                                                                                         'assignee.',
                                                                     'proposed_spec_sha256': '954e3ba4054b9977240fedc01f8486a61e0fbe68b226e4d10295599c091b829e'},
 'azure.gap.capacity_usage_alerts': {'provider': 'azure',
                                     'resource_kind': 'metric_alert',
                                     'severity': 'medium',
                                     'category': 'monitoring',
                                     'title': 'Workload capacity alerts are configured',
                                     'remediation_hint': 'Collect capacity metrics over the approved window, '
                                                         'establish current-use baselines, forecast average '
                                                         'and peak use including component failure, and add '
                                                         'capacity or alerts where thresholds are exceeded.',
                                     'proposed_spec_sha256': 'b4172f8a5f5ce60c7d906d2339e3de96cec996422e5cfdff438d08c678670d7e'},
 'azure.other.gateway_backend_health_alert': {'provider': 'azure',
                                              'resource_kind': 'metric_alert',
                                              'severity': 'medium',
                                              'category': 'monitoring',
                                              'title': 'Application Gateway unhealthy backend hosts trigger '
                                                       'an alert',
                                              'remediation_hint': 'Create an alert that compares '
                                                                  'healthy-to-unhealthy backend transitions '
                                                                  'against total targets over five minutes '
                                                                  'and notifies an enabled action group when '
                                                                  'the changed fraction exceeds 10%; test '
                                                                  'with a qualifying transition.',
                                              'proposed_spec_sha256': 'e77b0f4c2cdef102e02233a9cfe86befb23a75ffeb17f02380adcf000376d76e'},
 'azure_diagnostic_setting_11_5_2_3_7959930': {'provider': 'azure',
                                               'resource_kind': 'metric_alert',
                                               'severity': 'medium',
                                               'category': 'monitoring',
                                               'title': 'Azure Monitor metric alerts match approved settings',
                                               'remediation_hint': 'Monitor > Alerts > Alert rules: create '
                                                                   'or update each metric alert to the '
                                                                   'approved scope, aggregation, threshold, '
                                                                   'evaluation window, severity and enabled '
                                                                   'action group.',
                                               'proposed_spec_sha256': '4172b5a163f5b381e659f2dd5409ddd0465eb9038627e68d1511432f6cf055e8'},
 'azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa': {'provider': 'azure',
                                                                            'resource_kind': 'metric_alert',
                                                                            'severity': 'medium',
                                                                            'category': 'monitoring',
                                                                            'title': 'Create required Azure '
                                                                                     'Monitor metric alerts',
                                                                            'remediation_hint': 'In Azure '
                                                                                                'Monitor, '
                                                                                                'create or '
                                                                                                'enable the '
                                                                                                'alert for '
                                                                                                'the '
                                                                                                'specified '
                                                                                                'metric on '
                                                                                                'each '
                                                                                                'required '
                                                                                                'resource '
                                                                                                'ID.',
                                                                            'proposed_spec_sha256': '4be32cf8637ef7164d43aca5a9ade3d0f9bda18a6c9d89d637bb6eb883979634'},
 'azure.gap.kubernetes_cluster_container_cpu_and_memory_resource_limit': {'provider': 'azure',
                                                                          'resource_kind': 'pod',
                                                                          'severity': 'medium',
                                                                          'category': 'hardening',
                                                                          'title': 'Bound AKS container CPU '
                                                                                   'and memory limits',
                                                                          'remediation_hint': 'Set CPU and '
                                                                                              'memory limits '
                                                                                              'for every '
                                                                                              'applicable '
                                                                                              'regular, init '
                                                                                              'and ephemeral '
                                                                                              'container or '
                                                                                              'an effective '
                                                                                              'namespace '
                                                                                              'LimitRange; '
                                                                                              'redeploy and '
                                                                                              'verify '
                                                                                              'admitted '
                                                                                              'Pods.',
                                                                          'proposed_spec_sha256': '9256abd23a6315da0df1eae4e712b9edf0f445a213b579ee2d077b3b7b48bb36'},
 'azure.gap.kubernetes_cluster_container_use_allowed_apparmor_profile': {'provider': 'azure',
                                                                         'resource_kind': 'pod',
                                                                         'severity': 'medium',
                                                                         'category': 'hardening',
                                                                         'title': 'Kubernetes cluster '
                                                                                  'containers should only '
                                                                                  'use allowed AppArmor '
                                                                                  'profiles',
                                                                         'remediation_hint': 'Set '
                                                                                             'pod/container '
                                                                                             'securityContext.appArmorProfile.type '
                                                                                             'to '
                                                                                             'RuntimeDefault '
                                                                                             'or an approved '
                                                                                             'Localhost '
                                                                                             'profile, '
                                                                                             'including init '
                                                                                             'and ephemeral '
                                                                                             'containers; '
                                                                                             'redeploy and '
                                                                                             'enforce '
                                                                                             'through '
                                                                                             'admission '
                                                                                             'policy.',
                                                                         'proposed_spec_sha256': '73633e4aa84c8b47319767c174189e71dc69941311949cb2ec9fc2dc64ed7ae4'},
 'azure.gap.kubernetes_cluster_container_use_allowed_images': {'provider': 'azure',
                                                               'resource_kind': 'pod',
                                                               'severity': 'medium',
                                                               'category': 'hardening',
                                                               'title': 'Kubernetes cluster containers '
                                                                        'should only use allowed images',
                                                               'remediation_hint': 'Pin Pod images to '
                                                                                   'approved registry '
                                                                                   'digests in workload '
                                                                                   'manifests and redeploy; '
                                                                                   'configure admission '
                                                                                   'policy to reject '
                                                                                   'unapproved images.',
                                                               'proposed_spec_sha256': 'e113245f305fd2f31ca8a20dc6bff9fcde24607d9df55103a94efd16755fc3dc'}}

IDS = tuple(SPECS)

REPORT_ID, ROUTING_ID, GUEST_PRIV_ID, MONTHLY_ID, REGULAR_ID, NONPRIV_ID, PRIV_ID, TENANT_ID, CAPACITY_ID, GATEWAY_ID, SETTINGS_ID, REQUIRED_ID, LIMITS_ID, APPARMOR_ID, IMAGES_ID = IDS
REVIEW_IDS = (GUEST_PRIV_ID, MONTHLY_ID, REGULAR_ID, NONPRIV_ID, PRIV_ID, TENANT_ID)
FAMILIES = ('activity_log_alert', 'metric_alert', 'scheduled_query_rule')
ARM_TYPES = {'activity_log_alert': 'Microsoft.Insights/activityLogAlerts',
             'metric_alert': 'Microsoft.Insights/metricAlerts',
             'scheduled_query_rule': 'Microsoft.Insights/scheduledQueryRules',
             'action_group': 'Microsoft.Insights/actionGroups',
             'application_gateway': 'Microsoft.Network/applicationGateways'}


def _text(value):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise Unavailable('missing or malformed identity/string')
    return value


def _strings(value):
    if not isinstance(value, list):
        raise Unavailable('expected explicit string list')
    values = [_text(x) for x in value]
    if len(set(values)) != len(values):
        raise Unavailable('duplicate string identity')
    return values


def _date(value):
    try:
        instant = datetime.fromisoformat(_text(value).replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('invalid timestamp') from exc
    if instant.utcoffset() is None:
        raise Unavailable('timestamp lacks timezone')
    return instant


def _number(value, *, positive=False, signed=False):
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise Unavailable('invalid measured number')
    try:
        number = Decimal(str(value))
    except InvalidOperation as exc:
        raise Unavailable('invalid measured number') from exc
    if not number.is_finite() or number < 0 and not signed or positive and number <= 0:
        raise Unavailable('nonfinite or negative measured number')
    return number


def _scope(index):
    context = get(index, 'context', dict)
    scope = _text(get(context, 'scope', str))
    if get(context, 'provider', str) != 'azure' or not re.fullmatch(r'/subscriptions/[^/?#]+', scope, re.I):
        raise Unavailable('Azure subscription scope unresolved')
    return scope


def _policy(index, cid):
    scope = _scope(index)
    metadata = get(get(index, 'context', dict), 'metadata', dict)
    policies = optional(metadata, 'sw25_policy', None, dict)
    if 'sw25_policy' in metadata and not isinstance(policies, dict):
        raise Unavailable('legacy SW25 policy is malformed')
    if isinstance(policies, dict) and cid in policies:
        policy = _literal(policies, cid)
    else:
        review = get(metadata, 'compliance_policy.sw25', dict)
        if (get(review, 'status', str) != 'collected' or
                get(review, 'scope', str).casefold() != scope.casefold()):
            raise Unavailable('SW25 requirements unavailable or foreign')
        policy = _literal(get(review, 'checks', dict), cid)
        if not isinstance(policy, dict):
            raise Unavailable('policy is not an object')
        if 'scope' in policy and (not isinstance(policy['scope'], str) or policy['scope'].casefold() != scope.casefold()):
            raise Unavailable('policy belongs to another subscription')
        policy = {**policy, 'scope': scope}
    if not isinstance(policy, dict):
        raise Unavailable('policy is not an object')
    if get(policy, 'scope', str).casefold() != scope.casefold():
        raise Unavailable('policy belongs to another subscription')
    return policy


def _now(index):
    return _date(get(get(index, 'context', dict), 'created_at', str))


def _rows(index, kind, *, graph=False, identity='id'):
    scope = _scope(index)
    rows = complete_items(index, kind)
    envelopes = get(get(index, 'collections', dict), kind, list)
    wrappers = get(index, kind, list)
    expected_scopes = set()
    for envelope in envelopes:
        actual = get(envelope, 'scope', str)
        expected_scopes.add(actual)
        if get(envelope, 'type', str) != kind:
            raise Unavailable('foreign collection type')
        if graph:
            metadata = get(get(index, 'context', dict), 'metadata', dict)
            if not azure_directory_join_authorized(scope, metadata, envelope):
                raise Unavailable('directory tenant/capture/customer binding unresolved')
        elif actual.casefold() != scope.casefold():
            raise Unavailable('foreign collection scope: ' + kind)
        if get(envelope, 'status', str) == 'empty' and envelope.get('items', []):
            raise Unavailable('empty collection contains rows')
        if envelope.get('nextLink') or envelope.get('@odata.nextLink') or envelope.get('continue'):
            raise Unavailable('unfinished collection continuation')
    if len(expected_scopes) != 1:
        raise Unavailable('ambiguous collection scopes')
    for wrapper in wrappers:
        if get(wrapper, 'scope', str) not in expected_scopes or get(wrapper, 'type', str) != kind:
            raise Unavailable('foreign resource wrapper')
    found = set()
    for row in rows:
        rid = _text(get(row, identity, str))
        key = rid.casefold() if kind in ARM_TYPES or identity == 'resourceId' else rid
        if key in found:
            raise Unavailable('duplicate resource identity: ' + kind)
        found.add(key)
        if kind in ARM_TYPES:
            _arm(rid, scope, ARM_TYPES[kind])
        if graph:
            metadata = get(get(index, 'context', dict), 'metadata', dict)
            if (get(row, '_provenance.tenant_verified', bool) is not True
                    or get(row, '_provenance.tenant_id', str).casefold() != get(metadata, 'tenant_id', str).casefold()):
                raise Unavailable('projected directory item belongs to an unverified tenant')
    # A collector may retain empty envelope items for memory reasons; if present,
    # their native IDs must still agree with the projected index, not just counts.
    if all('items' in e for e in envelopes):
        native = [get(row, identity, str) for e in envelopes for row in list_of_objects(get(e, 'items', list))]
        projected = [get(row, identity, str) for row in rows]
        if sorted(native) != sorted(projected):
            raise Unavailable('collection/index item identities disagree')
    return rows


def _arm(rid, scope, resource_type=None):
    _text(rid)
    match = re.fullmatch(r'(/subscriptions/[^/?#]+)/resourceGroups/[^/?#]+/providers/([^/?#]+)/(.*)', rid, re.I)
    if not match or match[1].casefold() != scope.casefold():
        raise Unavailable('malformed or foreign ARM resource ID')
    parts = (match[2] + '/' + match[3]).split('/')
    if len(parts) < 3 or len(parts) % 2 != 1 or any(not p for p in parts):
        raise Unavailable('malformed ARM child identity')
    if resource_type and '/'.join(parts[:2]).casefold() != resource_type.casefold() or resource_type and len(parts) != 3:
        raise Unavailable('unexpected ARM resource type')
    return rid.casefold()


def _duration(value):
    match = re.fullmatch(r'P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?', _text(value))
    if not match:
        raise Unavailable('unsupported alert duration')
    seconds = sum(int(v or 0) * factor for v, factor in zip(match.groups(), (86400, 3600, 60, 1)))
    if seconds <= 0:
        raise Unavailable('alert duration must be positive')
    return seconds


def _one(index, kind, **kwargs):
    rows = _rows(index, kind, **kwargs)
    if len(rows) != 1:
        raise Unavailable('singleton evidence missing or ambiguous: ' + kind)
    return rows[0]


def _coverage(row, name):
    if get(row, '_coverage.' + name + '.status', str) not in ('collected', 'empty'):
        raise Unavailable('nested evidence incomplete: ' + name)


def _aggregate(failures, uncertainties, **evidence):
    if failures:
        return result(True, violations=failures[:20], violation_count=len(failures),
                      uncertain_count=len(uncertainties), **evidence)
    if uncertainties:
        return unknown('one or more applicable observations unresolved',
                       uncertainties=uncertainties[:20], **evidence)
    return result(False, **evidence)


def _literal(row, name):
    guard(row)
    translated = {'value': row[name]} if name in row else {}
    coverage = row.get('_coverage', {})
    if name in coverage:
        translated['_coverage'] = {'value': coverage[name]}
    return get(translated, 'value')


