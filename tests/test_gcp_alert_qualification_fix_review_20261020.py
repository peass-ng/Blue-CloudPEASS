"""Native counter-alert qualification after the 2026-10-20 logging review.

The association-only helper contract is separately tested by its existing suite.
All positive event cases here have native metric schemas and required threshold
fields; no fixture changes turn a counterexample into a positive.
"""
from copy import deepcopy

import pytest

from peaso.engine import evaluate_snapshot
from tests.test_gcp_logging_audit_batch_review_20261020 import (
    FILTERS, SCOPE, MTYPE, CHANNEL, native_collect, finding,
    forbid_network_and_credentials,
)

KMS = 'gcp_kms_key_destroy_alert'
RESOURCE_TYPES = {'audit_configuration_changes': 'project', 'bucket_iam_changes': 'gcs_bucket',
    'custom_role_changes': 'iam_role', 'custom_role_changes_with_undelete': 'iam_role',
    'firewall_rule_changes': 'gce_firewall_rule', 'network_changes': 'gce_network',
    'network_changes_beta_methods': 'gce_network', 'project_ownership_changes': 'project',
    'route_changes': 'gce_route', 'sql_instance_configuration_changes': 'cloudsql_database'}
CASES = [('gcp.claude2.logging.metric_alert_' + slug, FILTERS[slug], RESOURCE_TYPES[slug])
         for slug in RESOURCE_TYPES if slug != 'network_changes_beta_methods']
CASES += [('gcp.ports.logging_metric_alert_' + query + '_scoped', FILTERS[slug], RESOURCE_TYPES[slug])
    for query, slug in [('audit_configuration_changes', 'audit_configuration_changes'),
        ('custom_role_changes', 'custom_role_changes'),
        ('custom_role_changes_with_iam_admin_undelete_role', 'custom_role_changes_with_undelete'),
        ('firewall_rule_changes', 'firewall_rule_changes'), ('network_changes', 'network_changes_beta_methods'),
        ('network_route_changes', 'route_changes'), ('project_ownership_assignment', 'project_ownership_changes'),
        ('sql_instance_configuration_changes', 'sql_instance_configuration_changes'),
        ('storage_iam_permission_changes', 'bucket_iam_changes')]]
CASES += [(KMS, 'protoPayload.methodName="DestroyCryptoKeyVersion"', 'cloudkms_cryptokeyversion')]


def capture(cid, event_filter, resource_type, scenario='good'):
    metric = {'name': 'review', 'filter': event_filter, 'metricDescriptor': {
        'type': MTYPE, 'metricKind': 'DELTA', 'valueType': 'INT64'}}
    threshold = {'filter': 'metric.type="' + MTYPE + '" AND resource.type="' + resource_type + '"',
                 'comparison': 'COMPARISON_GT', 'thresholdValue': 0, 'duration': '0s'}
    policy = {'name': SCOPE + '/alertPolicies/1', 'enabled': True, 'combiner': 'OR',
        'notificationChannels': [CHANNEL], 'conditions': [{'conditionThreshold': threshold}]}
    channel = {'name': CHANNEL, 'type': 'email', 'enabled': True, 'verificationStatus': 'VERIFIED'}
    channels = [channel]
    denied, partial = (), ()
    if scenario == 'impossible_negative': threshold.update(comparison='COMPARISON_LT', thresholdValue=-1)
    elif scenario == 'sustained': threshold['duration'] = '600s'
    elif scenario == 'missing_comparison': threshold.pop('comparison')
    elif scenario == 'missing_duration': threshold.pop('duration')
    elif scenario == 'omitted_zero': threshold.pop('thresholdValue')
    elif scenario == 'fractional_zero': threshold['thresholdValue'] = 0.5
    elif scenario == 'unrelated_and':
        policy['combiner'] = 'AND'
        policy['conditions'].append({'conditionThreshold': {**threshold, 'filter': threshold['filter'].replace('/user/review', '/user/unrelated')}})
    elif scenario == 'independent_or':
        policy['conditions'].append({'conditionThreshold': {**threshold, 'filter': threshold['filter'].replace('/user/review', '/user/unrelated')}})
    elif scenario == 'negated_metric': metric['filter'] = 'NOT (' + event_filter + ')'
    elif scenario == 'actor_narrowing': metric['filter'] = '(' + event_filter + ') AND protoPayload.authenticationInfo.principalEmail="admin@example.com"'
    elif scenario == 'invalid': policy['validity'] = {'code': 3, 'message': 'Invalid condition'}
    elif scenario == 'foreign_project': threshold['filter'] += ' AND resource.labels.project_id="other"'
    elif scenario == 'foreign_policy': policy['name'] = 'projects/other/alertPolicies/1'
    elif scenario == 'wrong_resource': threshold['filter'] = threshold['filter'].replace(resource_type, 'aws_ec2_instance')
    elif scenario == 'missing_resource': threshold['filter'] = 'metric.type="' + MTYPE + '"'
    elif scenario == 'series_narrowing': threshold['filter'] += ' AND resource.labels.location="only-one"'
    elif scenario == 'wrong_kind': metric['metricDescriptor']['metricKind'] = 'GAUGE'
    elif scenario == 'wrong_value_type': metric['metricDescriptor']['valueType'] = 'DISTRIBUTION'
    elif scenario == 'wrong_descriptor': metric['metricDescriptor']['type'] = 'custom.googleapis.com/unrelated'
    elif scenario == 'missing_kind': metric['metricDescriptor'].pop('metricKind')
    elif scenario == 'denied_field': threshold['_coverage'] = {'comparison': {'status': 'denied'}}
    elif scenario == 'disabled': policy['enabled'] = False
    elif scenario == 'missing_enabled': policy.pop('enabled')
    elif scenario == 'denied': denied = ('monitoring_alert_policy',)
    elif scenario == 'partial': partial = ('monitoring_alert_policy',)
    elif scenario == 'aligned': threshold['aggregations'] = [{'alignmentPeriod': '60s', 'perSeriesAligner': 'ALIGN_DELTA'}]
    elif scenario == 'grouped': threshold['aggregations'] = [{'alignmentPeriod': '60s', 'perSeriesAligner': 'ALIGN_SUM', 'groupByFields': ['resource.label.project_id']}]
    elif scenario == 'trigger_many': threshold['trigger'] = {'count': 2}
    elif scenario == 'unverified': channel['verificationStatus'] = 'UNVERIFIED'
    elif scenario == 'verified_sibling':
        channel['verificationStatus'] = 'UNVERIFIED'
        channels.append({**channel, 'name': SCOPE + '/notificationChannels/2', 'verificationStatus': 'VERIFIED'})
        policy['notificationChannels'].append(channels[1]['name'])
    elif scenario == 'unreadable_sibling':
        channels.append({**channel, 'name': SCOPE + '/notificationChannels/2', '_coverage': {'enabled': {'status': 'denied'}}})
        policy['notificationChannels'].append(channels[1]['name'])
    elif scenario == 'duplicate_channel': channels.append({**channel, 'enabled': False})
    elif scenario == 'audit_category_narrowing':
        metric['filter'] = '(' + event_filter + ') AND protoPayload.serviceData.policyDelta.auditConfigDeltas.logType="DATA_READ"'
    elif scenario == 'owner_member_narrowing':
        metric['filter'] = '(' + event_filter + ') AND protoPayload.serviceData.policyDelta.bindingDeltas.member="user:new-owner@example.com"'
    elif scenario == 'fictional_kms':
        metric['filter'] = ('protoPayload.methodName="google.cloud.kms.v1.KeyManagementService.DisableCryptoKeyVersion" OR '
                            'protoPayload.methodName="google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion"')
    elif scenario == 'native_kms_resource': metric['filter'] = 'resource.type="cloudkms_cryptokeyversion" AND ' + event_filter
    payloads = {'logging_metric': [metric], 'monitoring_alert_policy': [policy], 'monitoring_notification_channel': channels}
    kinds = ['project', 'logging_metric', 'monitoring_alert_policy', 'monitoring_notification_channel', 'log_sink']
    if cid == KMS: kinds.append('alert_policy')
    native, _ = native_collect(kinds, payloads, denied=denied, partial=partial)
    return finding(native, cid)


@pytest.mark.parametrize('cid,event_filter,resource_type', CASES, ids=[x[0] for x in CASES])
@pytest.mark.parametrize('scenario', ['good', 'omitted_zero', 'fractional_zero', 'independent_or', 'aligned'])
def test_native_qualified_event_alert_positive_variants(cid, event_filter, resource_type, scenario):
    assert capture(cid, event_filter, resource_type, scenario)['status'] == 'PASS'


@pytest.mark.parametrize('cid,event_filter,resource_type', CASES, ids=[x[0] for x in CASES])
@pytest.mark.parametrize('scenario', ['impossible_negative', 'sustained', 'missing_comparison', 'missing_duration',
    'unrelated_and', 'negated_metric', 'actor_narrowing', 'invalid', 'foreign_project', 'foreign_policy',
    'wrong_resource', 'missing_resource', 'series_narrowing', 'wrong_kind', 'wrong_value_type',
    'wrong_descriptor', 'missing_kind', 'denied_field', 'missing_enabled', 'grouped', 'trigger_many'])
def test_native_unqualified_event_alert_never_passes(cid, event_filter, resource_type, scenario):
    row = capture(cid, event_filter, resource_type, scenario)
    assert row['status'] != 'PASS', row


@pytest.mark.parametrize('cid,event_filter,resource_type', CASES, ids=[x[0] for x in CASES])
@pytest.mark.parametrize('scenario,expected', [('disabled', 'FAIL'), ('denied', 'UNKNOWN'), ('partial', 'UNKNOWN')])
def test_native_event_alert_negative_and_incomplete_inventory(cid, event_filter, resource_type, scenario, expected):
    assert capture(cid, event_filter, resource_type, scenario)['status'] == expected


@pytest.mark.parametrize('cid,event_filter,resource_type', CASES[:9], ids=[x[0] for x in CASES[:9]])
@pytest.mark.parametrize('scenario,positive', [('unverified', False), ('verified_sibling', True),
                                             ('unreadable_sibling', True), ('duplicate_channel', False)])
def test_notification_channel_qualification_keeps_independent_positive(cid, event_filter, resource_type, scenario, positive):
    row = capture(cid, event_filter, resource_type, scenario)
    assert (row['status'] == 'PASS') is positive, row


@pytest.mark.parametrize('slug,scenario', [('audit_configuration_changes', 'audit_category_narrowing'),
                                         ('project_ownership_changes', 'owner_member_narrowing')])
def test_synthetic_audit_example_fields_are_not_universal(slug, scenario):
    cid, event_filter, resource_type = next(row for row in CASES if row[0] == 'gcp.claude2.logging.metric_alert_' + slug)
    assert capture(cid, event_filter, resource_type, scenario)['status'] != 'PASS'


@pytest.mark.parametrize('scenario,expected', [('native_kms_resource', 'PASS'), ('fictional_kms', 'UNKNOWN')])
def test_kms_uses_documented_destruction_operation(scenario, expected):
    assert capture(*CASES[-1], scenario)['status'] == expected


@pytest.mark.parametrize('kind', ['monitoring_alert_policy', 'logging_metric'])
@pytest.mark.parametrize('reverse', [False, True])
def test_native_conflicting_metric_or_policy_identity_cannot_pass(kind, reverse):
    cid, event_filter, resource_type = CASES[0]
    metric = {'name': 'review', 'filter': event_filter, 'metricDescriptor': {
        'type': MTYPE, 'metricKind': 'DELTA', 'valueType': 'INT64'}}
    policy = {'name': SCOPE + '/alertPolicies/1', 'enabled': True, 'notificationChannels': [CHANNEL],
              'conditions': [{'conditionThreshold': {'filter': 'metric.type="' + MTYPE + '" resource.type="project"',
                  'comparison': 'COMPARISON_GT', 'thresholdValue': 0, 'duration': '0s'}}]}
    conflicting = ({**policy, 'validity': {'code': 3, 'message': 'Invalid condition'}}
                   if kind == 'monitoring_alert_policy' else {**metric, 'filter': event_filter + ' AND severity=ERROR'})
    rows = [policy if kind == 'monitoring_alert_policy' else metric, conflicting]
    if reverse: rows.reverse()
    native, _ = native_collect(['project', 'logging_metric', 'monitoring_alert_policy', 'monitoring_notification_channel', 'log_sink'],
        {'logging_metric': rows if kind == 'logging_metric' else [metric],
         'monitoring_alert_policy': rows if kind == 'monitoring_alert_policy' else [policy],
         'monitoring_notification_channel': [{'name': CHANNEL, 'enabled': True, 'type': 'email', 'verificationStatus': 'VERIFIED'}]})
    assert finding(native, cid)['status'] != 'PASS'


@pytest.mark.parametrize('kind', ['monitoring_notification_channel', 'monitoring_alert_policy', 'logging_metric'])
@pytest.mark.parametrize('mode', ['pages', 'jobs'])
@pytest.mark.parametrize('conflicting', [False, True])
@pytest.mark.parametrize('reverse', [False, True])
def test_producer_alert_identity_merge_preserves_conflict_and_identical_receipts(kind, mode, conflicting, reverse):
    from peaso.collectors import gcp
    from tests.test_peaso_collectors_gcp import FixtureTransport, connector
    name = SCOPE + {'monitoring_notification_channel': '/notificationChannels/1',
                    'monitoring_alert_policy': '/alertPolicies/1', 'logging_metric': '/metrics/review'}[kind]
    field = 'filter' if kind == 'logging_metric' else 'enabled'
    left = {'name': name, field: 'protoPayload.methodName="SetIamPolicy"' if field == 'filter' else True}
    right = {**left, field: 'severity=ERROR' if field == 'filter' else False} if conflicting else deepcopy(left)
    rows = [left, right]
    if reverse: rows.reverse()
    def blocked(request): raise AssertionError('Merge proof performs no HTTP')
    collector = gcp.GCPCollector(connector([kind]), transport=FixtureTransport(blocked))
    if mode == 'pages':
        collected = collector.envelope(kind, SCOPE, 'logging', lambda: iter([([rows[0]], 'receipt-1'), ([rows[1]], 'receipt-2')]))
    else:
        collector.add(kind, SCOPE, 'logging', lambda: iter([([rows[0]], 'receipt-1')]))
        collected = collector.add(kind, SCOPE, 'logging', lambda: iter([([rows[1]], 'receipt-2')]))
    assert collected['source_requests'] == ['receipt-1', 'receipt-2']
    assert collected['coverage_status'] == ('partial' if conflicting else 'collected')
    if conflicting:
        assert collected['error']['code'] == 'conflicting_' + kind + '_identity'
    else:
        assert collected['items'][0]['_provenance']['source_requests'] == ['receipt-1', 'receipt-2']
