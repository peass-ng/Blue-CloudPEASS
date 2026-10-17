"""Native log subscription alias preserves actual readonly collection status."""
from types import SimpleNamespace
import pytest

from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector

CONTROL = 'aws_security_logs_central_search'
NAME = 'security'
GROUP = f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{NAME}'
STREAM = f'arn:aws:firehose:{REGION}:{ACCOUNT}:deliverystream/central'


@pytest.mark.parametrize('mode,expected', [('active', 'PASS'), ('empty_filters', 'FAIL'),
    ('group_denied', 'DENIED'), ('filter_denied', 'DENIED'), ('stream_denied', 'DENIED'),
    ('stream_detail_denied', 'UNKNOWN'), ('group_partial', 'UNKNOWN'), ('filter_partial', 'UNKNOWN')])
def test_hosted_native_logs_and_firehose_configuration(monkeypatch, sdk, mode, expected):
    session, add = sdk; sts, logs, firehose = add('sts'), add('logs'), add('firehose')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    if mode == 'group_denied':
        logs.add_client_error('describe_log_groups', 'AccessDeniedException', expected_params={})
    else:
        logs.add_response('describe_log_groups', {'logGroups': [{'logGroupName': NAME, 'arn': GROUP + ':*', 'logGroupArn': GROUP}],
            **({'nextToken': 'next-group'} if mode == 'group_partial' else {})}, {})
        if mode == 'filter_denied':
            logs.add_client_error('describe_subscription_filters', 'AccessDeniedException', expected_params={'logGroupName': NAME})
        else:
            logs.add_response('describe_subscription_filters', {
                'subscriptionFilters': [] if mode == 'empty_filters' else [{'filterName': 'to-central', 'logGroupName': NAME,
                    'destinationArn': STREAM}], **({'nextToken': 'next-filter'} if mode == 'filter_partial' else {})}, {'logGroupName': NAME})
    if mode == 'stream_denied':
        firehose.add_client_error('list_delivery_streams', 'AccessDeniedException', expected_params={'Limit': 100})
    else:
        firehose.add_response('list_delivery_streams', {'DeliveryStreamNames': ['central'], 'HasMoreDeliveryStreams': False}, {'Limit': 100})
        if mode == 'stream_detail_denied':
            firehose.add_client_error('describe_delivery_stream', 'AccessDeniedException', expected_params={'DeliveryStreamName': 'central'})
        else:
            firehose.add_response('describe_delivery_stream', {'DeliveryStreamDescription': {
                'DeliveryStreamName': 'central', 'DeliveryStreamARN': STREAM, 'DeliveryStreamStatus': 'ACTIVE',
                'DeliveryStreamType': 'DirectPut', 'VersionId': '1', 'HasMoreDestinations': False,
                'Destinations': [{'DestinationId': 'destinationId-0001'}]}}, {'DeliveryStreamName': 'central'})
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1, 'compliance_parameters': {
        'security_log_group_names': [NAME], 'approved_central_delivery_stream_arn': STREAM}}
    if mode in ('group_partial', 'filter_partial'): options['max_pages'] = 1
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CONTROL]})
    assert set(requirements) == {'cloudwatch_log_group', 'cloudwatch_subscription_filter', 'firehose_delivery_stream'}
    snapshot = collect_live(connector, requirements)
    alias = next(c for c in snapshot['collections'] if c['type'] == 'cloudwatch_subscription_filter')
    source = next(c for c in snapshot['collections'] if c['type'] == 'log_subscription_filter')
    assert alias['source_inventory'] == 'log_subscription_filter' and alias['status'] == source['status']
    assert all(row['collection_status'] == source['status'] for row in alias['items'])
    findings = evaluate_snapshot(snapshot, checks=[CONTROL])['findings']
    assert next(f['status'] for f in findings if f['check_id'] == CONTROL) == expected
    if mode == 'active':
        assert findings[0]['evidence']['semantics'] == 'Firehose subscription configuration only; search usability unverified'
    sts.assert_no_pending_responses(); logs.assert_no_pending_responses(); firehose.assert_no_pending_responses()
