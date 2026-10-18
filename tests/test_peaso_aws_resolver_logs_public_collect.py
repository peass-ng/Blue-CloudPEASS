"""Prepared native public Resolver QA; no ConfigStatus contract amendment."""
from types import SimpleNamespace
import pytest
from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live
from tests.archived_check_contract import plan_collection, evaluate_snapshot
from peaso.server.validation import validate_connector

CONTROL = 'aws_route53resolver_query_logs_forwarded'
VPC = 'vpc-0123456789abcdef0'
CONFIG = 'rqlc-0123456789abcdef0'
ASSOCIATION = 'rqlca-0123456789abcdef0'
GROUP = f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:resolver'
FORWARDER = f'arn:aws:firehose:{REGION}:{ACCOUNT}:deliverystream/siem'

@pytest.mark.parametrize('mode,expected', [('active', 'PASS'), ('config_failed', 'PASS'), ('empty_filters', 'FAIL'), ('no_association', 'FAIL'),
    ('filter_denied', 'DENIED'), ('config_denied', 'DENIED'), ('association_partial', 'UNKNOWN')])
def test_normal_native_resolver_forwarding(monkeypatch, sdk, mode, expected):
    session, add = sdk
    sts, ec2, resolver, logs = add('sts'), add('ec2'), add('route53resolver'), add('logs')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    ec2.add_response('describe_vpcs', {'Vpcs': [{'VpcId': VPC, 'State': 'available', 'CidrBlock': '10.0.0.0/16', 'IsDefault': False}]}, {})
    # Association/config jobs share a service client and run in sorted kind order.
    association = {'Id': ASSOCIATION,
        'ResolverQueryLogConfigId': CONFIG, 'ResourceId': VPC, 'Status': 'ACTIVE'}
    if mode == 'config_denied':
        resolver.add_client_error('list_resolver_query_log_configs', 'AccessDeniedException', expected_params={})
    else:
        resolver.add_response('list_resolver_query_log_configs', {'ResolverQueryLogConfigs': [{'Id': CONFIG,
            'Arn': f'arn:aws:route53resolver:{REGION}:{ACCOUNT}:resolver-query-log-config/{CONFIG}', 'Name': 'queries',
            'OwnerId': ACCOUNT, 'DestinationArn': GROUP, 'Status': 'FAILED' if mode == 'config_failed' else 'CREATED', 'ShareStatus': 'NOT_SHARED'}]}, {})
    resolver.add_response('list_resolver_query_log_config_associations', {'ResolverQueryLogConfigAssociations': [] if mode == 'no_association' else [association],
        **({'NextToken': 'next'} if mode == 'association_partial' else {})}, {})
    logs.add_response('describe_log_groups', {'logGroups': [{'logGroupName': 'resolver', 'arn': GROUP + ':*', 'logGroupArn': GROUP}]}, {})
    if mode == 'filter_denied':
        logs.add_client_error('describe_subscription_filters', 'AccessDeniedException', expected_params={'logGroupName': 'resolver'})
    else:
        logs.add_response('describe_subscription_filters', {'subscriptionFilters': [] if mode == 'empty_filters' else [
            {'filterName': 'to-siem', 'logGroupName': 'resolver', 'destinationArn': FORWARDER}]}, {'logGroupName': 'resolver'})
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1, 'compliance_parameters': {'approved_siem_forwarder_arns': [FORWARDER]}}
    if mode == 'association_partial': options['max_pages'] = 1
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CONTROL]})
    assert set(requirements) == {'vpc', 'resolver_query_log_config_association', 'resolver_query_log_config', 'resolver_log_subscription'}
    snapshot = collect_live(connector, requirements)
    result = next(f for f in evaluate_snapshot(snapshot, checks=[CONTROL])['findings'] if f['check_id'] == CONTROL)
    assert result['status'] == expected
    sts.assert_no_pending_responses(); ec2.assert_no_pending_responses(); resolver.assert_no_pending_responses(); logs.assert_no_pending_responses()
