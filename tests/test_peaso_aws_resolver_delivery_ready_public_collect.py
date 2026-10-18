"""Native delivery-readiness status is separate from configured SIEM routing."""
from types import SimpleNamespace
import pytest

from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live
from peaso.engine import plan_collection, evaluate_snapshot
from peaso.checks.aws_resolver_delivery_ready import CHECK_ID
from peaso.server.validation import validate_connector

CONTROL = CHECK_ID
CONFIG = 'rqlc-0123456789abcdef0'
ARN = f'arn:aws:route53resolver:{REGION}:{ACCOUNT}:resolver-query-log-config/{CONFIG}'


@pytest.mark.parametrize('mode,expected', [('CREATED', 'PASS'), ('FAILED', 'FAIL'), ('CREATING', 'UNKNOWN'),
    ('DELETING', 'UNKNOWN'), ('denied', 'DENIED'), ('partial', 'UNKNOWN'), ('empty', 'EMPTY')])
def test_public_native_resolver_readiness(monkeypatch, sdk, mode, expected):
    session, add = sdk; sts, resolver = add('sts'), add('route53resolver')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    if mode == 'denied':
        resolver.add_client_error('list_resolver_query_log_configs', 'AccessDeniedException', expected_params={})
    else:
        row = {'Id': CONFIG, 'Arn': ARN, 'Name': 'queries', 'OwnerId': ACCOUNT,
            'DestinationArn': f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:queries',
            'Status': 'CREATED' if mode == 'partial' else mode, 'ShareStatus': 'NOT_SHARED'}
        resolver.add_response('list_resolver_query_log_configs', {
            'ResolverQueryLogConfigs': [] if mode == 'empty' else [row],
            **({'NextToken': 'next'} if mode == 'partial' else {})}, {})
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1}
    if mode == 'partial': options['max_pages'] = 1
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    required = plan_collection({'connector': connector, 'checks': [CONTROL]})
    assert required == ['resolver_query_log_config']
    snapshot = collect_live(connector, required)
    findings = evaluate_snapshot(snapshot, checks=[CONTROL])['findings']
    if mode == 'partial':
        assert findings and {f['status'] for f in findings} == {'UNKNOWN'}
    else:
        assert len(findings) == 1 and findings[0]['status'] == expected
    if mode in ('CREATED', 'FAILED'):
        assert findings[0]['evidence']['native_status'] == mode
        assert findings[0]['evidence']['semantics'] == 'Native Resolver configuration status'
    if mode == 'partial':
        assert next(c for c in snapshot['collections'] if c['type'] == 'resolver_query_log_config')['status'] == 'partial'
    sts.assert_no_pending_responses(); resolver.assert_no_pending_responses()
