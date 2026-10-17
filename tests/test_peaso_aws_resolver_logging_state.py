"""An ACTIVE association cannot hide a native FAILED query-log configuration."""
import pytest

from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot
from peaso.checks.aws_resolver_delivery_ready import CHECK_ID
from tests.test_peaso_aws_bulk_inventory import sdk

ACCOUNT = '123456789012'
SCOPE = ACCOUNT + '/us-east-1'
GROUP = 'arn:aws:logs:us-east-1:' + ACCOUNT + ':log-group:resolver'
FORWARDER = 'arn:aws:firehose:us-east-1:' + ACCOUNT + ':deliverystream/security'
CHECK = CHECK_ID


@pytest.mark.parametrize('state,expected', [('CREATED', 'PASS'), ('FAILED', 'FAIL'),
                                         ('CREATING', 'UNKNOWN'), ('DELETING', 'UNKNOWN'),
                                         (None, 'UNKNOWN'), ('ACTIVE', 'UNKNOWN')])
def test_native_resolver_configuration_must_be_ready_to_forward(state, expected):
    config = {'Id': 'rqlc-config', 'DestinationArn': GROUP,
              'Arn': 'arn:aws:route53resolver:us-east-1:' + ACCOUNT + ':resolver-query-log-config/rqlc-config'}
    if state is not None: config['Status'] = state
    rows = {'vpc': [{'VpcId': 'vpc-123'}],
            'resolver_query_log_config': [config],
            'resolver_query_log_config_association': [{'Id': 'rqlca-association', 'ResourceId': 'vpc-123',
                                                       'Status': 'ACTIVE', 'ResolverQueryLogConfigId': config['Id']}],
            'resolver_log_subscription': [{'LogGroupArn': GROUP, 'DestinationArn': FORWARDER}]}
    snapshot = make_snapshot('aws', [SCOPE], [
        {'type': kind, 'scope': SCOPE, 'status': 'collected', 'items': items}
        for kind, items in rows.items()
    ], metadata={'parameters': {'approved_siem_forwarder_arns': [FORWARDER]}})
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    assert len(findings) == 1
    assert findings[0]['status'] == expected


@pytest.mark.parametrize('state,expected', [('CREATED', 'PASS'), ('FAILED', 'FAIL')])
def test_real_sdk_native_inventory_to_delivery_readiness_engine(sdk, state, expected):
    from peaso.collectors import aws, aws_bulk_inventory
    session, add = sdk
    stub = add('route53resolver')
    row = {'Id': 'rqlc-config', 'Arn': 'arn:aws:route53resolver:us-east-1:' + ACCOUNT + ':resolver-query-log-config/rqlc-config',
           'DestinationArn': GROUP, 'Status': state}
    stub.add_response('list_resolver_query_log_configs', {'ResolverQueryLogConfigs': [row]}, {})
    requests = aws.Requests({})
    read = aws_bulk_inventory.FETCHERS['resolver_query_log_config'](requests, session, 'us-east-1', ACCOUNT)
    assert read.status == 'collected'
    snapshot = make_snapshot('aws', [SCOPE], [{'type': 'resolver_query_log_config', 'scope': SCOPE,
                                             'status': read.status, 'items': read.items}])
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    assert len(findings) == 1 and findings[0]['status'] == expected
    assert requests.calls == 1
    stub.assert_no_pending_responses()


def test_same_native_capture_distinguishes_configured_route_from_failed_delivery(monkeypatch, sdk):
    from tests import test_peaso_aws_resolver_logs_public_collect as public_flow
    original = public_flow.evaluate_snapshot
    def evaluate_both(snapshot, *, checks):
        report = original(snapshot, checks=[public_flow.CONTROL, CHECK])
        states = {finding['check_id']: finding['status'] for finding in report['findings']}
        assert states[public_flow.CONTROL] == 'PASS'
        assert states[CHECK] == 'FAIL'
        return report
    monkeypatch.setattr(public_flow, 'evaluate_snapshot', evaluate_both)
    public_flow.test_normal_native_resolver_forwarding(monkeypatch, sdk, 'config_failed', 'PASS')
