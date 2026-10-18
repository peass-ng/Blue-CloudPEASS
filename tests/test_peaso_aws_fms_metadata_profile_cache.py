"""FMS rule-order metadata is redacted before its isolated request Future."""
import pytest

from peaso.collectors import aws
from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT


def acl_response():
    visibility = {'SampledRequestsEnabled': False, 'CloudWatchMetricsEnabled': True,
                  'MetricName': 'PRIVATE_METRIC_SENTINEL'}
    return {'WebACL': {
        'Name': 'managed-acl', 'Id': '11111111-1111-1111-1111-111111111111',
        'ARN': f'arn:aws:wafv2:us-east-1:{ACCOUNT}:regional/webacl/managed-acl/11111111-1111-1111-1111-111111111111',
        'DefaultAction': {'Allow': {}}, 'VisibilityConfig': visibility,
        'Description': 'PRIVATE_DESCRIPTION_SENTINEL', 'ManagedByFirewallManager': True,
        'CustomResponseBodies': {'private': {'ContentType': 'TEXT_PLAIN',
                                           'Content': 'PRIVATE_BODY_SENTINEL'}},
        'PreProcessFirewallManagerRuleGroups': [{
            'Name': 'managed-first', 'Priority': 0,
            'FirewallManagerStatement': {'ManagedRuleGroupStatement': {
                'VendorName': 'AWS', 'Name': 'AWSManagedRulesCommonRuleSet'}},
            'OverrideAction': {'None': {}}, 'VisibilityConfig': visibility}],
        'PostProcessFirewallManagerRuleGroups': []}}


def test_fms_future_keeps_rule_order_and_drops_payloads_without_changing_legacy(sdk):
    from peaso.collectors import aws_fms_rule_metadata_native as native
    session, add = sdk
    client = add('wafv2')
    raw = acl_response()
    params = {'Name': raw['WebACL']['Name'], 'Id': raw['WebACL']['Id'], 'Scope': 'REGIONAL'}
    client.add_response('get_web_acl', raw, params)
    client.add_response('get_web_acl', raw, params)
    reader = aws.Requests({})
    projected = reader.call(session, 'wafv2', 'us-east-1', 'get_web_acl',
                            _metadata_profile=native.PROFILE, **params)
    again = reader.call(session, 'wafv2', 'us-east-1', 'get_web_acl',
                        _metadata_profile=native.PROFILE, **params)
    assert projected == again
    assert 'managed-first' in str(projected) and "'Priority': 0" in str(projected)
    assert 'PRIVATE_' not in str(projected)
    assert reader.call(session, 'wafv2', 'us-east-1', 'get_web_acl', **params) == raw
    assert reader.calls == 2 and reader.cache_hits == 1
    assert {len(key) for key in reader._cache} == {5, 6}
    futures = [future for key, future in reader._cache.items() if len(key) == 6]
    assert len(futures) == 1 and 'PRIVATE_' not in str(futures[0].result())
    client.assert_no_pending_responses()


def test_fms_profile_rejects_unrelated_read_before_client_creation(monkeypatch):
    from peaso.collectors import aws_fms_rule_metadata_native as native
    reader = aws.Requests({})
    def forbidden(*args):
        raise AssertionError('operation must be bound before creating client')
    monkeypatch.setattr(reader, 'client', forbidden)
    with pytest.raises(aws.ReadFailure) as error:
        reader.call(object(), 'sts', 'us-east-1', 'get_caller_identity',
                    _metadata_profile=native.PROFILE)
    assert error.value.code == 'metadata_profile_operation_not_allowed'
    assert reader.calls == 0 and reader._cache == {}


@pytest.mark.parametrize('response', [None, {}, {'WebACL': {'Description': 'PRIVATE_MALFORMED_SENTINEL'}}])
def test_fms_malformed_response_is_not_retained_in_cached_exception(monkeypatch, response):
    from peaso.collectors import aws_fms_rule_metadata_native as native
    class Client:
        def get_web_acl(self, **params):
            return response
    reader = aws.Requests({'retry_attempts': 1})
    monkeypatch.setattr(reader, 'client', lambda *args: Client())
    with pytest.raises(aws.ReadFailure) as error:
        reader.call(object(), 'wafv2', 'us-east-1', 'get_web_acl',
                    _metadata_profile=native.PROFILE, Name='managed-acl',
                    Id='11111111-1111-1111-1111-111111111111', Scope='REGIONAL')
    assert error.value.status == 'malformed' and reader.calls == 1
    failure = next(iter(reader._cache.values())).exception()
    assert failure.__traceback__ is None and failure.__context__ is None and failure.__cause__ is None
    assert 'PRIVATE_' not in repr(vars(failure))
