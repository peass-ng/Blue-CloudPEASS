"""A reviewed metadata projection has its own cache; legacy callers stay stable."""
import pytest
from peaso.collectors import aws
from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT


@pytest.mark.parametrize('profile', ['unreviewed-profile', True, {'profile': 'unknown'}])
def test_unknown_metadata_profile_is_rejected_before_client_or_request(monkeypatch, profile):
    requests = aws.Requests({})
    def forbidden(*args):
        raise AssertionError('profile validation must happen before client creation')
    monkeypatch.setattr(requests, 'client', forbidden)
    with pytest.raises(aws.ReadFailure) as error:
        requests.call(object(), 'sts', 'us-east-1', 'get_caller_identity', _metadata_profile=profile)
    assert error.value.code == 'undeclared_metadata_profile'
    assert requests.calls == 0 and requests._cache == {}


def test_legacy_requests_keep_original_cache_key_and_single_flight(sdk):
    session, add = sdk
    sts = add('sts')
    response = {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}
    sts.add_response('get_caller_identity', response, {})
    requests = aws.Requests({})
    assert requests.call(session, 'sts', 'us-east-1', 'get_caller_identity') == response
    assert requests.call(session, 'sts', 'us-east-1', 'get_caller_identity') == response
    assert requests.calls == 1 and requests.cache_hits == 1
    assert len(requests._cache) == 1 and len(next(iter(requests._cache))) == 5
    sts.assert_no_pending_responses()


def guardrail_response():
    from datetime import datetime, timezone
    return {'name': 'PRIVATE_GUARDRAIL_MESSAGE_SENTINEL', 'guardrailId': 'abc123def456',
        'guardrailArn': f'arn:aws:bedrock:us-east-1:{ACCOUNT}:guardrail/abc123def456',
        'version': '1', 'status': 'READY', 'createdAt': datetime(2026, 10, 16, tzinfo=timezone.utc),
        'updatedAt': datetime(2026, 10, 16, tzinfo=timezone.utc),
        'blockedInputMessaging': 'PRIVATE_GUARDRAIL_MESSAGE_SENTINEL',
        'blockedOutputsMessaging': 'PRIVATE_GUARDRAIL_MESSAGE_SENTINEL'}


def test_profiled_future_is_redacted_and_reused_without_changing_legacy_schema(sdk):
    from peaso.collectors import aws_bedrock_reasoning_native as native
    session, add = sdk
    bedrock = add('bedrock')
    raw = guardrail_response()
    params = {'guardrailIdentifier': raw['guardrailArn'], 'guardrailVersion': '1'}
    bedrock.add_response('get_guardrail', raw, params)
    bedrock.add_response('get_guardrail', raw, params)
    reader = aws.Requests({})
    first = reader.call(session, 'bedrock', 'us-east-1', 'get_guardrail',
                        _metadata_profile=native.PROFILE, **params)
    second = reader.call(session, 'bedrock', 'us-east-1', 'get_guardrail',
                         _metadata_profile=native.PROFILE, **params)
    assert first == second and 'PRIVATE_GUARDRAIL_MESSAGE_SENTINEL' not in str(first)
    legacy = reader.call(session, 'bedrock', 'us-east-1', 'get_guardrail', **params)
    assert legacy == raw
    assert reader.calls == 2 and reader.cache_hits == 1
    assert {len(key) for key in reader._cache} == {5, 6}
    profiled = [future for key, future in reader._cache.items() if len(key) == 6]
    assert len(profiled) == 1
    assert 'PRIVATE_GUARDRAIL_MESSAGE_SENTINEL' not in str(profiled[0].result())
    bedrock.assert_no_pending_responses()


def test_reviewed_profile_cannot_be_applied_to_an_unrelated_operation(monkeypatch):
    from peaso.collectors import aws_bedrock_reasoning_native as native
    reader = aws.Requests({})
    def forbidden(*args):
        raise AssertionError('operation binding must be checked before creating a client')
    monkeypatch.setattr(reader, 'client', forbidden)
    with pytest.raises(aws.ReadFailure) as error:
        reader.call(object(), 'sts', 'us-east-1', 'get_caller_identity', _metadata_profile=native.PROFILE)
    assert error.value.code == 'metadata_profile_operation_not_allowed'
    assert reader.calls == 0 and reader._cache == {}


@pytest.mark.parametrize('response', [None, {}, {'name': 'PRIVATE_MALFORMED_PAYLOAD_SENTINEL'}])
def test_malformed_profile_response_never_survives_in_exception_frames(monkeypatch, response):
    from peaso.collectors import aws_bedrock_reasoning_native as native
    class Client:
        def get_guardrail(self, **params):
            return response
    reader = aws.Requests({'retry_attempts': 1})
    monkeypatch.setattr(reader, 'client', lambda *args: Client())
    with pytest.raises(aws.ReadFailure) as error:
        reader.call(object(), 'bedrock', 'us-east-1', 'get_guardrail',
                    _metadata_profile=native.PROFILE, guardrailIdentifier='abc123def456', guardrailVersion='1')
    assert error.value.status == 'malformed'
    assert reader.calls == 1
    failure = next(iter(reader._cache.values())).exception()
    assert isinstance(failure, aws.ReadFailure)
    assert failure.__traceback__ is None and failure.__context__ is None and failure.__cause__ is None
    assert 'PRIVATE_MALFORMED_PAYLOAD_SENTINEL' not in repr(vars(failure))
