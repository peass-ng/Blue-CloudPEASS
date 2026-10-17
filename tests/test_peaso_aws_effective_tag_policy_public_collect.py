"""Real SDK/Requests/public path; no network or raw policy retention."""
import json
from types import SimpleNamespace
import pytest

from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from tests.test_peaso_aws_effective_tag_policy_contract import response, MARKER
from peaso.checks.aws_effective_tag_policy import CHECK_ID as CHECK
from peaso.collectors import aws, collect_live, aws_effective_tag_policy_native as native
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector


PARAMS = {'PolicyType': 'TAG_POLICY', 'TargetId': ACCOUNT}


def queue(stub, mode):
    if mode in ('absent', 'denied', 'not_in_use', 'denied_not_in_use_message'):
        code = {'absent': native.NOT_FOUND, 'denied': 'AccessDeniedException',
                'not_in_use': 'AWSOrganizationsNotInUseException',
                'denied_not_in_use_message': 'AccessDeniedException'}[mode]
        stub.add_client_error('describe_effective_policy', code,
            service_message='AWSOrganizationsNotInUseException' if mode == 'denied_not_in_use_message' else 'fixture',
            expected_params=PARAMS)
        return
    raw = response()
    doc = json.loads(raw['EffectivePolicy']['PolicyContent'])
    if mode == 'mismatch': doc['tags']['environment']['tag_value'] = [MARKER]
    elif mode == 'unrestricted': doc['tags']['environment'].pop('tag_value')
    elif mode == 'unsupported': doc['tags']['environment']['tag_value'] = ['Prod*']
    elif mode == 'unrelated_unsupported': doc['tags']['secret'] = {'tag_key': 'Secret', 'tag_value': [MARKER + '*']}
    raw['EffectivePolicy']['PolicyContent'] = json.dumps(doc)
    if mode == 'empty_body': raw = {}
    elif mode == 'invalid_json': raw['EffectivePolicy']['PolicyContent'] = '{'
    elif mode == 'foreign': raw['EffectivePolicy']['TargetId'] = '999999999999'
    elif mode == 'missing_timestamp': raw['EffectivePolicy'].pop('LastUpdatedTimestamp')
    stub.add_response('describe_effective_policy', raw, PARAMS)


@pytest.mark.parametrize('mode,expected', [('finite', 'PASS'), ('mismatch', 'FAIL'),
    ('unrestricted', 'FAIL'), ('unsupported', 'UNKNOWN'), ('unrelated_unsupported', 'PASS'),
    ('absent', 'FAIL'), ('denied', 'DENIED'), ('not_in_use', 'FAIL'),
    ('denied_not_in_use_message', 'DENIED'),
    ('empty_body', 'UNKNOWN'), ('foreign', 'UNKNOWN'), ('missing_timestamp', 'UNKNOWN')])
def test_normal_hosted_plan_sdk_collect_engine(monkeypatch, sdk, mode, expected):
    session, add = sdk; sts, org = add('sts'), add('organizations')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    queue(org, mode)
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16,
            'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1, 'compliance_parameters': {
        'approved_ec2_tag_values': {'Environment': ['Production']}}}
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    required = plan_collection({'connector': connector, 'checks': [CHECK]})
    assert set(required) == {native.KIND}
    snapshot = collect_live(connector, required)
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    assert findings and all(f['status'] == expected for f in findings)
    serialized = json.dumps({'snapshot': snapshot, 'findings': findings}, default=str)
    assert MARKER not in serialized and 'PolicyContent' not in serialized
    if mode == 'finite':
        assert 'resource tagging and enforcement unassessed' in findings[0]['evidence']['semantics']
    sts.assert_no_pending_responses(); org.assert_no_pending_responses()


def test_successful_shared_future_contains_only_digest_projection(sdk):
    session, add = sdk; org = add('organizations'); queue(org, 'mismatch')
    reader = aws.Requests({'service_concurrency': 1, 'retry_attempts': 1})
    first = native.collect(reader, session, REGION, ACCOUNT)
    second = native.collect(reader, session, REGION, ACCOUNT)
    assert first.status == second.status == 'collected' and first.items == second.items
    assert reader.calls == 1 and reader.cache_hits >= 1
    assert len(reader._cache) == 1
    for future in reader._cache.values():
        retained = future.result()
        serialized = json.dumps(retained, default=str)
        assert MARKER not in serialized and 'PolicyContent' not in serialized
        assert retained['_metadata_projection'] == native.PROJECTION
        assert retained['EffectivePolicy']['TagAssignments'][0]['ValueDigests'] == [
            native.value_digest(ACCOUNT, 'Environment', MARKER)]
    org.assert_no_pending_responses()


def test_failed_projection_future_has_no_raw_exception_frames(sdk):
    session, add = sdk; org = add('organizations'); queue(org, 'invalid_json')
    reader = aws.Requests({'service_concurrency': 1, 'retry_attempts': 1})
    read = native.collect(reader, session, REGION, ACCOUNT)
    assert read.status == 'malformed' and read.items == [] and reader.calls == 1
    failure = next(iter(reader._cache.values())).exception()
    assert isinstance(failure, aws.ReadFailure)
    assert failure.__traceback__ is None and failure.__context__ is None and failure.__cause__ is None
    assert 'PolicyContent' not in repr(vars(failure))
    org.assert_no_pending_responses()


def test_registered_default_fixture_is_executable():
    from peaso.checks.fixtures import CASES
    from peaso.checks import evaluate_check
    for case, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
        assert evaluate_check(CHECK, CASES[CHECK][case], CASES[CHECK][case + '_index'])[0] == expected
