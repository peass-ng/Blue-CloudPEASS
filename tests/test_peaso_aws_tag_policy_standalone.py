"""Only exact native standalone absence certifies zero attached tag policies."""
from types import SimpleNamespace
import pytest
from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live, aws_organizations_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector

CONTROL = 'aws_cis_ec2_tag_policy'
ABSENT = 'AWSOrganizationsNotInUseException'


@pytest.mark.parametrize('mode,expected', [('standalone', 'FAIL'), ('denied', 'DENIED'),
    ('service', 'UNKNOWN'), ('timeout', 'UNKNOWN'), ('message_only', 'UNKNOWN'),
    ('similar_code', 'UNKNOWN'), ('empty_body', 'UNKNOWN'), ('malformed_identity', 'UNKNOWN')])
def test_hosted_sdk_typed_absence_and_read_failures(monkeypatch, sdk, mode, expected):
    session, add = sdk; sts, org = add('sts'), add('organizations')
    calls, original_call = [], aws.Requests.call
    def observed_call(self, session, service, region, operation, **arguments):
        calls.append((service, operation))
        return original_call(self, session, service, region, operation, **arguments)
    monkeypatch.setattr(aws.Requests, 'call', observed_call)
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    if mode == 'empty_body': org.add_response('describe_organization', {}, {})
    elif mode == 'malformed_identity':
        org.add_response('describe_organization', {'Organization': {'Id': 'o-invalid', 'MasterAccountId': ACCOUNT}}, {})
    else:
        code = {'standalone': ABSENT, 'denied': 'AccessDeniedException', 'service': 'ServiceException',
            'timeout': 'RequestTimeout', 'message_only': 'UnrecognizedError',
            'similar_code': ABSENT + 'Similar'}[mode]
        org.add_client_error('describe_organization', code,
            service_message=ABSENT if mode in ('message_only', 'denied') else 'not retained', expected_params={})
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1,
        'compliance_parameters': {'approved_ec2_tag_values': {'Environment': ['Production']}}}
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    required = plan_collection({'connector': connector, 'checks': [CONTROL]})
    assert required == ['organization_tag_policy']
    snapshot = collect_live(connector, required)
    inventory = next(c for c in snapshot['collections'] if c['type'] == 'organization_tag_policy')
    assert inventory['items'] == []
    if mode == 'standalone':
        assert inventory['status'] == 'empty' and inventory['error']['code'] == ABSENT
        assert snapshot['metadata']['calls'] == 2
    else: assert inventory['status'] not in ('collected', 'empty')
    if mode == 'service': assert inventory['error']['code'] == 'ServiceException'
    findings = evaluate_snapshot(snapshot, checks=[CONTROL])['findings']
    assert findings and all(f['status'] == expected for f in findings)
    assert calls == [('sts', 'get_caller_identity'), ('organizations', 'describe_organization')]
    # Observe request dispatch as well as SDK EOF: an unexpected read must not
    # disappear into the collector's error handling after Stubber rejects it.
    sts.assert_no_pending_responses(); org.assert_no_pending_responses()


@pytest.mark.parametrize('fetcher', [native.effective_scp, native.account_identities])
def test_other_organization_consumers_keep_unavailable_semantics(sdk, fetcher):
    session, add = sdk; org = add('organizations')
    org.add_client_error('describe_organization', ABSENT, expected_params={})
    reader = aws.Requests({'service_concurrency': 1, 'retry_attempts': 1})
    read = fetcher(reader, session, REGION, ACCOUNT)
    assert read.items == [] and read.status not in ('collected', 'empty')
    assert read.error['code'] == ABSENT and reader.calls == 1
    org.assert_no_pending_responses()
