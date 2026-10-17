"""Optional native Organizations ARNs must agree with org/owner/partition."""
from types import SimpleNamespace
import pytest
from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from tests.aws_tag_policy_fixture import collect_policy
from tests.test_peaso_aws_tag_policy_locked_assignment import MASTER, ORG, CONTROL
from peaso.collectors import aws, collect_live, aws_organizations_native as native
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector

ORG_ARN = f'arn:aws:organizations::{MASTER}:organization/{ORG}'
MASTER_ARN = f'arn:aws:organizations::{MASTER}:account/{ORG}/{MASTER}'


def organization():
    return {'Id': ORG, 'MasterAccountId': MASTER, 'Arn': ORG_ARN,
            'MasterAccountArn': MASTER_ARN, 'FeatureSet': 'ALL'}


@pytest.mark.parametrize('mode', ['missing_optional', 'correct', 'org_owner', 'org_id', 'org_partition',
    'master_owner', 'master_org', 'master_partition', 'master_tail'])
def test_public_tag_control_native_arn_binding(monkeypatch, sdk, mode):
    body = organization()
    if mode == 'missing_optional': body.pop('Arn'); body.pop('MasterAccountArn')
    elif mode == 'org_owner': body['Arn'] = ORG_ARN.replace(MASTER, ACCOUNT)
    elif mode == 'org_id': body['Arn'] = ORG_ARN.replace(ORG, 'o-9876543210')
    elif mode == 'org_partition': body['Arn'] = ORG_ARN.replace('arn:aws:', 'arn:aws-cn:')
    elif mode == 'master_owner': body['MasterAccountArn'] = MASTER_ARN.replace(MASTER, ACCOUNT)
    elif mode == 'master_org': body['MasterAccountArn'] = MASTER_ARN.replace(ORG, 'o-9876543210')
    elif mode == 'master_partition': body['MasterAccountArn'] = MASTER_ARN.replace('arn:aws:', 'arn:aws-us-gov:')
    elif mode == 'master_tail': body['MasterAccountArn'] = MASTER_ARN[:-12] + ACCOUNT
    if mode in ('missing_optional', 'correct'):
        _, finding = collect_policy(monkeypatch, sdk, {'tags': {'environment': {
            'tag_key': {'@@assign': 'Environment'}, 'tag_value': {'@@assign': ['Production']}}}}, organization=body)
        assert finding['status'] == 'PASS'
        return
    session, add = sdk; sts, org = add('sts'), add('organizations')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    org.add_response('describe_organization', {'Organization': body}, {})
    calls, original_call = [], aws.Requests.call
    def observed(self, session, service, region, operation, **arguments):
        calls.append((service, operation))
        return original_call(self, session, service, region, operation, **arguments)
    monkeypatch.setattr(aws.Requests, 'call', observed)
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1,
        'compliance_parameters': {'approved_ec2_tag_values': {'Environment': ['Production']}}}
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    snapshot = collect_live(connector, plan_collection({'connector': connector, 'checks': [CONTROL]}))
    inventory = next(c for c in snapshot['collections'] if c['type'] == 'organization_tag_policy')
    assert inventory['status'] == 'malformed' and inventory['items'] == []
    assert inventory['error']['code'] == 'organization_arn_identity_invalid'
    findings = evaluate_snapshot(snapshot, checks=[CONTROL])['findings']
    assert findings and all(f['status'] == 'UNKNOWN' for f in findings)
    assert calls == [('sts', 'get_caller_identity'), ('organizations', 'describe_organization')]
    sts.assert_no_pending_responses(); org.assert_no_pending_responses()


@pytest.mark.parametrize('field', ['Arn', 'MasterAccountArn'])
@pytest.mark.parametrize('invalid', [None, 123, [], {}])
def test_present_invalid_optional_field_is_not_an_omission(field, invalid):
    # SDK response-shape validation correctly refuses these fixtures; exercise
    # the defensive parser directly rather than bypassing Stubber validation.
    body = organization(); body[field] = invalid
    requests = SimpleNamespace(detail=lambda *args, **kwargs: {'collection_status': 'collected', 'Organization': body})
    org, read = native._organization(requests, object(), REGION)
    assert org is None and read.status == 'malformed' and read.items == []


def test_account_identity_consumer_stops_on_contradictory_native_arn(sdk):
    session, add = sdk; stub = add('organizations'); body = organization()
    body['Arn'] = ORG_ARN.replace(MASTER, ACCOUNT)
    stub.add_response('describe_organization', {'Organization': body}, {})
    reader = aws.Requests({'service_concurrency': 1, 'retry_attempts': 1})
    read = native.account_identities(reader, session, REGION, ACCOUNT)
    assert read.items == [] and read.status == 'malformed' and reader.calls == 1
    stub.assert_no_pending_responses()
