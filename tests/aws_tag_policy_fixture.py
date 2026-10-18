"""Portable typed SDK fixture for attached literal Organizations policies."""
import json
from types import SimpleNamespace
from peaso.collectors import aws, collect_live
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from tests.test_peaso_aws_bulk_inventory import ACCOUNT, REGION
from tests.test_peaso_aws_tag_policy_locked_assignment import MASTER, ORG, OU, ROOT, POLICY, CONTROL


def collect_policy(monkeypatch, sdk, document, *, readable=True, approved=None, organization=None):
    session, add = sdk; sts, org = add('sts'), add('organizations')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    org.add_response('describe_organization', {'Organization': organization if organization is not None else
        {'Id': ORG, 'MasterAccountId': MASTER, 'FeatureSet': 'ALL'}}, {})
    org.add_response('list_parents', {'Parents': [{'Id': OU, 'Type': 'ORGANIZATIONAL_UNIT'}]}, {'ChildId': ACCOUNT})
    org.add_response('list_parents', {'Parents': [{'Id': ROOT, 'Type': 'ROOT'}]}, {'ChildId': OU})
    summary = {'Id': POLICY, 'Arn': f'arn:aws:organizations::{MASTER}:policy/{ORG}/tag_policy/{POLICY}',
        'Name': 'policy', 'Type': 'TAG_POLICY', 'AwsManaged': False}
    org.add_response('list_policies_for_target', {'Policies': [summary]}, {'TargetId': ACCOUNT, 'Filter': 'TAG_POLICY'})
    org.add_response('describe_policy', {'Policy': {'PolicySummary': summary, 'Content': json.dumps(document)}}, {'PolicyId': POLICY})
    if readable:
        for target in (OU, ROOT):
            org.add_response('list_policies_for_target', {'Policies': []}, {'TargetId': target, 'Filter': 'TAG_POLICY'})
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1,
        'compliance_parameters': {'approved_ec2_tag_values': approved or {'Environment': ['Production']}}}
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CONTROL]})
    assert requirements == ['organization_tag_policy']
    snapshot = collect_live(connector, requirements)
    findings = evaluate_snapshot(snapshot, checks=[CONTROL])['findings']
    assert len(findings) == 1
    sts.assert_no_pending_responses(); org.assert_no_pending_responses()
    return snapshot, findings[0]
