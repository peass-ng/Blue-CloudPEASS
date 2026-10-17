"""Documented child-operator locks preserve literal attached TAG_POLICY values."""
import json
from types import SimpleNamespace
import pytest

from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector

CONTROL = 'aws_cis_ec2_tag_policy'
MASTER = '111111111111'
ORG = 'o-abcdefghij'
OU, ROOT, POLICY = 'ou-abcd-abcdefgh', 'r-abcd', 'p-abcdefgh'
LOCK = '@@operators_allowed_for_child_policies'


@pytest.mark.parametrize('mode,expected', [('locked_both', 'PASS'), ('locked_key', 'PASS'), ('locked_values', 'PASS'),
    ('wrong_value', 'FAIL'), ('lock_unknown', 'UNKNOWN'), ('lock_mixed', 'UNKNOWN'),
    ('lock_null', 'UNKNOWN'), ('append', 'UNKNOWN'), ('wildcard', 'UNKNOWN'), ('denied', 'DENIED'),
    ('custom_environment', 'FAIL'), ('secret_tag', 'PASS')])
def test_normal_hosted_native_literal_policy_with_child_lock(monkeypatch, sdk, mode, expected):
    session, add = sdk; sts, org = add('sts'), add('organizations')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    org.add_response('describe_organization', {'Organization': {'Id': ORG,
        'MasterAccountId': MASTER, 'FeatureSet': 'ALL'}}, {})
    org.add_response('list_parents', {'Parents': [{'Id': OU, 'Type': 'ORGANIZATIONAL_UNIT'}]}, {'ChildId': ACCOUNT})
    org.add_response('list_parents', {'Parents': [{'Id': ROOT, 'Type': 'ROOT'}]}, {'ChildId': OU})
    summary = {'Id': POLICY, 'Arn': f'arn:aws:organizations::{MASTER}:policy/{ORG}/tag_policy/{POLICY}',
        'Name': 'policy', 'Type': 'TAG_POLICY', 'AwsManaged': False}
    org.add_response('list_policies_for_target', {'Policies': [summary]}, {'TargetId': ACCOUNT, 'Filter': 'TAG_POLICY'})
    if mode == 'denied':
        org.add_client_error('describe_policy', 'AccessDeniedException', expected_params={'PolicyId': POLICY})
    else:
        key = {'@@assign': 'Environment'}
        values = {'@@assign': ['Development' if mode == 'wrong_value' else 'Prod*' if mode == 'wildcard' else 'Production']}
        if mode != 'locked_values': key[LOCK] = ['@@none']
        if mode != 'locked_key': values[LOCK] = ['@@none']
        if mode == 'lock_unknown': key[LOCK] = ['@@bogus']
        elif mode == 'lock_mixed': key[LOCK] = ['@@none', '@@assign']
        elif mode == 'lock_null': key[LOCK] = None
        elif mode == 'append': values = {'@@append': ['Production'], LOCK: ['@@none']}
        if mode == 'custom_environment': values['@@assign'] = ['MUST-NOT-LEAK-CUSTOM-ENVIRONMENT']
        document = {'tags': {'environment': {'tag_key': key, 'tag_value': values}}}
        if mode == 'secret_tag':
            document['tags']['password'] = {'tag_key': {'@@assign': 'Password'},
                'tag_value': {'@@assign': ['MUST-NOT-LEAK-POLICY-SECRET']}}
        org.add_response('describe_policy', {'Policy': {'PolicySummary': summary, 'Content': json.dumps(document)}}, {'PolicyId': POLICY})
        if mode in ('locked_both', 'locked_key', 'locked_values', 'wrong_value', 'custom_environment', 'secret_tag'):
            for target in (OU, ROOT):
                org.add_response('list_policies_for_target', {'Policies': []}, {'TargetId': target, 'Filter': 'TAG_POLICY'})
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1,
        'compliance_parameters': {'approved_ec2_tag_values': {'Environment': ['Production']}}}
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CONTROL]})
    assert requirements == ['organization_tag_policy']
    snapshot = collect_live(connector, requirements)
    findings = evaluate_snapshot(snapshot, checks=[CONTROL])['findings']
    assert len(findings) == 1 and findings[0]['status'] == expected
    if mode.startswith('locked'):
        rows = next(c['items'] for c in snapshot['collections'] if c['type'] == 'organization_tag_policy')
        assert 'Ec2Tags' not in rows[0] and rows[0]['TagValueDigests'][0]['ConstraintKind'] == 'finite'
        assert rows[0]['_provenance']['semantics'] == 'literal attached policy; tag presence and effective merge unassessed'
    if mode in ('custom_environment', 'secret_tag'):
        assert 'MUST-NOT-LEAK' not in json.dumps(snapshot)
        rows = next(c['items'] for c in snapshot['collections'] if c['type'] == 'organization_tag_policy')
        assert rows[0]['Complete'] is True and 'Ec2Tags' not in rows[0]
    sts.assert_no_pending_responses(); org.assert_no_pending_responses()
