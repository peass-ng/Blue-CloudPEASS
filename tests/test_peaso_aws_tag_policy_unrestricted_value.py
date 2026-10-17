"""An absent tag_value is unrestricted, distinct from a forbidden empty set."""
import json
from types import SimpleNamespace
import pytest

from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from tests.test_peaso_aws_tag_policy_locked_assignment import MASTER, ORG, OU, ROOT, POLICY, LOCK, CONTROL
from peaso.collectors import aws, collect_live
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector


@pytest.mark.parametrize('mode,expected', [('unrelated_unrestricted', 'PASS'), ('required_unrestricted', 'FAIL'),
    ('only_unrestricted', 'FAIL'), ('explicit_empty_values', 'FAIL'), ('explicit_null', 'UNKNOWN'),
    ('missing_key', 'UNKNOWN'), ('inherited_key', 'UNKNOWN'), ('malformed_values', 'UNKNOWN'), ('merged_values', 'UNKNOWN')])
def test_native_optional_value_is_not_an_invented_finite_constraint(monkeypatch, sdk, mode, expected):
    session, add = sdk; sts, org = add('sts'), add('organizations')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    org.add_response('describe_organization', {'Organization': {'Id': ORG, 'MasterAccountId': MASTER, 'FeatureSet': 'ALL'}}, {})
    org.add_response('list_parents', {'Parents': [{'Id': OU, 'Type': 'ORGANIZATIONAL_UNIT'}]}, {'ChildId': ACCOUNT})
    org.add_response('list_parents', {'Parents': [{'Id': ROOT, 'Type': 'ROOT'}]}, {'ChildId': OU})
    summary = {'Id': POLICY, 'Arn': f'arn:aws:organizations::{MASTER}:policy/{ORG}/tag_policy/{POLICY}',
        'Name': 'policy', 'Type': 'TAG_POLICY', 'AwsManaged': False}
    org.add_response('list_policies_for_target', {'Policies': [summary]}, {'TargetId': ACCOUNT, 'Filter': 'TAG_POLICY'})
    tags = {'environment': {'tag_key': {'@@assign': 'Environment', LOCK: ['@@none']},
        'tag_value': {'@@assign': ['Production']}}, 'costcenter': {'tag_key': {'@@assign': 'CostCenter'}}}
    if mode in ('only_unrestricted', 'explicit_empty_values'): del tags['environment']
    if mode == 'explicit_null': tags['costcenter']['tag_value'] = None
    elif mode == 'missing_key': del tags['costcenter']['tag_key']
    elif mode == 'inherited_key': tags['costcenter']['tag_key'] = {'@@append': 'CostCenter'}
    elif mode == 'malformed_values': tags['costcenter']['tag_value'] = {'@@assign': '100'}
    elif mode == 'merged_values': tags['costcenter']['tag_value'] = {'@@append': ['100']}
    elif mode == 'explicit_empty_values': tags['costcenter']['tag_value'] = {'@@assign': []}
    org.add_response('describe_policy', {'Policy': {'PolicySummary': summary, 'Content': json.dumps({'tags': tags})}}, {'PolicyId': POLICY})
    supported = mode in ('unrelated_unrestricted', 'required_unrestricted', 'only_unrestricted', 'explicit_empty_values')
    if supported:
        for target in (OU, ROOT):
            org.add_response('list_policies_for_target', {'Policies': []}, {'TargetId': target, 'Filter': 'TAG_POLICY'})
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    required = {'CostCenter': ['100']} if mode in ('only_unrestricted', 'explicit_empty_values') else {'Environment': ['Production']}
    if mode == 'required_unrestricted': required['CostCenter'] = ['100']
    options = {'service_concurrency': 1, 'retries': 1, 'compliance_parameters': {'approved_ec2_tag_values': required}}
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CONTROL]})
    assert requirements == ['organization_tag_policy']
    snapshot = collect_live(connector, requirements)
    findings = evaluate_snapshot(snapshot, checks=[CONTROL])['findings']
    assert len(findings) == 1 and findings[0]['status'] == expected
    if supported:
        row = next(c['items'][0] for c in snapshot['collections'] if c['type'] == 'organization_tag_policy')
        assert row['Complete'] is True
        constraint = next(entry for entry in row['TagValueDigests'] if entry['TagKey'] == 'CostCenter')
        assert 'Ec2Tags' not in row
        if mode == 'explicit_empty_values':
            assert constraint['ConstraintKind'] == 'finite' and constraint['ValueDigests'] == []
        else:
            assert constraint['ConstraintKind'] == 'unrestricted' and constraint['ValueDigests'] == []
    sts.assert_no_pending_responses(); org.assert_no_pending_responses()
