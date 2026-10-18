# Historical fixture contracts; current native admission is tested separately.
"""Normal Cognito-compatible owner options -> AWS collector -> OU evaluator."""
from types import SimpleNamespace
import pytest

from peaso.collectors import aws, collect_live
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from tests.test_peaso_aws_organization_ou_native import (
    sdk, ACCOUNT, REGION, MEMBER, PROD, SENSITIVE, ROOT, CONTROL,
    account, roster, parent, unit, paths,
)


@pytest.mark.parametrize('mode,expected', [('prod', 'PASS'), ('dev', 'FAIL'), ('roster_denied', 'DENIED'),
    ('unit_denied', 'UNKNOWN'), ('roster_partial', 'UNKNOWN'), ('shared_ou', 'PASS')])
def test_hosted_native_organization_member_scope(monkeypatch, sdk, mode, expected):
    session, add = sdk; sts = add('sts'); org = add('organizations')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    rows = roster() + ([account('888888888888')] if mode == 'shared_ou' else [])
    if mode == 'roster_denied':
        org.add_client_error('list_accounts', 'AccessDeniedException', expected_params={})
    else:
        org.add_response('list_accounts', {'Accounts': rows, **({'NextToken': 'next'} if mode == 'roster_partial' else {})}, {})
        if mode == 'unit_denied':
            parent(org, ACCOUNT, ROOT, 'ROOT')
            parent(org, MEMBER, PROD, 'ORGANIZATIONAL_UNIT')
            org.add_client_error('describe_organizational_unit', 'AccessDeniedException', expected_params={'OrganizationalUnitId': PROD})
        elif mode == 'shared_ou':
            parent(org, ACCOUNT, ROOT, 'ROOT')
            parent(org, '888888888888', PROD, 'ORGANIZATIONAL_UNIT'); unit(org, PROD, 'prod')
            parent(org, PROD, SENSITIVE, 'ORGANIZATIONAL_UNIT'); unit(org, SENSITIVE, 'sensitive')
            parent(org, SENSITIVE, ROOT, 'ROOT')
            parent(org, MEMBER, PROD, 'ORGANIZATIONAL_UNIT')
        elif mode != 'roster_partial':
            paths(org, mode)
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16,
        'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1,
        'compliance_parameters': {'organization_management_account_id': ACCOUNT,
            'approved_environment_ou_patterns': ['prod'], 'approved_sensitivity_ou_patterns': ['sensitive']}}
    if mode == 'roster_partial': options['max_pages'] = 1
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CONTROL]})
    assert set(requirements) == {'organization_account', 'organization_parent'}
    snapshot = collect_live(connector, requirements)
    findings = evaluate_snapshot(snapshot, checks=[CONTROL])['findings']
    assert next(f['status'] for f in findings if f['check_id'] == CONTROL) == expected
    parent_inventory = next(c for c in snapshot['collections'] if c['type'] == 'organization_parent')
    if mode == 'shared_ou':
        assert len(parent_inventory['items']) == 5
        assert len({r['_resource_id'] for r in parent_inventory['items']}) == 5
    if mode == 'unit_denied': assert parent_inventory['status'] == 'partial'
    sts.assert_no_pending_responses(); org.assert_no_pending_responses()
