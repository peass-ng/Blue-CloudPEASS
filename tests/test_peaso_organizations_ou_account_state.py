"""OU review follows native State while retaining valid legacy snapshots."""
from peaso.checks import evaluate_check
import pytest

CONTROL = 'aws_cis_organization_units_environment_sensitivity'
SCOPE = '123456789012/us-east-1'
MANAGEMENT = '123456789012'
MEMBER = '999999999999'


def case(member=None, good_path=True):
    member = {'Id': MEMBER, 'State': 'ACTIVE'} if member is None else member
    rows = {'organization_account': [{'Id': MANAGEMENT, 'State': 'ACTIVE'}, member],
        'organization_parent': [
            {'ChildId': MEMBER, 'ParentId': 'ou-abcd-12345678', 'ParentType': 'ORGANIZATIONAL_UNIT',
             'OrganizationalUnitName': 'prod' if good_path else 'dev'},
            {'ChildId': 'ou-abcd-12345678', 'ParentId': 'ou-abcd-87654321', 'ParentType': 'ORGANIZATIONAL_UNIT',
             'OrganizationalUnitName': 'sensitive'},
            {'ChildId': 'ou-abcd-87654321', 'ParentId': 'r-root', 'ParentType': 'ROOT'}]}
    index = {'context': {'provider': 'aws', 'scope': SCOPE, 'metadata': {
        'organization_management_account_id': MANAGEMENT,
        'approved_environment_ou_patterns': ['prod'], 'approved_sensitivity_ou_patterns': ['sensitive']}},
        'collections': {kind: [{'type': kind, 'scope': SCOPE, 'status': 'collected', 'items': items}] for kind, items in rows.items()},
        **{kind: [{'type': kind, 'scope': SCOPE, 'data': item} for item in items] for kind, items in rows.items()}}
    return {'scope': SCOPE}, index


@pytest.mark.parametrize('good_path,expected', [(True, 'PASS'), (False, 'FAIL')])
def test_state_only_active_account_uses_approved_ou_path(good_path, expected):
    subject, index = case(good_path=good_path)
    assert evaluate_check(CONTROL, subject, index)[0] == expected


@pytest.mark.parametrize('state', ['PENDING_ACTIVATION', 'SUSPENDED', 'PENDING_CLOSURE', 'CLOSED'])
def test_native_inactive_state_never_becomes_active(state):
    subject, index = case({'Id': MEMBER, 'State': state}, good_path=False)
    # Inactive members need no applicable OU path, provided the requested
    # native inventories themselves are complete.
    index['collections']['organization_parent'][0].update(status='empty', items=[])
    index['organization_parent'] = []
    assert evaluate_check(CONTROL, subject, index)[0] == 'PASS'


@pytest.mark.parametrize('state,status', [
    ('ACTIVE', 'ACTIVE'), ('PENDING_ACTIVATION', 'ACTIVE'),
    ('SUSPENDED', 'SUSPENDED'), ('CLOSED', 'SUSPENDED'), ('PENDING_CLOSURE', 'PENDING_CLOSURE'),
])
def test_documented_old_status_mapping_does_not_override_native_state(state, status):
    subject, index = case({'Id': MEMBER, 'State': state, 'Status': status}, good_path=False)
    assert evaluate_check(CONTROL, subject, index)[0] == ('FAIL' if state == 'ACTIVE' else 'PASS')


@pytest.mark.parametrize('state', [None, '', 'UNKNOWN', True, 1, [], {}])
def test_explicit_invalid_state_cannot_fall_back_to_valid_status(state):
    subject, index = case({'Id': MEMBER, 'State': state, 'Status': 'ACTIVE'})
    assert evaluate_check(CONTROL, subject, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('status', ['ACTIVE', 'SUSPENDED', 'PENDING_CLOSURE'])
def test_legacy_status_remains_supported_only_when_state_absent(status):
    subject, index = case({'Id': MEMBER, 'Status': status}, good_path=False)
    assert evaluate_check(CONTROL, subject, index)[0] == ('FAIL' if status == 'ACTIVE' else 'PASS')


@pytest.mark.parametrize('state,status', [
    ('ACTIVE', 'SUSPENDED'), ('SUSPENDED', 'ACTIVE'), ('CLOSED', 'ACTIVE'),
    ('PENDING_ACTIVATION', 'SUSPENDED'), ('PENDING_CLOSURE', 'ACTIVE'), ('ACTIVE', None),
])
def test_contradictory_or_malformed_native_fields_stay_unknown(state, status):
    subject, index = case({'Id': MEMBER, 'State': state, 'Status': status})
    assert evaluate_check(CONTROL, subject, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mode', ['id', 'duplicate', 'unreadable_state', 'missing_both', 'invalid_legacy'])
def test_account_identity_or_state_authority_is_not_inferred(mode):
    subject, index = case()
    member = index['organization_account'][1]['data']
    if mode == 'id': member['Id'] = 'not-an-account'
    elif mode == 'duplicate': member['Id'] = MANAGEMENT
    elif mode == 'unreadable_state':
        member.pop('State'); member['Status'] = 'ACTIVE'
        member['_coverage'] = {'State': {'status': 'denied'}}
    elif mode == 'missing_both': member.pop('State')
    elif mode == 'invalid_legacy': member.pop('State'); member['Status'] = 'CLOSED'
    assert evaluate_check(CONTROL, subject, index)[0] == 'UNKNOWN'
