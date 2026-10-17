"""Only a real, consistently typed Organizations parent can terminate a path."""
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_organizations_ou_account_state import case, CONTROL, SCOPE, MANAGEMENT


def verdict(index):
    snapshot = make_snapshot('aws', [SCOPE], [e for envs in index['collections'].values() for e in envs],
        metadata=index['context']['metadata'])
    return next(f['status'] for f in evaluate_snapshot(snapshot, checks=[CONTROL])['findings'] if f['check_id'] == CONTROL)


def parents(index):
    return index['collections']['organization_parent'][0]['items']


def arn(parent, organization='o-1234567890', management=MANAGEMENT):
    category = 'root' if parent.startswith('r-') else 'ou'
    return 'arn:aws:organizations::' + management + ':' + category + '/' + organization + '/' + parent


@pytest.mark.parametrize('mode', ['ou_as_root', 'root_as_ou', 'root_child', 'malformed_ou', 'unknown_account_child',
    'raw_id_disagrees', 'raw_type_disagrees', 'wrong_arn_type', 'foreign_arn_account', 'foreign_organization',
    'regional_arn', 'wrong_arn_id'])
def test_contradictory_or_invalid_parent_identity_is_unknown(mode):
    _, index = case()
    rows = parents(index)
    if mode == 'ou_as_root': rows[-1]['ParentId'] = 'ou-abcd-99999999'
    elif mode == 'root_as_ou': rows[0]['ParentId'] = 'r-root'
    elif mode == 'root_child': rows[0]['ChildId'] = 'r-root'
    elif mode == 'malformed_ou': rows[0]['ParentId'] = 'ou-a-short'
    elif mode == 'unknown_account_child': rows[0]['ChildId'] = '000000000000'
    elif mode == 'raw_id_disagrees': rows[0]['Id'] = 'ou-abcd-99999999'
    elif mode == 'raw_type_disagrees': rows[0]['Type'] = 'ROOT'
    elif mode == 'wrong_arn_type': rows[0]['Arn'] = arn(rows[0]['ParentId']).replace(':ou/', ':root/')
    elif mode == 'foreign_arn_account': rows[0]['Arn'] = arn(rows[0]['ParentId'], management='000000000000')
    elif mode == 'foreign_organization':
        rows[0]['Arn'] = arn(rows[0]['ParentId'])
        rows[-1]['Arn'] = arn(rows[-1]['ParentId'], organization='o-0987654321')
    elif mode == 'regional_arn': rows[0]['Arn'] = arn(rows[0]['ParentId']).replace('organizations::', 'organizations:us-east-1:')
    elif mode == 'wrong_arn_id': rows[0]['ParentArn'] = arn('ou-abcd-99999999')
    assert verdict(index) == 'UNKNOWN'


@pytest.mark.parametrize('good_path,expected', [(True, 'PASS'), (False, 'FAIL')])
def test_real_parent_shapes_and_optional_native_arns_preserve_decisions(good_path, expected):
    _, index = case(good_path=good_path)
    for row in parents(index):
        row.update(Id=row['ParentId'], Type=row['ParentType'], Arn=arn(row['ParentId']))
    assert verdict(index) == expected


def test_valid_legacy_account_status_remains_compatible():
    _, index = case({'Id': '999999999999', 'Status': 'ACTIVE'})
    assert verdict(index) == 'PASS'
