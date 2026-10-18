"""Literal policy keys identify the same tag, with case-insensitive identity."""
from copy import deepcopy
import pytest
from tests.test_peaso_aws_bulk_inventory import sdk
from tests.aws_tag_policy_fixture import collect_policy


@pytest.mark.parametrize('mode,expected', [('different_identity', 'UNKNOWN'),
    ('duplicate_casefold', 'UNKNOWN'), ('costcenter_lower', 'PASS'), ('costcenter_upper', 'PASS'),
    ('value_case_mismatch', 'FAIL'), ('missing_assigned_key', 'UNKNOWN'), ('empty_logical', 'UNKNOWN')])
def test_sdk_public_literal_policy_key_identity(monkeypatch, sdk, mode, expected):
    definition = {'tag_key': {'@@assign': 'CostCenter'}, 'tag_value': {'@@assign': ['Production']}}
    tags = {'costcenter': definition}
    if mode == 'different_identity': tags = {'other': definition}
    elif mode == 'duplicate_casefold':
        other = deepcopy(definition); other['tag_key']['@@assign'] = 'costcenter'
        tags['CostCenter'] = other
    elif mode == 'costcenter_upper': tags = {'COSTCENTER': definition}
    elif mode == 'value_case_mismatch': definition['tag_value']['@@assign'] = ['production']
    elif mode == 'missing_assigned_key': definition.pop('tag_key')
    elif mode == 'empty_logical': tags = {'': definition}
    snapshot, finding = collect_policy(monkeypatch, sdk, {'tags': tags},
        readable=expected != 'UNKNOWN', approved={'CostCenter': ['Production']})
    assert finding['status'] == expected
    if expected == 'UNKNOWN':
        inventory = next(c for c in snapshot['collections'] if c['type'] == 'organization_tag_policy')
        assert inventory['items'] == [] and inventory['status'] == 'malformed'
