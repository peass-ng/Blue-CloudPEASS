"""Declared unreadable restore owner policy cannot be hidden by its mirror."""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from peaso.checks import CHECKS

CID = 'azure_c5_ops_08_01b'


def fixture():
    case = json.loads((Path(__file__).parent / 'fixtures/bulk_pending_behavior.json').read_text())[CID]
    return deepcopy(case['pass']), deepcopy(case['pass_index'])


def verdict(item, index):
    return next(c for c in CHECKS if c.id == CID).evaluate(item, index)[0]


@pytest.mark.parametrize('path', [
    (), ('compliance_policy',), ('compliance_policy', 'sw22'), ('sw22',),
])
def test_declared_unreadable_policy_parent_or_leaf_is_unknown(path):
    item, index = fixture()
    row = index['context']['metadata']
    for key in path:
        row = row[key]
    field = 'compliance_policy' if not path else 'sw22' if path == ('compliance_policy',) else 'restore_tests'
    row['_coverage'] = {field: {'status': 'denied'}}
    assert verdict(item, index) == 'UNKNOWN'


def test_numerically_equal_but_differently_typed_policy_copies_are_ambiguous():
    item, index = fixture()
    policy = index['context']['metadata']['compliance_policy']['sw22']['restore_tests']
    policy['maxRestoreTestAgeDays'] = float(policy['maxRestoreTestAgeDays'])
    assert verdict(item, index) == 'UNKNOWN'


@pytest.mark.parametrize('namespace', ['legacy', 'standard', 'both'])
def test_complete_unambiguous_owner_policy_namespaces_preserve_pass(namespace):
    item, index = fixture()
    metadata = index['context']['metadata']
    if namespace == 'legacy':
        metadata.pop('compliance_policy')
    elif namespace == 'standard':
        metadata.pop('sw22')
    assert verdict(item, index) == 'PASS'
