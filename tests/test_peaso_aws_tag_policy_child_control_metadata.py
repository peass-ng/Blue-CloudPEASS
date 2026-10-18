"""Child-control permissions do not execute value-setting operators locally."""
import pytest
from tests.test_peaso_aws_bulk_inventory import sdk
from tests.aws_tag_policy_fixture import collect_policy

LOCK = '@@operators_allowed_for_child_policies'


def document(operators, value='Production'):
    return {'tags': {'environment': {'tag_key': {'@@assign': 'Environment', LOCK: ['@@assign']},
        'tag_value': {'@@assign': [value], LOCK: operators}}}}


@pytest.mark.parametrize('operators', [['@@assign'], ['@@all'], ['@@append'], ['@@remove'],
    ['@@assign', '@@append', '@@remove'], ['@@remove', '@@assign']])
def test_documented_child_control_forms_preserve_local_literal(monkeypatch, sdk, operators):
    snapshot, finding = collect_policy(monkeypatch, sdk, document(operators))
    assert finding['status'] == 'PASS'
    row = next(c['items'][0] for c in snapshot['collections'] if c['type'] == 'organization_tag_policy')
    assert 'Ec2Tags' not in row and row['TagValueDigests'][0]['ConstraintKind'] == 'finite'
    assert 'effective merge unassessed' in row['_provenance']['semantics']


def test_child_control_metadata_does_not_hide_literal_mismatch(monkeypatch, sdk):
    _, finding = collect_policy(monkeypatch, sdk, document(['@@assign'], 'Development'))
    assert finding['status'] == 'FAIL'


@pytest.mark.parametrize('operators', [None, '@@assign', [], ['@@unknown'], ['@@none', '@@assign'],
    ['@@all', '@@assign'], ['@@assign', '@@assign'], [True], [['@@assign']]])
def test_unrecognized_or_malformed_child_control_remains_unknown(monkeypatch, sdk, operators):
    _, finding = collect_policy(monkeypatch, sdk, document(operators), readable=False)
    assert finding['status'] == 'UNKNOWN'


def test_actual_remove_operator_still_requires_effective_inheritance(monkeypatch, sdk):
    value = document(['@@assign'])
    value['tags']['environment']['tag_value'] = {'@@remove': ['Production'], LOCK: ['@@assign']}
    _, finding = collect_policy(monkeypatch, sdk, value, readable=False)
    assert finding['status'] == 'UNKNOWN'
