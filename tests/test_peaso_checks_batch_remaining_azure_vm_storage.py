"""Exact signed Azure partition outcomes on portable captured source facts."""
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks import batch_remaining_azure_vm_storage  # noqa: F401
from peaso.checks.facts import MemoIndex

FIXTURE = Path(__file__).parent / 'fixtures' / 'batch_remaining_azure_vm_storage' / 'central-fixture-fragment.json'
CASES = json.loads(FIXTURE.read_text())
DISPOSITION = json.loads((FIXTURE.parent / 'full-id-disposition.json').read_text())
BATCH = {check.id: check for check in CHECKS if check.id in CASES}


def test_exact_batch_membership_and_native_categories():
    assert len(CASES) == len(BATCH) == 7
    assert len(DISPOSITION['ids']) == 50
    assert set(BATCH) == {row['id'] for row in DISPOSITION['ids'] if row['disposition'] == 'implemented_native_ready'}
    assert all(check.provider == 'azure' and check.category in {'hardening', 'network', 'exposure', 'least_privilege', 'iam_graph'} for check in BATCH.values())
    assert 'azure_vm_8_2_1_1_712e1ad' not in BATCH


@pytest.mark.parametrize('check_id', sorted(CASES))
@pytest.mark.parametrize('status', ('PASS', 'FAIL', 'UNKNOWN'))
def test_source_observed_verdicts(check_id, status):
    case = CASES[check_id]
    observed, evidence = BATCH[check_id].evaluate(case[status.lower()], case[status.lower()+'_index'])
    assert observed == status, (check_id, status, observed, evidence)


@pytest.mark.parametrize('check_id', sorted(CASES))
def test_missing_context_is_unknown(check_id):
    case = CASES[check_id]
    status, _ = BATCH[check_id].evaluate(case['pass'], {})
    assert status == 'UNKNOWN'


def test_inventory_validation_is_cached_per_memo_index():
    check = BATCH['azure.gap.compute_vm_attached_with_network']
    case = CASES[check.id]
    index = MemoIndex(case['pass_index'])
    assert check.evaluate(case['pass'], index)[0] == 'PASS'
    before = {key: id(value) for key, value in index.memo.items()}
    assert any(key[0] == 'azure_remaining_02' for key in before)
    assert check.evaluate(case['pass'], index)[0] == 'PASS'
    assert before == {key: id(value) for key, value in index.memo.items()}
