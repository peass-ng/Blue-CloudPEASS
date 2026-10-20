"""Keep malformed historical evidence distinct from current native witnesses."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
import pytest
from peaso.checks import evaluate_check
from peaso.checks.fixtures import CASES
from peaso.checks.facts import MemoIndex
ROOT=Path(__file__).resolve().parents[1]
@pytest.mark.parametrize('cid',['gcp.claude.bigquery_dataset.no_gmail_access','gcp.claude.bigquery_dataset.no_googlegroups_access'])
def test_old_non_mailbox_fail_fixture_is_preserved_and_unresolved(cid):
    old=CASES[cid]
    assert '@'not in old['fail']['access'][0]['userByEmail']
    assert evaluate_check(cid,deepcopy(old['fail']),deepcopy(old.get('fail_index',old.get('index',{}))))[0]=='UNKNOWN'
@pytest.mark.parametrize('stem',['alert','compute','final-services','prior-bounded','native57'])
def test_current_native_fixture_is_bound_to_exact_successor_proof(stem):
    fixture=json.loads((ROOT/f'tests/fixtures/gcp-{stem}-native-successor-20261020.json').read_text())
    key='predicate_successor_sha256'
    if key not in fixture:
        assert stem=='alert'
        key='source_successor_sha256'
    proof=ROOT/f'docs/gcp-review/recheck-20261020/{stem}-predicate-successors.json'
    assert fixture[key]==hashlib.sha256(proof.read_bytes()).hexdigest()
