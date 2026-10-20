"""Exhaustive AWS copy accounting and replay of actual native-test witnesses.

The fixture was captured while 19,942 native tests passed. Each exact evaluator
and description remains source-bound here; verdicts and evidence are immutable.
"""
from copy import deepcopy
import gzip
import hashlib
import inspect
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, CHECK_ALIASES
from peaso.checks.catalog import description_for
from peaso.checks.aws_evidence_explanations import evidence_summary, review_rows, reviewed_explanation
from peaso.checks.aws_natural_evidence import complete_explanation
from peaso.checks.aws_review_20261019 import MODULES
from importlib import import_module

ROOT = Path(__file__).resolve().parents[1]
CHECK_BY_ID = {c.id: c for c in CHECKS if c.provider == 'aws'}
ROWS = review_rows()
LEDGER = json.loads((ROOT / 'docs/evidence-reviews/aws.json').read_text())
CASES = json.loads(gzip.decompress((ROOT / 'tests/fixtures/aws_evidence_review.json.gz').read_bytes()))
from tests.aws_late_native_contracts_20261020 import IDS as LATE_IDS, assert_contract

STATUSES = ('PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'EMPTY', 'NOT_APPLICABLE')
EXTENSION_IDS = {row['spec']['id'] for name in MODULES
                 for row in import_module('peaso.checks.' + name).ADMISSION_DATA['checks']}


def test_every_registered_aws_check_and_retired_alias_has_source_review_and_real_native_witnesses():
    aliases = {old for old, new in CHECK_ALIASES.items() if new in CHECK_BY_ID}
    assert len(CHECK_BY_ID) == 1521 + len(EXTENSION_IDS) + len(LATE_IDS)
    assert set(CHECK_BY_ID) == set(CASES) | LATE_IDS
    assert not set(CASES) & LATE_IDS
    assert set(CHECK_BY_ID) | aliases == set(ROWS) == set(LEDGER['checks'])
    assert sum(len(rows) for cid, rows in CASES.items() if cid not in EXTENSION_IDS) == 8882
    assert all(len(CASES[cid]) >= 4 for cid in EXTENSION_IDS)
    assert all(ROWS[cid]['review_status'] == 'source_reviewed_and_native_replayed' for cid in set(ROWS) - LATE_IDS)
    assert all(ROWS[cid]['purpose'] and ROWS[cid]['fields'] is not None for cid in set(ROWS) - LATE_IDS)
    for cid in LATE_IDS:
        assert_contract(cid, CHECK_BY_ID[cid], LEDGER['checks'][cid], ROWS[cid], description_for(cid))


@pytest.mark.parametrize('cid', sorted(CHECK_BY_ID))
def test_exact_evaluator_and_requirement_contract_match_the_review(cid):
    row = LEDGER['checks'][cid]
    if cid in LATE_IDS:
        assert_contract(cid, CHECK_BY_ID[cid], row, ROWS[cid], description_for(cid))
        return
    function = inspect.unwrap(CHECK_BY_ID[cid].evaluate)
    assert hashlib.sha256(inspect.getsource(function).encode()).hexdigest() == row['evaluator_sha256']
    if cid in EXTENSION_IDS:
        target = getattr(function, 'reviewed_target', function)
        assert hashlib.sha256(inspect.getsource(target).encode()).hexdigest() == row['target_sha256']
    contract = json.dumps(description_for(cid), sort_keys=True, separators=(',', ':')).encode()
    assert hashlib.sha256(contract).hexdigest() == row['description_contract_sha256']
    assert ROWS[cid]['purpose'] == row['purpose']
    assert row['fixture_count'] == len(CASES[cid])
    assert row['missing_fixture_ids'] == []


@pytest.mark.parametrize('cid', sorted(CASES))
def test_all_captured_success_failure_partial_and_inapplicable_witnesses(cid):
    for case in CASES[cid]:
        finding = dict(provider='aws', check_id=cid, status=case['status'], evidence=deepcopy(case['evidence']))
        before = deepcopy(finding)
        summary = evidence_summary(finding)
        assert summary == case['summary']
        assert len(summary) <= 250
        complete = complete_explanation(finding)
        assert summary == complete or ROWS[cid]['purpose'] in summary
        assert not summary.startswith(('{', '[')) and '\n' not in summary
        assert 'All of:' not in summary and 'quantifier' not in summary
        if summary != complete:
            assert reviewed_explanation(cid, summary, finding['status']) == summary
        assert finding == before


@pytest.mark.parametrize('cid', sorted(CHECK_BY_ID))
def test_every_status_with_absent_or_unrelated_evidence_is_explicitly_unclaimed(cid):
    for status in STATUSES:
        for evidence in ({}, {'unrelated': True}):
            summary = evidence_summary(dict(provider='aws', check_id=cid, status=status, evidence=evidence))
            complete = complete_explanation(dict(provider='aws', check_id=cid, status=status, evidence=evidence))
            assert summary and (summary == complete or ROWS[cid]['purpose'] in summary)
            assert any(text in summary for text in ('No usable deciding evidence', 'Required evidence is unavailable',
                                                     'outside the control’s applicability', 'No applicable resources',
                                                     'could not be checked', 'cannot confirm whether root keys exist'))
            assert not summary.startswith(('The policy grants', 'The function has', 'Automatic rotation is enabled'))


def test_retired_equivalent_ids_reuse_the_survivor_native_value_interpretation():
    for old, new in CHECK_ALIASES.items():
        if new not in CHECK_BY_ID:
            continue
        for case in CASES[new]:
            finding = dict(provider='aws', status=case['status'], evidence=case['evidence'])
            assert evidence_summary(dict(finding, check_id=old)) == evidence_summary(dict(finding, check_id=new))


def test_invalid_identifiers_and_foreign_provider_do_not_get_aws_copy():
    for cid in (None, {}, [], 'aws.not-reviewed'):
        assert evidence_summary(dict(provider='aws', check_id=cid, status='FAIL', evidence={})) is None
    assert evidence_summary(dict(provider='gcp', check_id='aws.iam.console_mfa', status='FAIL', evidence={})) is None
