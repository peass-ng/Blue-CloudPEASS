"""Every current provider check and pinned Kubernetes source has one recorded result."""
import csv
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.native_only import exclusions
ROOT=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('provider',['gcp','azure','k8s'])
def test_every_registered_id_has_recorded_review_or_explicit_exclusion(provider):
    rows=list(csv.DictReader((ROOT/'docs/check-review/checks.csv').open()))
    selected=[r for r in rows if r['provider']==provider]
    expected={c.id for c in CHECKS if c.provider==provider}
    assert len(selected)==len({r['check_id']for r in selected})
    assert {r['check_id']for r in selected}==expected
    progress=json.loads((ROOT/'docs/check-review/progress.json').read_text())
    assert progress['inventory_counts'][provider]==len(expected)
    assert progress['active_counts'][provider]==len(expected-exclusions().keys())
    for row in selected:
        assert row['current_goal_status']
        assert row['current_goal_receipt'] and (ROOT/row['current_goal_receipt']).is_file()
        assert row['remaining_action']  # Limits stay explicit even for accepted bounded tests.

def test_kubernetes_upstream_dispositions_conserve_pinned_inventory():
    record=json.loads((ROOT/'docs/check-review/k8s-upstream-parity-20261020.json').read_text())
    matrix=list(csv.DictReader((ROOT/record['matrix']).open()))
    inventory=json.loads((ROOT/record['source_inventory']).read_text())['checks']
    assert len(matrix)==len({r['source_id']for r in matrix})==record['source_total']
    assert {r['source_id']for r in matrix}=={r['check_id']for r in inventory}
    assert not record['unaccounted_ids'] and not record['pending_candidates']
    assert sum(record['counts'].values())==len(matrix)
    native={c.id for c in CHECKS}
    for row in matrix:
        assert row['current_review_status'] and row['remaining_action']
        for cid in filter(None,row['reviewed_native_ids'].split(';')):
            assert cid in native


def test_azure_current_sources_all_have_explicit_preserved_or_reviewed_disposition():
    record=json.loads((ROOT/'docs/check-review/azure-upstream-parity-20261020.json').read_text())
    rows=list(csv.DictReader((ROOT/record['matrix']).open()))
    source=json.loads((ROOT/record['source_inventory']).read_text())['checks']
    assert len(rows)==len({r['source_id']for r in rows})==record['source_total']
    assert {r['source_id']for r in rows}=={r['check_id']for r in source}
    assert sum(record['counts'].values())==len(rows)
    assert not record['unaccounted_source_ids'] and not record['missing_native_ids']
    for row in rows:
        assert row['source_reason'] and row['scope_limit']
        for receipt in filter(None,row['native_receipts'].split(';')):
            assert (ROOT/receipt).is_file()


def test_reassessment_original_reasons_use_exact_raw_source_ids():
    import hashlib
    correction=json.loads((ROOT/'docs/check-review/azure-rejected-source-original-reason-errata-20261020.json').read_text())
    for field in ('report','raw_upstream_manifest'):
        row=correction[field]
        assert hashlib.sha256((ROOT/row['path']).read_bytes()).hexdigest()==row['sha256']
    report=json.loads((ROOT/correction['report']['path']).read_text())
    raw={r['check_id']:r for r in json.loads((ROOT/correction['raw_upstream_manifest']['path']).read_text())['checks']}
    actual={r['source_id']:(r['original_reason'],raw[r['source_id']]['reason'])for r in report['sources']
            if r['original_reason']!=raw[r['source_id']]['reason']}
    assert actual=={r['source_id']:(r['report_recorded_original_reason'],r['actual_upstream_reason'])for r in correction['records']}
    matrix=list(csv.DictReader((ROOT/'docs/check-review/azure-upstream-parity-20261020.csv').open()))
    for row in matrix:
        if row['source_id']in raw:
            assert row['source_reason']==raw[row['source_id']]['reason']
