"""Current loaded predicates must match an individual, source-bound review."""
import hashlib
import inspect
import json
import csv
from pathlib import Path
from peaso.checks import CHECKS
from tests.test_gcp_current_source_reconciliation_20261020 import _bound_functions


def test_all_current_azure_k8s_bodies_have_exact_existing_or_erratum_receipts():
    root=Path(__file__).resolve().parents[1]
    audit=json.loads((root/'docs/check-review/azure-k8s-current-predicate-bindings-20261020.json').read_text())
    err=json.loads((root/audit['current_master_attestation_errata']).read_text())
    rows={r['id']:r for r in audit['checks']};fixes={r['id']:r for r in err['records']}
    current={c.id:c for c in CHECKS if c.provider in ('azure','k8s')}
    added='azure.review.function.selected_package_source_secret_indicators'
    assert current.keys()-{added}==rows.keys() and len(rows)==2017
    new=current[added]
    assert new.provider=='azure' and new.kind=='azure_function_package_portable_20261020'
    master,=[r for r in csv.DictReader((root/'docs/check-review/checks.csv').open()) if r['check_id']==added]
    function=inspect.unwrap(new.evaluate)
    assert master['current_goal_status'] in {'native_integration_final_gate_pending','accepted_local_bounded_native_review'}
    assert master['current_bound_predicate_sha256']==hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
    assert master['source_sha256']==hashlib.sha256((root/master['source']).read_bytes()).hexdigest()
    current={cid:c for cid,c in current.items()if cid!=added}
    assert set(fixes)==set(audit['master_attestation_mismatches']) and len(fixes)==26
    assert not audit['current_unresolved_reviewed_bindings'] and not err['unresolved_ids']
    for cid,check in current.items():
        row=rows[cid];fn=next(f for f in _bound_functions(check.evaluate)
                             if str(Path(inspect.getsourcefile(f)).relative_to(root))==row['current_source']
                             and hashlib.sha256(inspect.getsource(f).encode()).hexdigest()==row['current_body_sha256'])
        assert fn and (root/row['review_receipt']).is_file()
        if cid not in fixes:
            assert row['current_body_sha256']==row['expected_body_sha256']
            continue
        fix=fixes[cid]
        assert fix['master_column_body_sha256']==row['expected_body_sha256']
        assert fix['current_body_sha256']==row['current_body_sha256']
        assert fix['matching_individual_reviews']
        for proof in fix['matching_individual_reviews']:
            raw=(root/proof['path']).read_bytes()
            assert hashlib.sha256(raw).hexdigest()==proof['sha256']
            node=json.loads(raw)
            for part in proof['record_path']:node=node[part]
            assert node.get('id',node.get('check_id'))==cid
            bound=proof['current_evaluator']
            assert bound.get('source_text_sha256',bound.get('sha256'))==row['current_body_sha256']
