"""Constant INFO definitions retain manual questions rather than fake native support."""
import hashlib,json,re
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parent.parent
REVIEWS=json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_manual.json').read_text())
PROOFS={r['source_review']['query_id']:r['source_review'] for r in REVIEWS.values()}


@pytest.mark.parametrize('query',PROOFS)
def test_actual_pinned_definition_has_no_security_decision(query):
    duckdb=pytest.importorskip('duckdb');sql=PROOFS[query]['pinned_sql']
    assert 'case' not in sql.lower() and not re.search(r'\bwhere\b',sql,re.I)
    with duckdb.connect(':memory:') as db:
        db.execute("CREATE TABLE azure_subscription AS SELECT '/subscriptions/a' AS id,'A' AS display_name UNION ALL SELECT '/subscriptions/b','B'")
        assert all(row[1]=='info' for row in db.execute(sql).fetchall())
    assert hashlib.sha256(sql.encode()).hexdigest()==PROOFS[query]['pinned_sql_sha256']


def test_all_manual_control_ids_questions_versions_and_current_provider_context_conserved():
    assert len(REVIEWS)==412 and len(PROOFS)==3
    for sid,r in REVIEWS.items():
        assert r['disposition']=='rejected' and r['native_checks']==[] and r['review_classification']=='manual_attestation'
        assert r['manual_requirement']['question'] and r['manual_requirement']['guidance']
        assert r['official_docs'] and r['source_review']['arguments']==[]
        assert r['source_review']['constant_source_status']=='info'
