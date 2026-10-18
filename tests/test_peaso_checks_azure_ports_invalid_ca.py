"""Exact pinned CA grant/population predicates cannot establish enabled MFA."""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_invalid_ca.json').read_text())
PROOFS = {r['source_review']['query_id']: r['source_review'] for r in REVIEWS.values()}


@pytest.mark.parametrize('query', PROOFS)
def test_disabled_mfa_policy_satisfies_pinned_grant_test_without_enforcement(query):
    duckdb = pytest.importorskip('duckdb')
    proof = PROOFS[query]; sql = proof['pinned_sql']
    assert 'state' not in sql
    with duckdb.connect(':memory:') as db:
        declares = db.execute("SELECT json_contains(?::JSON, '[\"mfa\"]'::JSON)", [json.dumps(proof['counterexample']['grantControls']['builtInControls'])]).fetchone()[0]
    assert declares is True and proof['counterexample']['state'] == 'disabled'
    assert proof['counterexample']['source_status'] == 'ok'
    if query.endswith('for_administrators'):
        assert 'from\n      distinct_tenant as t,\n      azuread_conditional_access_policy as p' in sql
    if query == 'ad_all_user_mfa_enabled':
        assert "includeRoles" in sql and "includeUsers" not in sql
        assert proof['counterexample']['conditions']['users']['includeUsers'] == []


def test_all_ten_exact_owned_rows_have_actual_mfa_condition_fault_evidence():
    claude = set(json.loads((ROOT / 'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS) == 10 and len(PROOFS) == 3 and not set(REVIEWS) & claude
    assert all(r['disposition'] == 'rejected' and r['review_classification'] == 'invalid_predicate' and r['native_checks'] == [] for r in REVIEWS.values())
    assert all(r['source_review']['arguments'] == [] and r['official_docs'] for r in REVIEWS.values())
