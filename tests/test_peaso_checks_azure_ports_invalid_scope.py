"""Execute the pinned faulty contact scopes against independent two-subscription truth."""
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_invalid_scope.json').read_text())
PROOFS = {row['source_review']['query_id']: row['source_review'] for row in REVIEWS.values()}


def _verified_merge(row):
    """A corrected merge is legitimate only with a recorded same-requirement verification."""
    v = row.get('native_equivalence_verification')
    return bool(row.get('disposition') == 'merged' and row.get('review_classification') == 'corrected_native_merge' and v
                and v.get('verdict') == 'same_control_requirement' and v.get('target_native_checks') == row['native_checks'] and row['native_checks']
                and all(v.get(k) for k in ('resource', 'property', 'pass_condition', 'upstream_defect_only'))
                and row.get('upstream_defect', {}).get('reason'))


def _not_fake(row):
    """Unverified rows stay rejected with no native; verified rows are corrected merges."""
    return _verified_merge(row) or (row['disposition'] == 'rejected' and row['native_checks'] == [] and 'native_equivalence_verification' not in row)


def _cls(row):
    return row.get('upstream_defect', {}).get('classification') if row.get('review_classification') == 'corrected_native_merge' else row.get('review_classification')


def _sql(proof):
    sql = re.sub(r'^\s*\$\{.*?\}\s*$', '', proof['pinned_sql'], flags=re.M).replace('jsonb_array_length(', 'json_array_length(')
    sql = re.sub(r"(\w+)\s*@>\s*('(?:[^']*)')", r'json_contains(\1, \2::JSON)', sql)
    # PostgreSQL JSON aggregate with FILTER, represented by a typed DuckDB list
    # aggregate then JSON conversion; grouping/filter/limit/joins are unchanged.
    sql = re.sub(r'jsonb_agg\(email\)\s*filter\s*\((where [^\n]+)\)', r'to_json(list(email) filter (\1))', sql, flags=re.I)
    return sql


@pytest.mark.parametrize('query', PROOFS, ids=str)
def test_global_limit_one_produces_false_alarm_for_a_compliant_subscription(query):
    duckdb = pytest.importorskip('duckdb')
    with duckdb.connect(':memory:') as db:
        db.execute('CREATE TABLE azure_subscription(subscription_id VARCHAR)')
        db.execute("INSERT INTO azure_subscription VALUES ('sub-a'), ('sub-b')")
        db.execute('CREATE TABLE azure_security_center_contact(subscription_id VARCHAR, name VARCHAR, email VARCHAR, notifications_by_role JSON, notifications_sources JSON)')
        for subscription in ('sub-a', 'sub-b'):
            db.execute('INSERT INTO azure_security_center_contact VALUES (?, ?, ?, ?::JSON, ?::JSON)', [subscription, 'default', 'security@example.invalid', json.dumps({'state': 'On', 'roles': ['Owner']}), json.dumps([{'sourceType': 'Alert', 'minimalSeverity': 'High'}])])
        result = db.execute(_sql(PROOFS[query])).fetchall()
    assert len(result) == 2
    assert sorted(row[1] for row in result) == ['alarm', 'ok']
    assert PROOFS[query]['counterexample']['required_statuses'] == ['ok', 'ok']


def test_invalid_scope_adjudications_have_substantive_exclusive_source_proofs():
    claude = set(json.loads((ROOT / 'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS) == 24 and not set(REVIEWS) & claude
    assert len(PROOFS) == 3
    for review in REVIEWS.values():
        assert _not_fake(review)
        assert _cls(review) == 'invalid_predicate'
        assert review['source_review']['arguments'] == []
        assert 'limit 1' in review['source_review']['pinned_sql'].lower()
        assert review['official_docs']
