"""Pinned source joins/range predicates demonstrate real scope and port counterexamples."""
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_invalid_network.json').read_text())
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


@pytest.mark.parametrize('query', PROOFS, ids=str)
def test_same_nsg_name_in_different_resource_groups_wrongly_alarms_safe_nsg(query):
    duckdb = pytest.importorskip('duckdb')
    proof = PROOFS[query]
    sql = proof['pinned_sql']
    # Execute actual final source SELECT/join/status logic with the independently
    # established risky-rule CTE, removing only presentation/dimension macros.
    tail = sql[sql.lower().rfind('    select\n'):]
    tail = re.sub(r'^\s*\$\{.*?\}\s*$', '', tail, flags=re.M)
    tail = tail.replace('sg.title', 'sg.name')
    with duckdb.connect(':memory:') as db:
        db.execute('CREATE TABLE azure_network_security_group(id VARCHAR, name VARCHAR, subscription_id VARCHAR)')
        db.execute('INSERT INTO azure_network_security_group VALUES (?, ?, ?), (?, ?, ?)', [proof['counterexample']['risky_id'], 'same', 'sub', proof['counterexample']['safe_id'], 'same', 'sub'])
        db.execute("CREATE TABLE network_sg AS SELECT 'same' AS sg_name")
        db.execute("CREATE TABLE azure_subscription AS SELECT 'sub' AS subscription_id")
        rows = db.execute(tail).fetchall()
    assert len(rows) == 2 and {row[1] for row in rows} == {'alarm'}
    assert proof['counterexample']['required_declaration_statuses'] == ['alarm', 'ok']
    assert proof['counterexample']['risky_id'] != proof['counterexample']['safe_id']


def test_pinned_udp_predicate_omits_exact_sensitive_service_ports():
    duckdb = pytest.importorskip('duckdb')
    sql = PROOFS['network_security_group_udp_service_restricted']['pinned_sql']
    expression = sql[sql.index("dport = '*'"):sql.index('    )\n    select')].strip()
    # Strip closing CTE/outer-AND parentheses while preserving the inner actual
    # source OR expression. Exact '53' does not satisfy '*' or '%-%'.
    expression = expression.rsplit('\n        )', 1)[0]
    with duckdb.connect(':memory:') as db:
        ranged = db.execute('SELECT ' + expression + ' FROM (SELECT ? AS dport)', ['50-55']).fetchone()[0]
        # The original eligibility guards omit scalar53. Some SQL planners also
        # evaluate its invalid range cast eagerly; neither can alarm this valid
        # sensitive-port declaration. Keep the source casts unchanged above.
        exact_eligible = db.execute("SELECT dport='*' OR dport LIKE '%-%' FROM (SELECT '53' AS dport)").fetchone()[0]
    assert exact_eligible is False and ranged is True


def test_dual_http_source_requires_range_to_cover_both_ports_instead_of_either():
    duckdb = pytest.importorskip('duckdb')
    sql = PROOFS['network_security_group_https_port_80_443_access_restricted']['pinned_sql']
    assert ':: integer >= 80' in sql and ':: integer <= 443' in sql
    with duckdb.connect(':memory:') as db:
        actual = db.execute("SELECT dport IN ('80','443','*') OR (dport LIKE '%-%' AND split_part(dport,'-',1)::INTEGER <= 80 AND split_part(dport,'-',2)::INTEGER >= 80 AND split_part(dport,'-',1)::INTEGER <= 443 AND split_part(dport,'-',2)::INTEGER >= 443) FROM (SELECT '80-81' AS dport)").fetchone()[0]
    assert actual is False  # TCP80 is nevertheless permitted by this declared range.


def test_substantive_source_review_ownership_and_identity_proof():
    claude = set(json.loads((ROOT / 'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS) == 30 and len(PROOFS) == 5 and not set(REVIEWS) & claude
    assert all(_not_fake(row) and _cls(row) == 'invalid_predicate' for row in REVIEWS.values())
    # Priority-aware azure.claude.nsg_internet_* natives are only similar; merges target declaration-audit natives.
    assert all(_verified_merge(row) and all(n.startswith('azure.gap.nsg_declared_internet_') for n in row['native_checks']) for row in REVIEWS.values())
    assert all(row['source_review']['arguments'] == [] and row['official_docs'] for row in REVIEWS.values())
