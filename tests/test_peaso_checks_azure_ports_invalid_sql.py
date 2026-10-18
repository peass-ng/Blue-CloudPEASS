"""Substantive SQL source measurement counterexamples; no fake support wrappers."""
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_invalid_sql.json').read_text())
PROOFS = {r['source_review']['query_id']: r['source_review'] for r in REVIEWS.values()}


def test_enabled_threat_detection_does_not_establish_va_configuration():
    duckdb = pytest.importorskip('duckdb')
    proof = PROOFS['sql_server_and_databases_va_enabled']
    case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s*=", r'(\1) =', proof['status_case_sql'])
    example = proof['counterexample']
    with duckdb.connect(':memory:') as db:
        status = db.execute('SELECT ' + case + ' FROM (SELECT ?::JSON AS security, ?::JSON AS assessment)', [json.dumps(example['security']), json.dumps(example['assessment'])]).fetchone()[0]
    assert status == 'ok' and example['expressVulnerabilityAssessment']['properties']['state'] == 'Disabled'
    assert 'assessment' not in case


def test_all_alerts_query_alarms_empty_disabled_types_and_passes_disabled_policy():
    duckdb = pytest.importorskip('duckdb')
    sql = PROOFS['sql_server_threat_detection_all_enabled']['pinned_sql']
    assert 'not (p ->' in sql and 'disabledAlerts' in sql and "'[\"\"]'" in sql
    with duckdb.connect(':memory:') as db:
        empty_list_bad, empty_string_bad = [db.execute("SELECT NOT ((p -> 'properties' -> 'disabledAlerts') = '[\"\"]'::JSON) FROM (SELECT ?::JSON AS p)", [json.dumps({'properties': {'state': state, 'disabledAlerts': alerts}})]).fetchone()[0] for state, alerts in [('Enabled', []), ('Disabled', [''])]]
    assert empty_list_bad is True and empty_string_bad is False
    assert 'state' not in sql


def test_only_exact_owned_five_refs_are_rejected_for_actual_condition_defects():
    claude = set(json.loads((ROOT / 'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS) == 5 and len(PROOFS) == 2 and not set(REVIEWS) & claude
    assert all(r['disposition'] == 'rejected' and r['review_classification'] == 'invalid_predicate' and r['native_checks'] == [] for r in REVIEWS.values())
    assert all(r['source_review']['arguments'] == [] and r['source_review']['counterexample'] for r in REVIEWS.values())
