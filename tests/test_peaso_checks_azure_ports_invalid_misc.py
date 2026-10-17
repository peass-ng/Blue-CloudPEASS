"""Wrong WAF/path/public-access source predicates have real provider counterexamples."""
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_invalid_misc.json').read_text())
PROOFS = {r['source_review']['query_id']: r['source_review'] for r in REVIEWS.values()}


@pytest.mark.parametrize('query', PROOFS)
def test_executed_source_case_misclassifies_provider_configuration(query):
    duckdb = pytest.importorskip('duckdb')
    proof = PROOFS[query]
    case = proof['status_case_sql'].replace('::json', '')
    case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s*(in|is\s+not\s+null|=)", r'(\1) \2', case, flags=re.I)
    example = proof['counterexample']
    if query.startswith('application_insights'):
        cols = {'type': example['type'], 'public_network_access_for_ingestion': example['publicNetworkAccessForIngestion'], 'public_network_access_for_query': example['publicNetworkAccessForQuery']}
    else: cols = {'web_application_firewall_configuration': example['webApplicationFirewallConfiguration']}
    defs, values = [], []
    for name, value in cols.items():
        defs.append('?' + ('::JSON' if isinstance(value, dict) else '') + ' AS ' + name)
        values.append(json.dumps(value) if isinstance(value, dict) else value)
    with duckdb.connect(':memory:') as db:
        assert db.execute('SELECT ' + case + ' FROM (SELECT ' + ','.join(defs) + ')', values).fetchone()[0] == example['source_status']


def test_four_defective_owned_refs_have_specific_source_field_evidence():
    claude = set(json.loads((ROOT / 'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS) == 4 and len(PROOFS) == 3 and not set(REVIEWS) & claude
    assert all(r['disposition'] == 'rejected' and r['native_checks'] == [] and r['source_review']['counterexample'] for r in REVIEWS.values())
