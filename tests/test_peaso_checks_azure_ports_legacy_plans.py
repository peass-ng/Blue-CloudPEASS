"""Legacy pricing applicability and exact source selector proofs, native-only."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_legacy_plans as ports
from peaso.checks.fixtures import CASES
from peaso.checks.azure_ports_defender import _fixture

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_legacy_plans.json').read_text())
REGISTRY = {check.id: check for check in CHECKS}


@pytest.mark.parametrize('cid', ports.CHECK_IDS, ids=str)
def test_legacy_plan_observed_standard_free_and_uncertain_absence(cid):
    check = REGISTRY[cid]
    for label, desired in (('pass', 'PASS'), ('fail', 'FAIL')):
        fixture = CASES[cid]
        item, index = copy.deepcopy(fixture[label]), copy.deepcopy(fixture[label + '_index'])
        before = copy.deepcopy((item, index))
        assert check.evaluate(item, index)[0] == desired
        assert (item, index) == before
    for status in ('empty', 'denied', 'partial', 'malformed'):
        assert check.evaluate({'scope': '/subscriptions/sub'}, _fixture('security_pricing', [], status))[0] == 'UNKNOWN'
    assert check.evaluate({'scope': '/tenants/tenant'}, {})[0] == 'NOT_APPLICABLE'
    index = copy.deepcopy(CASES[cid]['pass_index'])
    index['security_pricing'].append(copy.deepcopy(index['security_pricing'][0]))
    assert check.evaluate({'scope': '/subscriptions/sub'}, index)[0] == 'UNKNOWN'
    index['security_pricing'].pop()
    row = index['security_pricing'][0]['data']
    row['id'] = row['id'].replace('/sub/', '/foreign/')
    assert check.evaluate({'scope': '/subscriptions/sub'}, index)[0] == 'UNKNOWN'
    row['id'] = row['id'].replace('/foreign/', '/sub/')
    row['properties']['pricingTier'] = 'FutureTier'
    assert check.evaluate({'scope': '/subscriptions/sub'}, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('query', ports.SOURCE_QUERIES, ids=str)
def test_pinned_plan_case_and_selector_are_conserved(query):
    duckdb = pytest.importorskip('duckdb')
    proof = next(row['source_review'] for row in REVIEWS.values() if row['source_review']['query_id'] == query)
    case = re.sub(r'\b[a-z_]+\.(\w+)\b', r'\1', proof['status_case_sql'])
    for tier, expected in (('Standard', 'ok'), ('Free', 'alarm')):
        with duckdb.connect(':memory:') as db:
            assert db.execute('SELECT ' + case + ' FROM (SELECT ? AS pricing_tier, ? AS name)', [tier, proof['pricing_plan']]).fetchone()[0] == expected
    assert "name = '" + proof['pricing_plan'] + "'" in proof['pinned_sql']


def test_legacy_mapping_ownership_and_no_replacement_substitution():
    claude = set(json.loads((ROOT / 'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS) == 17 and not set(REVIEWS) & claude
    assert all(row['source_review']['arguments'] == [] for row in REVIEWS.values())
    assert all('obsolete_definition' != row.get('review_classification') for row in REVIEWS.values())
    for query in ports.PLANS:
        assert ports.SOURCE_QUERIES[query] == 'azure.port.' + query
