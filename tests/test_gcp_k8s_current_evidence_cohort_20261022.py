"""Exact current native cohort over immutable provider evidence-review ledgers."""
from copy import deepcopy
import gzip
import hashlib
import inspect
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, CHECK_ALIASES
from peaso.checks.catalog import description_for
from peaso.finding_observation import evidence_summary


ROOT = Path(__file__).resolve().parents[1]
LABELS = ('pass', 'fail', 'unknown', 'missing', 'malformed', 'manual',
          'not_applicable', 'denied', 'empty')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False).encode())


def _cohort(provider):
    path = ROOT / f'docs/evidence-reviews/{provider}-current-native-successor-20261022.json'
    receipt = json.loads(path.read_text())
    assert receipt['schema_version'] == 1 and receipt['provider'] == provider
    return receipt


def _reconcile(provider, receipt, prior, current):
    added = set(receipt['added'])
    retired = set(receipt['retired_aliases'])
    assert added.isdisjoint(prior) and retired <= prior
    assert current == (prior - retired) | added
    assert len(prior) == receipt['prior_count']
    assert len(current) == receipt['current_count']
    assert {old: CHECK_ALIASES[old] for old in retired} == receipt['retired_aliases']
    assert set(receipt['retired_aliases'].values()) <= current


@pytest.mark.parametrize('provider,prior_count,added_count,retired_count,current_count', [
    ('gcp', 538, 23, 2, 559),
    ('k8s', 1016, 15, 0, 1031),
])
def test_all_current_ids_have_exact_immutable_predecessor_and_native_successor(
        provider, prior_count, added_count, retired_count, current_count):
    receipt = _cohort(provider)
    catalog_path = ROOT / receipt['native_catalog']
    assert sha(catalog_path.read_bytes()) == receipt['native_catalog_sha256']
    catalog = json.loads(gzip.decompress(catalog_path.read_bytes()))
    current_catalog = {cid for cid, kind in catalog['native_kinds'].items()
                       if kind[0] == provider}
    current_registry = {check.id for check in CHECKS if check.provider == provider}
    assert current_registry == current_catalog
    prior_path = ROOT / receipt['prior_ledger']
    assert sha(prior_path.read_bytes()) == receipt['prior_ledger_sha256']
    ledger = json.loads(prior_path.read_text())
    prior = set(ledger if provider == 'azure' else ledger['checks'])
    assert (len(prior), len(receipt['added']), len(receipt['retired_aliases']),
            len(current_catalog)) == (prior_count, added_count, retired_count, current_count)
    _reconcile(provider, receipt, prior, current_catalog)


@pytest.mark.parametrize('provider', ('gcp', 'k8s'))
def test_each_added_native_id_replays_pinned_source_description_and_witnesses(provider):
    receipt = _cohort(provider)
    checks = {check.id: check for check in CHECKS if check.provider == provider}
    catalog = json.loads(gzip.decompress((ROOT / receipt['native_catalog']).read_bytes()))
    for cid, row in receipt['added'].items():
        assert row['native_kind'] == catalog['native_kinds'][cid]
        assert digest(description_for(cid)) == row['description_sha256'], cid
        evaluator = inspect.unwrap(checks[cid].evaluate)
        source_path = Path(inspect.getsourcefile(evaluator)).resolve()
        assert source_path.relative_to(ROOT).as_posix() == row['evaluator_source'], cid
        assert sha(source_path.read_bytes()) == row['evaluator_source_sha256'], cid
        assert sha(inspect.getsource(evaluator).encode()) == row['evaluator_body_sha256'], cid
        case_path = ROOT / row['cases_source']
        assert sha(case_path.read_bytes()) == row['cases_source_sha256'], cid
        cases = json.loads(case_path.read_text())[cid]
        assert digest(cases) == row['case_sha256'], cid
        assert set(row['branches']) == set(cases) & set(LABELS), cid
        assert {'pass', 'fail'} <= set(row['branches']), cid
        for label, expected in row['branches'].items():
            item = deepcopy(cases[label])
            index = deepcopy(cases.get(label + '_index', cases.get('index', {})))
            status, evidence = checks[cid].evaluate(item, index)
            finding = {'provider': provider, 'check_id': cid,
                       'status': status, 'evidence': evidence}
            observation = evidence_summary(finding)
            assert status == expected['status'], (cid, label, status)
            assert digest(evidence) == expected['evidence_sha256'], (cid, label)
            native_text = (observation if expected['native_text_field'] == 'public_observation'
                           else evidence[expected['native_text_field']])
            assert isinstance(native_text, str) and native_text.strip(), (cid, label)
            assert sha(native_text.encode()) == expected['native_text_sha256'], (cid, label)
            assert (sha(observation.encode()) if observation is not None else None) == \
                expected['observation_sha256'], (cid, label)


@pytest.mark.parametrize('provider', ('gcp', 'k8s'))
def test_missing_or_tampered_successor_id_cannot_reconcile(provider):
    receipt = _cohort(provider)
    prior_ledger = json.loads((ROOT / receipt['prior_ledger']).read_text())
    prior = set(prior_ledger if provider == 'azure' else prior_ledger['checks'])
    current = {check.id for check in CHECKS if check.provider == provider}
    missing = deepcopy(receipt)
    missing['added'].pop(next(iter(missing['added'])))
    with pytest.raises(AssertionError):
        _reconcile(provider, missing, prior, current)
    tampered = deepcopy(receipt)
    tampered['retired_aliases']['invented.retired.alias'] = next(iter(current))
    with pytest.raises(AssertionError):
        _reconcile(provider, tampered, prior, current)


def test_gcp_cross_project_proxy_absence_keeps_unknown_verdict():
    rows = _cohort('gcp')['added']
    for cid in ('gcp.network.http_proxy_forwarding_rule_reference',
                'gcp.network.https_proxy_forwarding_rule_reference'):
        assert rows[cid]['branches']['fail']['status'] == 'UNKNOWN'
