"""Prepared successor source/closure/fixture guard, no installation hook."""
from copy import deepcopy
import json
from pathlib import Path
import shutil

import pytest
from peaso import checks
from peaso.checks import azure_nsp_query_cmk_runtime_admission_20261020 as admission
from tests.test_azure_nsp_query_cmk_runtime_20261020 import offline_successor_bridge


def test_prepared_inputs_preserve_registry_and_real_native_cases():
    before = tuple(checks.CHECKS)
    receipt, cases, declarations = admission.reviewed_inputs()
    assert receipt['prepared'] is True and receipt['registry_hook'] is False
    assert tuple(checks.CHECKS) == before and not hasattr(admission, 'install')
    for spec, function in declarations:
        assert spec['dependencies'] == [spec['kind'], 'subscription']
        for branch in ('pass', 'fail', 'unknown'):
            assert function(cases[spec['id']][branch], cases[spec['id']][branch + '_index'])[0] == branch.upper()
    cases[declarations[0][0]['id']]['pass'].clear()
    assert admission.reviewed_inputs()[1][declarations[0][0]['id']]['pass']


@pytest.mark.parametrize('which', ['source', 'consumer', 'receipt', 'cases', 'native_fixture'])
def test_prepared_source_or_fixture_drift_rejected(tmp_path, which):
    root = Path(__file__).resolve().parents[1]
    prior = json.loads((root / 'peaso/checks' / admission.predecessor.RECEIPT).read_bytes())
    current = json.loads((root / 'peaso/checks' / admission.RECEIPT).read_bytes())
    paths = set(prior['sources']) | {row['path'] for row in prior['fixtures']} | {
        row['path'] for row in prior['functions'].values()} | set(current['sources']) | {
        row['path'] for row in current['fixtures']} | {'peaso/checks/' + admission.predecessor.RECEIPT,
                                                   'peaso/checks/' + admission.RECEIPT}
    for relative in paths:
        path = tmp_path / relative;path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, path)
    targets = {'source': 'peaso/collectors/azure_nsp_query_cmk_runtime_20261020.py',
               'consumer': 'peaso/checks/azure_nsp_query_cmk_runtime_review_20261020.py',
               'receipt': 'peaso/checks/' + admission.RECEIPT,
               'cases': current['fixtures'][0]['path'], 'native_fixture': current['fixtures'][1]['path']}
    with (tmp_path / targets[which]).open('ab') as stream: stream.write(b'\n')
    with pytest.raises(RuntimeError): admission.reviewed_inputs(tmp_path)


@pytest.mark.parametrize('which', ['constructor', 'request', 'consumer', 'helper', 'version'])
def test_runtime_successor_replacement_or_schema_drift_rejected(monkeypatch, which):
    if which == 'constructor': monkeypatch.setattr(admission.producer.ParentCapture, '__init__', lambda *a, **kw: None)
    if which == 'request': monkeypatch.setattr(admission.producer.ParentCapture, 'request', lambda *a, **kw: ({}, {}))
    if which == 'consumer': monkeypatch.setattr(admission.candidate, 'nsp', lambda *a: ('PASS', {}))
    if which == 'helper': monkeypatch.setattr(admission.producer, 'subscription_receipt', lambda *a: {})
    if which == 'version': monkeypatch.setattr(admission.producer, 'SUBSCRIPTION_VERSION', '2099-01-01')
    with pytest.raises(RuntimeError): admission.reviewed_inputs()


def test_successor_does_not_rewrite_original_declarations_or_case_sources():
    assert all(d['dependencies'] == [d['kind']] for d in admission.predecessor.candidate.DECLARATIONS)
    original_receipt, cases, declarations = admission.predecessor.reviewed_inputs()
    assert original_receipt['ids'] == list(admission.candidate.IDS)
    assert all(spec['dependencies'] == [spec['kind']] for spec, _ in declarations)
    assert admission.producer.ParentCapture.__bases__ == (admission.producer.native.Capture,)
