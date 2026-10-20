"""Admission source integrity and transactional registry behavior, not cloud mocks."""
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import azure_final_native_admission_20261020 as admission


def inputs(tmp_path):
    directory = tmp_path / 'repo/peaso/checks'
    directory.mkdir(parents=True)
    source = directory / 'proposal.py'
    source.write_text('def evaluate(item, index):\n    return "UNKNOWN", {}\n')
    cases = {'azure.test.native_admission': {
        'pass': {}, 'pass_index': {}, 'fail': {}, 'fail_index': {},
        'unknown': {}, 'unknown_index': {},
    }}
    fixture = directory / 'fixtures.json'
    fixture.write_text(json.dumps(cases))
    receipt = {'schema_version': 1, 'new_check_ids': list(cases),
               'sources': [{'path': 'peaso/checks/proposal.py',
                            'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}],
               'fixtures': {'path': 'peaso/checks/fixtures.json',
                            'sha256': hashlib.sha256(fixture.read_bytes()).hexdigest()}}
    (directory / 'azure_final_native_admission_20261020.json').write_text(json.dumps(receipt))
    return directory, receipt, cases


@pytest.mark.parametrize('fault', ['source_drift', 'fixture_drift', 'source_escape', 'fixture_escape', 'incomplete'])
def test_unreviewed_or_incomplete_inputs_reject_before_admission(tmp_path, fault):
    directory, receipt, cases = inputs(tmp_path)
    before = tuple(CHECKS)
    if fault == 'source_drift':
        (directory / 'proposal.py').write_text('changed source')
    elif fault == 'fixture_drift':
        (directory / 'fixtures.json').write_text('{}')
    elif fault == 'source_escape':
        receipt['sources'][0]['path'] = '../unreviewed.py'
    elif fault == 'fixture_escape':
        receipt['fixtures']['path'] = '../unreviewed.json'
    else:
        del cases['azure.test.native_admission']['unknown_index']
        path = directory / 'fixtures.json'
        path.write_text(json.dumps(cases))
        receipt['fixtures']['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    (directory / 'azure_final_native_admission_20261020.json').write_text(json.dumps(receipt))
    with pytest.raises(RuntimeError):
        admission._reviewed_inputs(directory)
    assert tuple(CHECKS) == before


def test_reviewed_input_bytes_are_retained(tmp_path):
    directory, receipt, cases = inputs(tmp_path)
    assert admission._reviewed_inputs(directory) == (receipt, cases)


def declarations():
    def evaluate(item, index):
        return 'PASS', {'declaration': True}
    return [({'id': 'azure.test.native_admission_' + suffix, 'category': 'hardening',
              'kind': 'managed_hsm', 'title': 'Admission boundary test', 'severity': 'medium',
              'dependencies': ['managed_hsm'], 'remediation': 'Review the declaration.'}, evaluate)
            for suffix in ('first', 'second')]


def test_partial_registration_rolls_back_callbacks_fixtures_and_originals(monkeypatch):
    import peaso.checks as registry
    staged = declarations()
    cases = {row['id']: {'sentinel': 'staged'} for row, _ in staged}
    originals = {'before': object()}
    aks = SimpleNamespace(_ORIGINALS=originals)
    aks.install_successors = lambda: originals.update(added=object())
    monkeypatch.setattr(admission, '_reviewed_inputs', lambda: ({'new_check_ids': list(cases)}, cases))
    monkeypatch.setattr(admission, '_declarations', lambda: (aks, staged))
    register = registry.register

    def fail_second(ident, *args, **kwargs):
        if ident.endswith('second'):
            raise RuntimeError('simulated admission failure')
        return register(ident, *args, **kwargs)

    before = tuple(CHECKS)
    prior_originals = dict(originals)
    monkeypatch.setattr(registry, 'register', fail_second)
    with pytest.raises(RuntimeError, match='simulated admission failure'):
        admission.install()
    assert tuple(CHECKS) == before
    assert originals == prior_originals
    assert not set(cases).intersection(CASES)


def test_explicit_admission_is_idempotent_and_preserves_typed_verdict(monkeypatch):
    staged = declarations()
    cases = {row['id']: {'sentinel': 'staged'} for row, _ in staged}
    aks = SimpleNamespace(_ORIGINALS={}, install_successors=lambda: None)
    monkeypatch.setattr(admission, '_reviewed_inputs', lambda: ({'new_check_ids': list(cases)}, cases))
    monkeypatch.setattr(admission, '_declarations', lambda: (aks, staged))
    before = tuple(CHECKS)
    try:
        admission.install()
        once = tuple(CHECKS)
        admission.install()
        assert tuple(CHECKS) == once
        for metadata, _ in staged:
            check = next(check for check in CHECKS if check.id == metadata['id'])
            status, evidence = check.evaluate({}, {})
            assert status == 'PASS'
            assert evidence['native_declaration_id'] == metadata['id']
            assert evidence['native_declaration_satisfied'] is True
            assert evidence['effective_access'] == 'not_tested'
            assert CASES[metadata['id']] == deepcopy(cases[metadata['id']])
    finally:
        CHECKS[:] = before
        for ident in cases:
            CASES.pop(ident, None)
