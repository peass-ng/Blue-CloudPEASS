"""Production source/callable/collision/rollback gates; no live authentication."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import shutil
import types

import pytest
from peaso import checks
from peaso.checks import fixtures
from peaso.checks import azure_nsp_query_cmk_production_tde_successor_20261020 as admission
from peaso.collectors import azure
from tests.test_azure_nsp_query_cmk_production_20261020 import offline


def isolate(monkeypatch):
    monkeypatch.setattr(checks, 'CHECKS', [c for c in checks.CHECKS if c.id not in admission.IDS])
    monkeypatch.setattr(fixtures, 'CASES', {key: value for key, value in fixtures.CASES.items() if key not in admission.IDS})
    monkeypatch.setattr(admission, '_INSTALLED', {})


def test_installed_exactly_once_and_idempotent():
    before = tuple(checks.CHECKS)
    receipt, cases, declarations = admission.reviewed_inputs()
    admission.install();admission.install()
    assert tuple(checks.CHECKS) == before
    for spec, function in declarations:
        rows = [c for c in checks.CHECKS if c.id == spec['id']]
        assert len(rows) == 1 and rows[0].evaluate.__wrapped__ is function
        assert rows[0].dependencies == [spec['kind'], 'subscription']
        assert fixtures.CASES[spec['id']] == cases[spec['id']]
        assert admission.proof._metadata(rows[0]) == receipt['metadata'][spec['id']]


@pytest.mark.parametrize('stage', ['second_registration', 'second_fixture'])
def test_second_failure_rolls_back_checks_cases_and_admission(monkeypatch, stage):
    isolate(monkeypatch)
    before = tuple(checks.CHECKS);before_cases = dict(fixtures.CASES)
    if stage == 'second_registration':
        class FailingList(list):
            def append(self, value):
                if value.id == admission.IDS[1]: raise RuntimeError('injected second registration')
                super().append(value)
        monkeypatch.setattr(checks, 'CHECKS', FailingList(checks.CHECKS))
    else:
        class FailingCases(dict):
            def __setitem__(self, key, value):
                if key == admission.IDS[1]: raise RuntimeError('injected second fixture')
                super().__setitem__(key, value)
        monkeypatch.setattr(fixtures, 'CASES', FailingCases(fixtures.CASES))
    with pytest.raises(RuntimeError, match='injected second'): admission.install()
    assert tuple(checks.CHECKS) == before and fixtures.CASES == before_cases and admission._INSTALLED == {}


@pytest.mark.parametrize('which', ['partial_check', 'duplicate_check', 'cases', 'alias', 'kind', 'endpoint'])
def test_namespace_collision_is_not_replaced(monkeypatch, which):
    installed = next(c for c in checks.CHECKS if c.id == admission.IDS[0])
    isolate(monkeypatch)
    if which == 'partial_check': checks.CHECKS.append(installed)
    if which == 'duplicate_check': checks.CHECKS.extend([installed, installed])
    if which == 'cases': fixtures.CASES[admission.IDS[0]] = {'original': 'preserve'}
    if which == 'alias': monkeypatch.setattr(checks, 'CHECK_ALIASES', {**checks.CHECK_ALIASES, 'unrelated': admission.IDS[0]})
    if which == 'kind': monkeypatch.setattr(azure, 'TYPES', azure.TYPES + (admission.producer.KINDS[0],))
    if which == 'endpoint': monkeypatch.setitem(azure.ENDPOINTS, admission.producer.KINDS[0], ('Microsoft.Network', 'unreviewed'))
    before = tuple(checks.CHECKS);old_cases = dict(fixtures.CASES)
    with pytest.raises(RuntimeError): admission.install()
    assert tuple(checks.CHECKS) == before and fixtures.CASES == old_cases


@pytest.mark.parametrize('which', ['title', 'kind', 'dependencies', 'boolean_type', 'safe_code', 'checked_code', 'safe_copy', 'leaf_cell', 'case'])
def test_installed_metadata_closure_code_or_cases_drift_rejected(monkeypatch, which):
    cid = admission.IDS[0];position = next(i for i,c in enumerate(checks.CHECKS) if c.id == cid)
    original = checks.CHECKS[position];safe = original.evaluate;checked = admission.proof._bindings(safe)['checked']
    monkeypatch.setattr(checks, 'CHECKS', list(checks.CHECKS))
    if which in ('title', 'kind', 'dependencies', 'boolean_type'):
        fields = {'title': {'title': 'foreign'}, 'kind': {'kind': 'foreign'},
                  'dependencies': {'declared_dependencies': ('foreign',)}, 'boolean_type': {'allow_incomplete_failure': 0}}
        checks.CHECKS[position] = replace(original, **fields[which])
    if which in ('safe_code', 'checked_code'):
        fn = safe if which == 'safe_code' else checked
        freevars = len(fn.__code__.co_freevars)
        # Compile a replacement with exactly the same closure arity.
        source = 'def factory():\n' + ''.join(f' x{i}=None\n' for i in range(freevars)) + ' def replacement(*a, **k):\n  return (' + ','.join(f'x{i}' for i in range(freevars)) + ',)\n return replacement\n'
        namespace = {};exec(source, namespace)
        monkeypatch.setattr(fn, '__code__', namespace['factory']().__code__)
    if which == 'safe_copy':
        clone = types.FunctionType(safe.__code__, safe.__globals__, safe.__name__, safe.__defaults__, safe.__closure__)
        clone.__dict__.update(safe.__dict__);clone.__qualname__ = safe.__qualname__
        checks.CHECKS[position] = replace(original, evaluate=clone)
    if which == 'leaf_cell':
        cell = checked.__closure__[0];old = cell.cell_contents
        monkeypatch.setattr(cell, 'cell_contents', lambda *a: ('PASS', {}))
    if which == 'case':
        monkeypatch.setattr(fixtures, 'CASES', deepcopy(fixtures.CASES));fixtures.CASES[cid]['pass'].clear()
    with pytest.raises(RuntimeError): admission.install()


@pytest.mark.parametrize('which', ['collect', 'selected', 'helper'])
@pytest.mark.parametrize('change', ['replacement', 'code'])
def test_shared_or_admission_executing_callable_guard(monkeypatch, which, change):
    owner = azure if which != 'helper' else admission
    name = {'collect': 'collect', 'selected': '_selected', 'helper': '_verify'}[which]
    fn = getattr(owner, name)
    if change == 'replacement':
        clone = types.FunctionType(fn.__code__, fn.__globals__, fn.__name__, fn.__defaults__, fn.__closure__)
        clone.__kwdefaults__ = fn.__kwdefaults__;clone.__qualname__ = fn.__qualname__
        monkeypatch.setattr(owner, name, clone)
    else:
        # Keep valid source coordinates so this reaches the executable-code
        # guard rather than an unrelated parser error from an indented lambda.
        literal = {'collect': 'azure', 'selected': 'subscription', 'helper': 'checked'}[which]
        constants = list(fn.__code__.co_consts)
        constants[constants.index(literal)] = 'unreviewed-code-constant'
        monkeypatch.setattr(fn, '__code__', fn.__code__.replace(co_consts=tuple(constants)))
    with pytest.raises(RuntimeError): admission.install()


def copy_inputs(tmp_path):
    root = Path(__file__).resolve().parents[1]
    paths = set()
    for helper in (admission.prepared.predecessor, admission.prepared, admission):
        relative = 'peaso/checks/' + helper.RECEIPT
        receipt = json.loads((root / relative).read_bytes())
        paths.add(relative);paths.update(receipt.get('sources', {}));paths.add(receipt['helper_path'])
        paths.update(row['path'] for row in receipt['functions'].values())
        paths.update(row['path'] for row in receipt['fixtures'])
        paths.update(receipt.get('predecessor_files', {}))
        if 'predecessor_pack' in receipt:
            paths.add(receipt['predecessor_pack']['path'])
    for relative in paths:
        target = tmp_path / relative;target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, target)
    # Every tamper starts from a complete, admitted copy; a missing historical
    # input must not masquerade as rejection of the intended mutation.
    assert admission.reviewed_inputs(tmp_path)[2]
    return root


@pytest.mark.parametrize('which', ['receipt', 'helper', 'cases', 'fixture', 'collect', 'selected'])
def test_disk_source_and_native_fixture_guard(tmp_path, which):
    copy_inputs(tmp_path)
    receipt = json.loads((tmp_path / 'peaso/checks' / admission.RECEIPT).read_bytes())
    paths = {'receipt': 'peaso/checks/' + admission.RECEIPT,
             'helper': receipt['helper_path'],
             'cases': 'peaso/checks/' + admission.CASES_FILE,
             'fixture': next(row['path'] for row in receipt['fixtures'] if row['path'].endswith('.gz')),
             'collect': 'peaso/collectors/azure.py', 'selected': 'peaso/collectors/azure.py'}
    path = tmp_path / paths[which]
    if which in ('collect', 'selected'):
        text = path.read_text();needle = ('    """Return native facts with separate directory, inheritance and usage coverage."""' if which == 'collect' else '    selected = set(wanted)')
        path.write_text(text.replace(needle, needle + '\n    # unreviewed exact callable delta', 1))
    else:
        with path.open('ab') as stream: stream.write(b'\n')
    with pytest.raises(RuntimeError): admission.reviewed_inputs(tmp_path)


def test_unrelated_surrounding_source_is_extensible(tmp_path):
    copy_inputs(tmp_path)
    with (tmp_path / 'peaso/collectors/azure.py').open('a') as stream: stream.write('\n# unrelated reviewed parallel module addition\n')
    assert admission.reviewed_inputs(tmp_path)[2]
