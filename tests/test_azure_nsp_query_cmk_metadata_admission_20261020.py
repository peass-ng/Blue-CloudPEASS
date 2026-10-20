"""Uninstalled two-control admission: native branches, tamper and rollback."""
from copy import deepcopy
from tests.shared_admission_epoch_compatibility_20261020 import snapshot_cases, active_shared, source_at_epoch, sealed_ast
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import socket
import types

import pytest
from peaso import checks
from peaso.checks import fixtures
from peaso.checks import azure_nsp_query_cmk_metadata_admission_20261020 as admission
from peaso.checks import azure_nsp_query_cmk_metadata_proposal_20261020 as candidate
from peaso.collectors import azure
from peaso.collectors import azure_nsp_query_cmk_metadata_proposal_20261020 as producer
from tests.test_azure_nsp_query_cmk_metadata_proposal_20261020 import NativeHTTP, capture, nsp_mode, query_mode


@pytest.fixture(autouse=True)
def offline_isolated_registry(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network, DNS and authentication forbidden')
    for owner, names in ((socket, ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex')),
                         (socket.socket, ('connect', 'connect_ex', 'sendto')), (azure, ('credential_for',))):
        for name in names:
            monkeypatch.setattr(owner, name, blocked)
    registry, case_store = checks.CHECKS, fixtures.CASES
    before = list(registry)
    old_cases = {cid: deepcopy(case_store[cid]) for cid in admission.IDS if cid in case_store}
    old_installed = dict(admission._INSTALLED)
    registry[:] = [c for c in registry if c.id not in admission.IDS]
    for cid in admission.IDS: case_store.pop(cid, None)
    admission._INSTALLED.clear()
    yield
    registry[:] = before
    checks.CHECKS = registry
    fixtures.CASES = case_store
    admission._INSTALLED.clear();admission._INSTALLED.update(old_installed)
    for cid in admission.IDS:
        if cid in old_cases: case_store[cid] = old_cases[cid]
        else: case_store.pop(cid, None)


def copy_reviewed_inputs(tmp_path):
    root = Path(__file__).resolve().parents[1]
    receipt = json.loads((root / 'peaso/checks' / admission.RECEIPT).read_bytes())
    paths = set(receipt['sources']) | {f['path'] for f in receipt['fixtures']} | {
        row['path'] for row in receipt['functions'].values()} | {'peaso/checks/' + admission.RECEIPT}
    for name in paths:
        path = tmp_path / name;path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, path)
    return receipt


def test_reviewed_inputs_are_unregistered_and_fresh():
    before = tuple(checks.CHECKS)
    receipt, cases, declarations = admission.reviewed_inputs()
    assert tuple(checks.CHECKS) == before
    assert [d['id'] for d, _ in declarations] == list(admission.IDS)
    assert len(receipt['functions']) >= 40 and set(cases) == set(admission.IDS)
    cases[admission.IDS[0]]['pass'].clear()
    assert admission.reviewed_inputs()[1][admission.IDS[0]]['pass']
    assert all(azure.TYPES.count(kind) == 1 for kind in producer.KINDS)


@pytest.mark.parametrize('kind,mode,want', [
    (producer.NSP_KIND, 'enforced', 'PASS'), (producer.NSP_KIND, 'learning', 'FAIL'),
    (producer.NSP_KIND, 'transition', 'UNKNOWN'), (producer.NSP_KIND, 'profile_denied', 'DENIED'),
    (producer.NSP_KIND, 'association_partial', 'UNKNOWN'),
    (producer.QUERY_KIND, 'cmk', 'PASS'), (producer.QUERY_KIND, 'provider', 'FAIL'),
    (producer.QUERY_KIND, 'table_key_missing', 'UNKNOWN'), (producer.QUERY_KIND, 'no_links', 'NOT_APPLICABLE'),
    (producer.QUERY_KIND, 'denied_storage', 'DENIED'), (producer.QUERY_KIND, 'partial_links', 'UNKNOWN'),
    (producer.QUERY_KIND, 'table_service_key', 'FAIL'),
])
def test_explicit_atomic_install_actual_http_to_public_engine(monkeypatch, kind, mode, want):
    admission.install()
    http = NativeHTTP();(nsp_mode if kind == producer.NSP_KIND else query_mode)(http, mode)
    actual, _, findings = capture(monkeypatch, http, kind)
    assert actual == {want}, findings


def test_install_twice_is_atomic_and_idempotent():
    before = tuple(checks.CHECKS)
    admission.install();installed = tuple(checks.CHECKS)
    admission.install()
    assert tuple(checks.CHECKS) == installed and installed[:len(before)] == before
    assert [c.id for c in installed[len(before):]] == list(admission.IDS)
    assert set(admission._INSTALLED) == set(admission.IDS)


@pytest.mark.parametrize('which', ['source', 'helper', 'fixture', 'native_fixture', 'proposal', 'receipt'])
def test_disk_source_fixture_receipt_drift_rejected(tmp_path, which):
    receipt = copy_reviewed_inputs(tmp_path)
    names = {'source': 'peaso/collectors/azure_nsp_query_cmk_metadata_proposal_20261020.py',
             'helper': receipt['helper_path'], 'fixture': receipt['fixtures'][0]['path'],
             'native_fixture': receipt['fixtures'][1]['path'], 'proposal': receipt['fixtures'][2]['path'],
             'receipt': 'peaso/checks/' + admission.RECEIPT}
    with (tmp_path / names[which]).open('ab') as stream: stream.write(b'\n')
    with pytest.raises(RuntimeError): admission.reviewed_inputs(tmp_path)


def test_shared_surrounding_source_can_change_without_whole_module_repin(tmp_path):
    copy_reviewed_inputs(tmp_path)
    path = tmp_path / 'peaso/collectors/azure.py'
    with path.open('a') as stream: stream.write('\ndef unrelated_metadata_integration_extension():\n    return None\n')
    admission.reviewed_inputs(tmp_path)


@pytest.mark.parametrize('target', ['strict_request', 'capture_full', 'predicate', 'consumer_helper', 'reader', 'token', 'register'])
def test_runtime_callable_replacement_rejected_even_with_copied_code(monkeypatch, target):
    owners = {'strict_request': (producer, 'metadata_get'), 'capture_full': (producer.Capture, 'full'),
              'predicate': (candidate, 'nsp'), 'consumer_helper': (candidate, '_bound'),
              'reader': (azure._Reader, 'call'), 'token': (azure.AzureTransport, 'token'), 'register': (checks, 'register')}
    owner, name = owners[target];original = getattr(owner, name)
    copy = types.FunctionType(original.__code__, original.__globals__, original.__name__, original.__defaults__, original.__closure__)
    copy.__module__ = original.__module__;copy.__qualname__ = original.__qualname__
    copy.__kwdefaults__ = original.__kwdefaults__
    monkeypatch.setattr(owner, name, copy)
    with pytest.raises(RuntimeError, match='replacement'): admission.reviewed_inputs()


@pytest.mark.parametrize('target', ['predicate', 'strict_request', 'reader'])
def test_same_function_in_memory_code_replacement_rejected(monkeypatch, target):
    function = {'predicate': candidate.nsp, 'strict_request': producer.metadata_get, 'reader': azure._Reader.call}[target]
    changed = function.__code__.replace(co_consts=tuple('tampered_constant' if value is None else value for value in function.__code__.co_consts))
    monkeypatch.setattr(function, '__code__', changed)
    with pytest.raises(RuntimeError, match='executing code'): admission.reviewed_inputs()


@pytest.mark.parametrize('field', ['title', 'kind', 'dependencies', 'severity'])
def test_declaration_metadata_drift_rejected(monkeypatch, field):
    changed = deepcopy(candidate.DECLARATIONS)
    changed[0][field] = ['other_kind'] if field == 'dependencies' else 'unreviewed'
    monkeypatch.setattr(candidate, 'DECLARATIONS', changed)
    with pytest.raises(RuntimeError, match='schema'): admission.reviewed_inputs()


@pytest.mark.parametrize('target', ['kind', 'limit', 'module_alias', 'class'])
def test_runtime_schema_and_helper_identity_drift_rejected(monkeypatch, target):
    if target == 'kind': monkeypatch.setattr(producer, 'NSP_KIND', 'foreign_kind')
    if target == 'limit': monkeypatch.setattr(producer, 'MAX_BYTES', 1048576)
    if target == 'module_alias': monkeypatch.setattr(candidate, 'native', types.SimpleNamespace())
    if target == 'class':
        replacement = type('Capture', producer.Capture.__bases__, dict(vars(producer.Capture)))
        monkeypatch.setattr(producer, 'Capture', replacement)
    with pytest.raises(RuntimeError): admission.reviewed_inputs()


@pytest.mark.parametrize('field', ['title', 'control', 'kind', 'allow_incomplete_failure'])
def test_registered_metadata_drift_rejected(monkeypatch, field):
    admission.install();installed = list(checks.CHECKS)
    selected = next(c for c in installed if c.id == admission.IDS[0])
    value = True if field == 'allow_incomplete_failure' else 'unreviewed'
    installed[installed.index(selected)] = replace(selected, **{field: value})
    monkeypatch.setattr(checks, 'CHECKS', installed)
    with pytest.raises(RuntimeError, match='declaration'): admission.install()
    assert checks.CHECKS == installed


@pytest.mark.parametrize('which', ['safe_code', 'checked_code', 'safe_object', 'checked_leaf', 'cases'])
def test_registered_wrapper_code_closure_and_fixture_drift_rejected(monkeypatch, which):
    admission.install();check = next(c for c in checks.CHECKS if c.id == admission.IDS[0])
    safe = check.evaluate;checked = admission._bindings(safe)['checked']
    if which in ('safe_code', 'checked_code'):
        function = safe if which == 'safe_code' else checked
        monkeypatch.setattr(function, '__code__', function.__code__.replace(co_consts=function.__code__.co_consts + ('tampered',)))
    if which == 'safe_object':
        copied = types.FunctionType(safe.__code__, safe.__globals__, safe.__name__, safe.__defaults__, safe.__closure__)
        copied.__dict__.update(safe.__dict__);copied.__qualname__ = safe.__qualname__
        checks.CHECKS[checks.CHECKS.index(check)] = replace(check, evaluate=copied)
    if which == 'checked_leaf':
        cell = checked.__closure__[0];original = cell.cell_contents;cell.cell_contents = candidate.query
        try:
            with pytest.raises(RuntimeError, match='binding'): admission.install()
        finally: cell.cell_contents = original
        return
    if which == 'cases': fixtures.CASES[check.id]['pass'] = {}
    with pytest.raises(RuntimeError): admission.install()


@pytest.mark.parametrize('which', ['alias', 'partial_check', 'duplicate_check', 'cases', 'kind_endpoint'])
def test_registration_namespace_collision_rejected_without_changes(monkeypatch, which):
    if which == 'alias': monkeypatch.setitem(checks.CHECK_ALIASES, admission.IDS[0], 'existing.survivor')
    if which in ('partial_check', 'duplicate_check'):
        admission.install()
        if which == 'partial_check': checks.CHECKS[:] = [c for c in checks.CHECKS if c.id != admission.IDS[1]]
        else: checks.CHECKS.append(next(c for c in checks.CHECKS if c.id == admission.IDS[0]))
    if which == 'cases': fixtures.CASES[admission.IDS[0]] = {'unreviewed': True}
    if which == 'kind_endpoint': monkeypatch.setitem(azure.ENDPOINTS, producer.NSP_KIND, ('Microsoft.Example/items', '2026-01-01'))
    before = tuple(checks.CHECKS);old = deepcopy({cid: fixtures.CASES[cid] for cid in admission.IDS if cid in fixtures.CASES})
    with pytest.raises(RuntimeError, match='collision'): admission.install()
    assert tuple(checks.CHECKS) == before
    assert {cid: fixtures.CASES[cid] for cid in admission.IDS if cid in fixtures.CASES} == old


@pytest.mark.parametrize('stage', ['second_registration', 'second_fixture_write'])
def test_second_control_failure_rolls_back_both_checks_and_cases(monkeypatch, stage):
    before = tuple(checks.CHECKS);old = snapshot_cases(fixtures.CASES)
    if stage == 'second_registration':
        class FailSecondAppend(list):
            def append(self, item):
                if item.id == admission.IDS[1]: raise RuntimeError('injected second registration failure')
                return super().append(item)
        monkeypatch.setattr(checks, 'CHECKS', FailSecondAppend(checks.CHECKS))
    else:
        class FailSecondWrite(dict):
            def __setitem__(self, key, value):
                if key == admission.IDS[1]: raise RuntimeError('injected second fixture failure')
                return super().__setitem__(key, value)
        monkeypatch.setattr(fixtures, 'CASES', FailSecondWrite(fixtures.CASES))
    with pytest.raises(RuntimeError, match='injected second'): admission.install()
    assert tuple(checks.CHECKS) == before and fixtures.CASES == old
    assert admission._INSTALLED == {}


def test_receipt_is_immutable_and_no_hook_is_installed():
    root = Path(__file__).resolve().parents[1]
    data = (root / 'peaso/checks' / admission.RECEIPT).read_bytes()
    assert hashlib.sha256(data).hexdigest() == admission.RECEIPT_SHA256
    assert admission.__name__ not in (root / 'peaso/checks/__init__.py').read_text()
    assert not any(c.id in admission.IDS for c in checks.CHECKS)


def test_later_dedicated_kind_additions_are_compatible(monkeypatch):
    monkeypatch.setattr(azure, 'TYPES', tuple(kind for kind in azure.TYPES if kind not in producer.KINDS) + producer.KINDS)
    admission.install();admission.install()
    assert all(sum(c.id == cid for c in checks.CHECKS) == 1 for cid in admission.IDS)


def test_duplicate_dedicated_kind_rejected(monkeypatch):
    monkeypatch.setattr(azure, 'TYPES', tuple(azure.TYPES) + (producer.NSP_KIND,) * 2)
    with pytest.raises(RuntimeError, match='kind collision'): admission.install()


def test_missing_callable_and_changed_default_are_rejected(monkeypatch):
    with monkeypatch.context() as patch:
        patch.delattr(producer, 'metadata_get')
        with pytest.raises(RuntimeError, match='function set'): admission.reviewed_inputs()
    monkeypatch.setattr(producer.collect, '__kwdefaults__', {'transport': 'unreviewed'})
    with pytest.raises(RuntimeError, match='binding'): admission.reviewed_inputs()


def test_imported_parser_replacement_is_rejected(monkeypatch):
    monkeypatch.setattr(producer, 'urlsplit', lambda *args: None)
    with pytest.raises(RuntimeError, match='helper identity'): admission.reviewed_inputs()


def test_boolean_integer_metadata_substitution_is_not_equivalent(monkeypatch):
    changed = deepcopy(candidate.DECLARATIONS);changed[0]['registered'] = 0
    monkeypatch.setattr(candidate, 'DECLARATIONS', changed)
    with pytest.raises(RuntimeError, match='schema'): admission.reviewed_inputs()
