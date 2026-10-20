"""Current guard baseline, exact tamper rejection and independent package replay."""
from copy import deepcopy
import ast
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from peaso import engine
from peaso.collectors import aws
from peaso.server import validation
from peaso.checks import aws_codebuild_buildspec_shared_successor_20261020 as shared
from peaso.checks import aws_codebuild_buildspec_s3_successor_20261020 as s3
from peaso.checks import aws_codebuild_buildspec_runtime_admission_20261020 as codebuild
from peaso.checks import gcp_dataflow_batch_source_runtime_admission_20261020 as dataflow

ROOT = Path(__file__).resolve().parents[1]


def baseline():
    shared.reviewed_inputs()
    s3.reviewed_inputs()
    receipt, _, _ = dataflow.reviewed_inputs()
    assert len(receipt['runtime_functions']) == 119
    codebuild.reviewed_inputs()


def test_current_baseline_not_already_red_and_original119_binding_closure():
    baseline()
    assert shared.original.reviewed_inputs is shared.reviewed_inputs
    assert dataflow.shared is shared
    assert shared.predecessor.original is shared.original
    for actual, expected in dataflow._bindings():
        assert actual is expected
    assert len(dataflow._bindings()) == 18


@pytest.mark.parametrize('owner,name', [(engine, '_request'), (engine, 'collect_snapshot'),
    (validation, 'validate_connector'), (aws, 'collect')])
def test_current_guard_executing_code_tamper_rejects_then_restored_passes(monkeypatch, owner, name):
    baseline()
    with monkeypatch.context() as patch:
        patch.setattr(owner, name, lambda *args, **kwargs: None)
        with pytest.raises((RuntimeError, KeyError, TypeError)):
            shared.reviewed_inputs() if owner is not aws else s3.reviewed_inputs()
    baseline()


@pytest.mark.parametrize('name', ['reviewed_inputs', 'check_shared', 'prepared_inputs', 'install_bundle'])
def test_current_successor_helpers_reject_substitution_after_green_baseline(monkeypatch, name):
    baseline()
    with monkeypatch.context() as patch:
        patch.setattr(shared, name, lambda *args, **kwargs: None)
        with pytest.raises(RuntimeError, match='callable replaced'):
            shared.reviewed_delta()
    baseline()


def test_unrelated_source_addition_rejected_then_original_restored(monkeypatch):
    baseline()
    function = engine._request
    # Mutate real executing code; leave source/receipt/filesystem reads intact.
    with monkeypatch.context() as patch:
        patch.setattr(function, '__code__', (lambda request: None).__code__)
        with pytest.raises(RuntimeError):
            shared.reviewed_inputs()
    baseline()


def test_exact_shared_node_reconstruction_and_unchanged_predecessor_helpers():
    receipt = shared.reviewed_delta()
    archive = json.loads(gzip.decompress((ROOT / receipt['archive']).read_bytes()))
    assert set(receipt['shared_functions']) == {'engine._request', 'engine.collect_snapshot', 'validation.validate_connector', 'aws.collect'}
    for name, row in receipt['shared_functions'].items():
        function = {'engine._request': engine._request, 'engine.collect_snapshot': engine.collect_snapshot,
            'validation.validate_connector': validation.validate_connector, 'aws.collect': aws.collect}[name]
        restored = shared.inspect.getsource(function)
        for addition in row['exact_additions']:
            assert restored.count(addition) == 1
            restored = restored.replace(addition, '', 1)
        assert restored == archive['functions'][name]['source']
        assert hashlib.sha256(restored.encode()).hexdigest() == row['predecessor_sha256']
    for name, item in archive['files'].items():
        if name.startswith('peaso/checks/') and not name.endswith('/__init__.py'):
            assert (ROOT / name).read_bytes() == bytes.fromhex(item['hex'])


def test_network_diagnostic_route_proof_remains_valid_with_current_original119_guard():
    import importlib.util
    path = ROOT / 'peaso/checks/k8s_network_inventory_successor_20261020.py'
    spec = importlib.util.spec_from_file_location('_codebuild_current_network_diagnostic', path)
    diagnostic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(diagnostic)
    from peaso.collectors import k8s_network_extensions as network, k8s_network_route_extensions as route, k8s_network_catalog as catalog
    proof = diagnostic.validate(ROOT, network)
    assert proof['static_runtime119'] == 119
    baseline()
    reviewed = diagnostic.receipt(ROOT)
    diagnostic.executing(route.match, reviewed['isolated_route_matcher'], route, ROOT)
    for path in diagnostic.assert_disjoint(dict(network.RESOURCES, **route.RESOURCES), diagnostic.native_kinds(ROOT, reviewed)):
        assert route.match(path) is None and catalog.allowed_path(path) is False


def test_bundle_registration_failure_restores_aliases_cases_and_registry(monkeypatch):
    import peaso.checks as checks
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    baseline()
    before = tuple(CHECKS)
    stored = {k: deepcopy(v) for k, v in CASES.items() if k in {shared.original.CHECK, codebuild.runtime.CHECK, *dataflow.runtime.CHECKS}}
    aliases = (shared.original.reviewed_inputs, shared.original._INSTALLED, dataflow.shared)
    original = next(c for c in CHECKS if c.id == codebuild.runtime.CHECK)
    CHECKS.remove(original); CASES.pop(codebuild.runtime.CHECK)
    original_register = checks.register
    def broken_register(ident, *args, **kwargs):
        if ident == codebuild.runtime.CHECK:
            def broken(function):
                CHECKS.append(original)
                raise RuntimeError('final registration failed')
            return broken
        return original_register(ident, *args, **kwargs)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(checks, 'register', broken_register)
            with pytest.raises(RuntimeError, match='final registration failed'):
                shared.install_bundle()
        assert not any(c.id == codebuild.runtime.CHECK for c in CHECKS)
        assert (shared.original.reviewed_inputs, shared.original._INSTALLED, dataflow.shared) == aliases
        assert all(CASES[k] == v for k, v in stored.items() if k != codebuild.runtime.CHECK)
    finally:
        CHECKS[:] = before
        CASES[codebuild.runtime.CHECK] = stored[codebuild.runtime.CHECK]
    baseline()


def test_independent_package_data_normal_import_and_cross_process_json_replay(tmp_path):
    """Copy installable package bytes, not a wheel build or a source-read mock."""
    installed = tmp_path / 'installed'
    shutil.copytree(ROOT / 'peaso', installed / 'peaso', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    # Existing Azure package data uses this deliberately packaged namespace.
    fixture_names = ('azure_nsp_query_cmk_metadata_proposal_20261020.json.gz',
        'azure_nsp_query_cmk_runtime_native_20261020.json.gz',
        'azure_nsp_query_cmk_production_native_20261020.json.gz',
        'azure_sql_tde_parent_identity_predecessor_20261020.json.gz')
    namespace = installed / 'tests/fixtures'
    namespace.mkdir(parents=True)
    (installed / 'tests/__init__.py').write_text('')
    (namespace / '__init__.py').write_text('')
    for name in fixture_names:
        shutil.copyfile(ROOT / 'tests/fixtures' / name, namespace / name)
    script = '''
import json
from pathlib import Path
import peaso
from peaso.checks import aws_codebuild_buildspec_runtime_admission_20261020 as admission
from peaso.checks import aws_codebuild_buildspec_runtime_consumer_20261020 as consumer
from peaso.checks import aws_codebuild_buildspec_shared_successor_20261020 as shared
assert Path(peaso.__file__).resolve().is_relative_to(Path.cwd())
receipt,cases=admission.reviewed_inputs()
assert receipt['native_cases_required'] is True
shared.reviewed_inputs()
case=cases[consumer.runtime.CHECK]
statuses={name:consumer.evaluate(json.loads(json.dumps(case[name])),json.loads(json.dumps(case[name+'_index'])))[0] for name in ('pass','fail','unknown','malformed','partial')}
assert statuses=={'pass':'PASS','fail':'FAIL','unknown':'UNKNOWN','malformed':'UNKNOWN','partial':'FAIL'}
print(json.dumps(statuses,sort_keys=True))
'''
    environment = dict(os.environ, PYTHONPATH=str(installed), AWS_EC2_METADATA_DISABLED='true',
        AWS_CONFIG_FILE='/nonexistent/package-proof', AWS_SHARED_CREDENTIALS_FILE='/nonexistent/package-proof')
    process = subprocess.run([sys.executable, '-c', script], cwd=installed, env=environment,
        capture_output=True, text=True, timeout=90)
    assert process.returncode == 0, process.stderr[-6000:]
    assert json.loads(process.stdout)['partial'] == 'FAIL'
