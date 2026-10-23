"""Current additive-source epoch, actual substitution and rollback proofs."""
from copy import deepcopy
import gzip
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from peaso import engine
from peaso.collectors import azure
from peaso.server import validation
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import azure_function_package_shared_successor_20261020 as shared
from peaso.checks import azure_function_package_integration_admission_20261020 as admission
from peaso.checks import azure_function_package_tde_successor_20261020 as tde
from peaso.checks import azure_metadata_only_tde_admission_successor_20261020 as current_tde
from peaso.private_secret_source_epoch_20261021 import AdmissionError
from peaso.checks import gcp_dataflow_batch_source_runtime_admission_20261020 as dataflow
from peaso.checks import aws_codebuild_buildspec_runtime_admission_20261020 as codebuild
from peaso.checks import aws_codebuild_buildspec_s3_successor_20261020 as s3
from peaso.collectors import azure_function_package_integration_20261020 as runtime

ROOT = Path(__file__).resolve().parents[1]


def baseline():
    shared.reviewed_inputs()
    current_tde.reviewed_inputs()
    receipt, _, _ = dataflow.reviewed_inputs()
    assert len(receipt['runtime_functions']) == 119
    assert len(dataflow._bindings()) == 18
    assert all(actual is original for actual, original in dataflow._bindings())
    codebuild.reviewed_inputs()
    with pytest.raises(RuntimeError):
        s3.reviewed_inputs()  # The current shared successor owns this later source.
    return admission.reviewed_inputs()


def test_current_baseline_original119_and_exact_predecessor_bytes():
    receipt, cases = baseline()
    assert shared.original.reviewed_inputs is shared.reviewed_inputs and dataflow.shared is shared
    shared.reviewed_delta()  # The current successor verifies the live source.
    historical = importlib.import_module('peaso.checks.azure_function_package_shared_successor_20261020')
    proof_raw = (ROOT / 'peaso/checks' / historical.RECEIPT).read_bytes()
    assert hashlib.sha256(proof_raw).hexdigest() == historical.RECEIPT_SHA256
    proof = json.loads(proof_raw)
    archive = json.loads(gzip.decompress((ROOT / proof['archive']).read_bytes()))
    for name, row in archive['files'].items():
        old = bytes.fromhex(row['hex'])
        assert hashlib.sha256(old).hexdigest() == row['sha256']
    assert len(receipt['functions']) == 265 and len(cases) == 9


@pytest.mark.parametrize('module,name,gate', [(engine, '_request', 'shared'),
    (engine, 'collect_snapshot', 'shared'), (validation, 'validate_connector', 'shared'),
    (azure, 'collect', 'tde'), (runtime, 'collect', 'native'),
    (runtime, 'finalize', 'native'), (runtime, 'collect_pipeline', 'native'),
    (runtime.predecessor, '_reader', 'native'), (runtime.source.storage, '_scan', 'native')])
def test_actual_executing_code_substitution_rejected_and_restored(monkeypatch, module, name, gate):
    baseline()
    function = getattr(module, name)
    with monkeypatch.context() as patch:
        patch.setattr(function, '__code__', (lambda *args, **kwargs: None).__code__)
        with pytest.raises((RuntimeError, KeyError, TypeError, AdmissionError)):
            {'shared': shared.reviewed_inputs, 'tde': current_tde.reviewed_inputs, 'native': admission.reviewed_inputs}[gate]()
    baseline()


@pytest.mark.parametrize('name', ['reviewed_inputs', 'check_shared', 'install_bundle'])
def test_new_shared_helper_substitution_rejected_and_restored(monkeypatch, name):
    baseline()
    function = getattr(shared, name)
    with monkeypatch.context() as patch:
        patch.setattr(function, '__code__', (lambda *args, **kwargs: None).__code__)
        with pytest.raises(RuntimeError):
            shared.reviewed_delta()
    baseline()


@pytest.mark.parametrize('case', ['source_aliases', 'reader_class', 'union_class'])
def test_canonical_module_and_helper_class_substitution_rejected(monkeypatch, case):
    from types import SimpleNamespace
    baseline()
    with monkeypatch.context() as patch:
        if case == 'source_aliases':
            fake = SimpleNamespace(**vars(runtime.source))
            # Preserve original function objects while substituting every
            # imported producer alias; canonical module binding still rejects.
            patch.setattr(runtime, 'source', fake)
            patch.setattr(runtime.predecessor, 'source', fake)
            patch.setattr(runtime.exporter, 'source', fake)
        elif case == 'reader_class':
            patch.setattr(azure, '_Reader', type('SubstitutedReader', (azure._Reader,), {}))
        else:
            patch.setattr(runtime.predecessor, '_Union', type('SubstitutedUnion', (runtime.predecessor._Union,), {}))
        with pytest.raises(RuntimeError):
            admission.reviewed_inputs()
    baseline()


def test_atomic_registration_wave_rolls_back_every_touched_owner(monkeypatch):
    from peaso.checks import fixtures
    baseline()
    original_checks = tuple(CHECKS)
    original = next(c for c in CHECKS if c.id == runtime.CHECK)
    CHECKS.remove(original)
    class RejectingStore(dict):
        def __setitem__(self, key, value):
            super().__setitem__(key, value)
            if key == runtime.CHECK:
                raise RuntimeError('directed_last_owner_rejection')
    store = RejectingStore(CASES)
    store.pop(runtime.CHECK)
    old_checks, old_cases = tuple(CHECKS), dict(store)
    old_alias, old_shared = shared.original.reviewed_inputs, dataflow.shared
    old_package, old_tde = admission._INSTALLED, dict(tde.original._INSTALLED)
    try:
        # A real CASES write fails after actual register() and preceding owners
        # ran. No executing helper or filesystem read is substituted.
        with monkeypatch.context() as patch:
            patch.setattr(fixtures, 'CASES', store)
            with pytest.raises(RuntimeError, match='directed_last_owner_rejection'):
                shared.install_bundle()
        assert tuple(CHECKS) == old_checks and all(a is b for a, b in zip(CHECKS, old_checks))
        assert set(store) == set(old_cases) and all(store[k] is value for k, value in old_cases.items())
        assert shared.original.reviewed_inputs is old_alias and dataflow.shared is old_shared
        assert admission._INSTALLED is old_package and tde.original._INSTALLED == old_tde
    finally:
        CHECKS[:] = original_checks
        admission._INSTALLED = old_package
    baseline()


def test_registration_metadata_and_fixture_replacement_rejected():
    from dataclasses import replace
    check, = [c for c in CHECKS if c.id == runtime.CHECK]
    position = CHECKS.index(check)
    try:
        CHECKS[position] = replace(check, title='hostile replacement')
        with pytest.raises(RuntimeError, match='registration replaced'):
            admission.install()
    finally:
        CHECKS[position] = check
    old_case = CASES[runtime.CHECK]
    try:
        CASES[runtime.CHECK] = dict(old_case, **{'pass': {}})
        with pytest.raises(RuntimeError, match='CASES replaced'):
            admission.install()
    finally:
        CASES[runtime.CHECK] = old_case
    admission.install()


def test_package_only_import_source_substitution_negative_and_restored(tmp_path):
    installed = tmp_path / 'installed'
    shutil.copytree(ROOT / 'peaso', installed / 'peaso', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    namespace = installed / 'tests/fixtures'; namespace.mkdir(parents=True)
    (installed / 'tests/__init__.py').write_text('')
    (namespace / '__init__.py').write_text('')
    for name in ('azure_nsp_query_cmk_metadata_proposal_20261020.json.gz',
        'azure_nsp_query_cmk_runtime_native_20261020.json.gz',
        'azure_nsp_query_cmk_production_native_20261020.json.gz',
        'azure_sql_tde_parent_identity_predecessor_20261020.json.gz'):
        shutil.copyfile(ROOT / 'tests/fixtures' / name, namespace / name)
    env = {**os.environ, 'PYTHONPATH': str(installed), 'XDG_STATE_HOME': str(tmp_path / 'state')}
    command = [sys.executable, '-B', '-c', '''
import json, pathlib
import peaso
assert pathlib.Path(peaso.__file__).resolve().is_relative_to(pathlib.Path.cwd())
from peaso.checks import azure_function_package_shared_successor_20261020 as shared
from peaso.checks import azure_function_package_integration_admission_20261020 as admission
shared.reviewed_inputs()
r,c=admission.reviewed_inputs()
print(json.dumps({'functions':len(r['functions']),'cases':len(c)}))
''']
    def run():
        return subprocess.run(command, cwd=installed, env=env, capture_output=True, text=True, timeout=240)
    first = run(); assert first.returncode == 0, first.stderr
    assert json.loads(first.stdout)['functions'] == 265
    # Only isolated copied package bytes change; shared files and all reads are real.
    target = installed / 'peaso/engine.py'; original = target.read_bytes()
    target.write_bytes(original.replace(b'package_preflight(content_options,', b'hostile_preflight(content_options,', 1))
    rejected = run(); assert rejected.returncode != 0 and 'Deployed AI current source changed: expected=' in rejected.stderr
    target.write_bytes(original)
    restored = run(); assert restored.returncode == 0, restored.stderr
    assert restored.stdout == first.stdout


def test_head3_entrypoint_preserves_completed_package_epoch_and_rejects_code_substitution(monkeypatch):
    from peaso.checks import azure_function_package_head3_entrypoint_20261020 as entrypoint
    from peaso.checks import gcp_workbench_head3_admission_20261020 as head3
    # This receipt proves the older HEAD3 step. Later signed successors own
    # the live initializer, so its old two-line delta is no longer present.
    raw = (ROOT / 'peaso/checks' / entrypoint.RECEIPT).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == entrypoint.RECEIPT_SHA256
    receipt = json.loads(raw)
    packed = (ROOT / receipt['archive']['path']).read_bytes()
    assert hashlib.sha256(packed).hexdigest() == receipt['archive']['sha256']
    archive = json.loads(gzip.decompress(packed))
    for row in archive.values():
        assert hashlib.sha256(bytes.fromhex(row['hex'])).hexdigest() == row['sha256']
    shared.reviewed_delta()  # Current successor verifies the live initializer.
    assert all(sum(c.id == ident for c in CHECKS) == 1 for ident in head3.CHECK_IDS)
    with monkeypatch.context() as patch:
        patch.setattr(entrypoint.reviewed_entrypoint, '__code__', (lambda *args, **kwargs: None).__code__)
        with pytest.raises(RuntimeError):
            shared.reviewed_delta()
    baseline()
