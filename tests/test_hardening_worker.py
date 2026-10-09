"""Cold startup must use the database budget and fail closed on missing plugins."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize('failure', [None, 'startup', 'schema', 'plugin'])
def test_cold_startup_and_failed_initialization(monkeypatch, tmp_path, failure):
    monkeypatch.syspath_prepend(str(Path('docker').resolve()))
    spec = importlib.util.spec_from_file_location('worker_under_test', 'docker/hardening_worker.py')
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    output, runtime = tmp_path / 'output', tmp_path / 'runtime'
    monkeypatch.setattr(worker.shutil, 'copytree', lambda source, target: (target / 'config').mkdir(parents=True))
    monkeypatch.setattr(worker.os, 'environ', {})
    monkeypatch.setattr(worker.argparse.ArgumentParser, 'parse_args', lambda self: SimpleNamespace(
        self_test=True, provider=None, timeout=1800, input_dir=str(tmp_path), output_dir=str(output), work_dir=str(runtime)))
    started, ready, benchmark = False, False, False

    def execute(command, **kwargs):
        nonlocal started, ready, benchmark
        code, data = 0, '{}'
        if 'start' in command:
            # A cold database needs longer than the inventory command's budget.
            assert kwargs['timeout'] >= 120
            code = int(failure == 'startup')
            started = not code
        elif 'query' in command:
            assert started and ready
            code = int(failure == 'schema')
            data = json.dumps({'rows': []})
        elif 'list' in command:
            if not started:
                raise worker.subprocess.TimeoutExpired(command, 30)
            ready = failure != 'plugin'
            data = json.dumps({'failed': {'missing-plugin': {}} if failure == 'plugin' else {}})
        elif command[0] == 'powerpipe':
            assert ready
            benchmark = True
            Path(command[command.index('--export') + 1]).write_text(json.dumps({'fixture': True}))
        return SimpleNamespace(returncode=code, stdout=data, stderr='startup unavailable' if code else '')

    monkeypatch.setattr(worker.subprocess, 'run', execute)
    worker.main()
    result = json.loads((output / 'result.json').read_text())
    assert benchmark == (failure is None)
    assert bool(result['errors']) == bool(failure)
    assert len(result['runs']) == (0 if failure else 1)
    assert not runtime.exists()


@pytest.mark.parametrize('exit_code', [0, 7])
def test_postgres_without_shared_memory_preserves_initdb_arguments(monkeypatch, tmp_path, exit_code):
    import sys
    import subprocess
    monkeypatch.syspath_prepend(str(Path('docker').resolve()))
    spec = importlib.util.spec_from_file_location('memory_worker', 'docker/hardening_worker.py')
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    install = tmp_path / "private ' runtime"
    binary = install / 'db' / '14.19.0' / 'postgres' / 'bin' / 'initdb'
    binary.parent.mkdir(parents=True)
    arguments = tmp_path / 'arguments.json'
    binary.write_text(f'#!{sys.executable}\nimport json,pathlib,sys\npathlib.Path({str(arguments)!r}).write_text(json.dumps(sys.argv[1:]))\nsys.exit({exit_code})\n')
    binary.chmod(0o700)
    monkeypatch.setattr(worker.os.path, 'isdir', lambda path: False)
    worker.prepare_postgres_memory(install)
    supplied = ['--pgdata=' + str(install / 'db' / '14.19.0' / 'data'), "literal ' $ argument"]
    response = subprocess.run([str(binary), *supplied], capture_output=True)
    assert response.returncode == exit_code
    assert json.loads(arguments.read_text()) == supplied
    config = install / 'db' / '14.19.0' / 'data' / 'postgresql.conf.d' / 'bluepeass-memory.conf'
    assert config.exists() == (exit_code == 0)
    if not exit_code:
        assert config.read_text() == 'dynamic_shared_memory_type=mmap\n'


def test_writable_shared_memory_leaves_postgres_unchanged(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path('docker').resolve()))
    spec = importlib.util.spec_from_file_location('unmodified_memory_worker', 'docker/hardening_worker.py')
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    monkeypatch.setattr(worker.os.path, 'isdir', lambda path: True)
    monkeypatch.setattr(worker.os, 'access', lambda path, mode: True)
    worker.prepare_postgres_memory(tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_provider_schema_snapshot_is_taken_after_materialization(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path('docker').resolve()))
    spec = importlib.util.spec_from_file_location('provider_worker', 'docker/hardening_worker.py')
    worker = importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
    output, runtime = tmp_path / 'output', tmp_path / 'runtime'
    monkeypatch.setattr(worker.shutil, 'copytree', lambda source, target: (target / 'config').mkdir(parents=True))
    monkeypatch.setattr(worker.os, 'environ', {})
    monkeypatch.setattr(worker.argparse.ArgumentParser, 'parse_args', lambda self: SimpleNamespace(
        self_test=False, provider='aws', timeout=1800, input_dir=str(tmp_path), output_dir=str(output), work_dir=str(runtime)))
    original_read = Path.read_text
    def read(path, *args, **kwargs):
        if str(path) == '/opt/bluepeass/catalog.json':
            return json.dumps({'aws':[{'mod':'fixture','version':'fixture','benchmarks':['all'],'directory':str(tmp_path)}]})
        return original_read(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)
    monkeypatch.setattr(worker, 'prepare_query_context', lambda *args: [])
    loaded, ran = False, False
    def execute(command, **kwargs):
        nonlocal loaded, ran
        data = '{}'
        if 'list' in command:
            loaded = True
        elif 'query' in command:
            data = json.dumps({'rows':[{'schema_name':'aws'}] if loaded else []})
        elif command[0] == 'powerpipe':
            ran = True
            Path(command[command.index('--export')+1]).write_text('{}')
        return SimpleNamespace(returncode=0, stdout=data, stderr='')
    monkeypatch.setattr(worker.subprocess, 'run', execute)
    worker.main()
    assert ran
    result = json.loads((output/'result.json').read_text())
    assert not result['errors'] and len(result['runs']) == 1
