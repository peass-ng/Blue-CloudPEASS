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
            assert started
            code = int(failure == 'schema')
            ready = not code
            data = json.dumps({'rows': []})
        elif 'list' in command:
            if not ready:
                raise worker.subprocess.TimeoutExpired(command, 30)
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
