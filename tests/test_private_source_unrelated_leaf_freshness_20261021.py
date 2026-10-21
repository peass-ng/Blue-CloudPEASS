"""An unrelated function proof must still reject another leaf after warming."""
import hashlib
import inspect
from pathlib import Path

import pytest
from peaso import checks


def test_unrelated_gcp_function_keeps_full_leaf_freshness_after_warm_admission(monkeypatch):
    shared = checks.aws_workload_command_shared_successor_20261020
    admission = checks.gcp_function_secret_page_admission_20261020
    fn = admission.reviewed_inputs
    root = Path(checks.__file__).resolve().parents[2]
    relative = Path(inspect.getsourcefile(fn)).resolve().relative_to(root).as_posix()
    assert relative.startswith('peaso/checks/gcp_')
    other_leaf = root / 'peaso/collectors/gcp_image_secret_indicators.py'
    assert relative != other_leaf.relative_to(root).as_posix()
    row = {'path': relative, 'qualname': fn.__qualname__,
           'sha256': hashlib.sha256(inspect.getsource(fn).encode()).hexdigest(),
           'defaults': fn.__defaults__, 'kwdefaults': fn.__kwdefaults__}
    # Keep the same compiled artifact dictionary across both entries.
    artifacts = {}
    shared._check_function(fn, row, root, artifacts)
    original = Path.read_bytes
    def changed(path):
        raw = original(path)
        return raw + b'\n# unrelated leaf changed after warm proof\n' if path.resolve() == other_leaf else raw
    monkeypatch.setattr(Path, 'read_bytes', changed)
    with pytest.raises((ValueError, RuntimeError)):
        shared._check_function(fn, row, root, artifacts)
