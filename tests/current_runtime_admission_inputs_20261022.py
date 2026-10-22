"""Current Workbench/Dataproc test inputs after fresh admitted installation."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path

from peaso import checks
from peaso.checks.fixtures import CASES
from peaso.rawv2_private_source_successor_20261021 import install_admission

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = {
    'gcp_workbench_source_runtime_admission_20261020':
        'peaso.checks.gcp_workbench_source_runtime_consumer_20261020',
    'gcp_dataproc_source_runtime_admission_20261020':
        'peaso.checks.gcp_dataproc_referenced_source_secret_review_20261020',
}


def current_inputs(admission):
    name = admission.__name__.rsplit('.', 1)[1]
    if CANDIDATES.get(name) is None or importlib.import_module(admission.__name__) is not admission:
        raise ValueError('Unreviewed current test admission')
    install_admission(name)
    path = ROOT / 'peaso/checks' / (name + '.json')
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == admission.RECEIPT_SHA256
    receipt = json.loads(raw)
    candidate = importlib.import_module(CANDIDATES[name])
    assert tuple(row['id'] for row in receipt['checks']) == admission.CHECK_IDS
    assert tuple(row['id'] for row in candidate.DECLARATIONS) == admission.CHECK_IDS
    cases = deepcopy({cid: CASES[cid] for cid in admission.CHECK_IDS})
    declarations = []
    for row in candidate.DECLARATIONS:
        function_name = next(proof['evaluate'].rsplit(':', 1)[1]
                             for proof in receipt['checks'] if proof['id'] == row['id'])
        function = getattr(candidate, function_name)
        actual, = [check for check in checks.CHECKS if check.id == row['id']]
        assert inspect.unwrap(actual.evaluate) is function
        declarations.append((row, function))
    return receipt, cases, declarations


def alter_exact_source_read(monkeypatch, relative):
    """Return modified bytes only for one named source in the current root."""
    target = (ROOT / relative).resolve()
    original = Path.read_bytes
    hits = []
    def read(path, *args, **kwargs):
        data = original(path, *args, **kwargs)
        if Path(path).resolve() == target:
            hits.append(target)
            return data + b'\n# unreviewed mutation\n'
        return data
    monkeypatch.setattr(Path, 'read_bytes', read)
    return hits
