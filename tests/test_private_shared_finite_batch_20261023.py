"""Focused negatives for finite source proof reuse inside shared admission."""
import importlib
import inspect
import json
import sys
from pathlib import Path

import pytest

from peaso.checks import private_secret_shared_source_successor_20261021 as shared


ROOT = Path(__file__).resolve().parents[1]


def _row(gcp=False):
    receipt = json.loads((ROOT / 'peaso/checks' / shared.RECEIPT).read_bytes())
    qualified = next(qualified for qualified, row in receipt['functions'].items()
                     if not gcp or row['path'].startswith('peaso/checks/gcp_'))
    module_name, name = qualified.split(':')
    function = importlib.import_module(module_name)
    for part in name.split('.'):
        function = getattr(function, part)
    return function, receipt['functions'][qualified], qualified


def test_forged_batch_or_map_cannot_skip_source_proof():
    with pytest.raises(RuntimeError, match='Invalid finite callable proof batch'):
        shared._check_function(({'forged': 'map'},), None, ROOT, {})
    with pytest.raises(RuntimeError, match='Invalid finite callable proof batch'):
        shared._check_function(((_row()[0], _row()[1], 7),), None, ROOT, {})


def test_gcp_source_mutation_after_row_is_rejected_at_batch_exit():
    row = _row()
    target = ROOT / 'peaso/checks/gcp_artifact_file_secret_review_20261019.py'
    original = target.read_bytes()
    lines, start = inspect.getsourcelines(shared._check_function)
    exit_line = start + max(index for index, line in enumerate(lines)
                            if line.strip() == '_source_delta(root)')
    changed = False

    def trace(frame, event, arg):
        nonlocal changed
        if (not changed and event == 'line' and frame.f_code is shared._check_function.__code__
                and frame.f_lineno == exit_line):
            target.write_bytes(original + b'\n#tampered after row proof\n')
            changed = True
        return trace

    prior = sys.gettrace()
    try:
        sys.settrace(trace)
        with pytest.raises(RuntimeError):
            shared._check_function((row,), None, ROOT, {})
        assert changed
    finally:
        sys.settrace(prior)
        target.write_bytes(original)


def test_direct_gcp_row_still_requires_fresh_full_source_proof():
    row = _row(gcp=True)
    target = ROOT / 'peaso/checks/gcp_artifact_file_secret_review_20261019.py'
    original = target.read_bytes()
    try:
        target.write_bytes(original + b'\n#tampered before direct proof\n')
        with pytest.raises(RuntimeError):
            shared._check_function(row[0], row[1], ROOT, {})
    finally:
        target.write_bytes(original)
