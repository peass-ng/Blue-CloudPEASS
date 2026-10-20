"""The wheel retains the exact immutable NSP/TDE admission input closure."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tests.test_peaso_installed_wheel import ADMISSION_RUNTIME_DATA, installed_wheel


RECEIPTS = (
    'azure_nsp_query_cmk_metadata_admission_20261020.json',
    'azure_nsp_query_cmk_runtime_admission_20261020.json',
    'azure_nsp_query_cmk_production_tde_successor_20261020.json',
)


def input_closure(root):
    paths = set()
    for name in RECEIPTS:
        relative = 'peaso/checks/' + name
        receipt = json.loads((root / relative).read_bytes())
        paths.update((relative, receipt['helper_path']))
        paths.update(receipt.get('sources', {}))
        paths.update(row['path'] for row in receipt['functions'].values())
        paths.update(row['path'] for row in receipt['fixtures'])
        paths.update(receipt.get('predecessor_files', {}))
        if 'predecessor_pack' in receipt:
            paths.add(receipt['predecessor_pack']['path'])
    return paths


def test_installed_exact_input_closure_and_runtime_data_only(installed_wheel):
    target, _ = installed_wheel
    root = Path(__file__).resolve().parents[1]
    paths = input_closure(root)
    assert len(paths) == 23
    assert {name for name in paths if name.startswith('tests/')} == set(ADMISSION_RUNTIME_DATA)
    assert not (target.parent / 'source').exists()
    assert {p.relative_to(target).as_posix() for p in (target / 'tests').rglob('*')
            if p.is_file()} == set(ADMISSION_RUNTIME_DATA)
    for name in paths:
        assert (target / name).read_bytes() == (root / name).read_bytes(), name


@pytest.mark.parametrize('relative', ADMISSION_RUNTIME_DATA)
@pytest.mark.parametrize('change', ('missing', 'tampered'))
def test_installed_admission_rejects_each_missing_or_tampered_input(installed_wheel, relative, change):
    target, environment = installed_wheel
    # Start from an admitted, source-free install on every run. Both the warm
    # reader and a fresh import must reject the intended single-file mutation.
    code = '''
import json,pathlib,subprocess,sys
target,relative,change = sys.argv[1:]
sys.path.insert(0, target)
from peaso.checks import azure_nsp_query_cmk_production_tde_successor_20261020 as admission
assert admission.reviewed_inputs()[2]
path = pathlib.Path(target) / relative
original = path.read_bytes()
if change == 'missing':
    expected = ('malformed metadata admission inputs' if 'metadata_proposal' in relative else
                'malformed runtime successor inputs' if 'runtime_native' in relative else
                'malformed production admission inputs')
else:
    expected = ('metadata native fixture/proposal changed' if 'metadata_proposal' in relative else
                'runtime successor fixture changed' if 'runtime_native' in relative else
                'TDE predecessor pack changed' if 'identity_predecessor' in relative else
                'production native fixture changed')
try:
    if change == 'missing':
        path.unlink()
    else:
        path.write_bytes(original + b'\\n')
    try:
        admission.reviewed_inputs()
    except RuntimeError as exc:
        assert str(exc) == expected, (str(exc), expected)
    else:
        raise AssertionError('warm admission accepted modified runtime data')
    startup = 'import sys;sys.path.insert(0,sys.argv[1]);from peaso import checks'
    result = subprocess.run([sys.executable, '-I', '-c', startup, target],
                            cwd=target, capture_output=True, text=True, timeout=90)
    assert result.returncode != 0 and ('RuntimeError: ' + expected) in result.stderr, result.stderr
finally:
    path.write_bytes(original)
assert admission.reviewed_inputs()[2]
print(json.dumps({'path': relative, 'change': change, 'rejected': expected}))
'''
    result = subprocess.run([sys.executable, '-I', '-c', code, str(target), relative, change],
                            cwd=target, env=environment, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stderr[-4000:]
    assert json.loads(result.stdout)['path'] == relative
