"""Packaging-safe, fresh-process parity for the frozen evidence presentation."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT/'peaso/server'
NATIVE_ROOT = (ROOT/'peaso/checks').resolve().parents[1]
ARCHIVE = ROOT/'tests/fixtures/evidence_static_parity_all_20261020.jsonl.gz'
ARCHIVE_SHA256 = '87196e7873b320bdc8109b8c685977baa4c5ce5fc8e848e0b98ec1f33c14b24c'
SKIPPED = ROOT/'tests/fixtures/evidence_static_skipped_20261020.json'
SKIPPED_SHA256 = '73162790353f206ca8b2e8e8fd5bc3d505d04960bb7736a448c17fef4146357f'
RUNTIME = ('evidence_static.py', 'evidence_static_source_manifest.json',
           'evidence_static_data_manifest.json', 'evidence_static_field_specs.json',
           'evidence_static_privesc_entries.json')


def _stage(tmp_path):
    """Build a package overlay without writing to the source checkout."""
    (tmp_path/'risk_rules').symlink_to(ROOT/'risk_rules', target_is_directory=True)
    peaso = tmp_path/'peaso'
    peaso.mkdir()
    for child in (ROOT/'peaso').iterdir():
        if child.name != 'server':
            (peaso/child.name).symlink_to(child, target_is_directory=child.is_dir())
    server=peaso/'server'
    server.mkdir()
    for child in RUNTIME_ROOT.iterdir():
        if child.name not in RUNTIME:
            (server/child.name).symlink_to(child, target_is_directory=child.is_dir())
    for name in RUNTIME:
        (server/name).write_bytes((RUNTIME_ROOT/name).read_bytes())
    return tmp_path


def _run(stage, script):
    # The copied helper reads the package overlay; normal Python imports use
    # the actual source package, as they do after installation.
    assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() == ARCHIVE_SHA256
    env=dict(os.environ, PYTHONPATH=str(NATIVE_ROOT)+os.pathsep+str(ROOT)+os.pathsep+str(stage))
    result=subprocess.run([sys.executable,'-c',script,str(ARCHIVE),str(stage)],
                          cwd=NATIVE_ROOT,env=env,text=True,capture_output=True,timeout=180)
    assert result.returncode == 0, result.stdout+'\n'+result.stderr
    return result.stdout


COLD = r'''
import copy,gzip,importlib.util,json,sys
from pathlib import Path
path=Path(sys.argv[2])/'peaso/server/evidence_static.py'
spec=importlib.util.spec_from_file_location('evidence_static_cold',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
assert not any(name=='peaso.checks' or name.startswith('peaso.checks.') or name=='peaso.analysis' or name.startswith('peaso.analysis.') or name=='peaso.engine' for name in sys.modules)
count=0
with gzip.open(sys.argv[1],'rt',encoding='utf-8') as file:
 for line in file:
  row=json.loads(line);finding=copy.deepcopy(row['finding']);before=copy.deepcopy(finding)
  try: actual={'value':module.evidence_summary(finding)}
  except Exception as error: actual={'error':type(error).__name__,'message':str(error)}
  assert actual==row['expected'],(count,row['finding']['check_id'],actual,row['expected'])
  assert finding==row['after'],count
  count+=1
  assert not any(name=='peaso.checks' or name.startswith('peaso.checks.') or name=='peaso.analysis' or name.startswith('peaso.analysis.') or name=='peaso.engine' for name in sys.modules),count
assert count==12145,count
print('cold parity',count)
'''


def test_all_fixtures_exact_cold_parity(tmp_path):
    assert 'cold parity 12145' in _run(_stage(tmp_path),COLD)


def test_skipped_fixture_accounting():
    assert hashlib.sha256(SKIPPED.read_bytes()).hexdigest() == SKIPPED_SHA256
    rows=json.loads(SKIPPED.read_text())
    assert len(rows)==1081
    assert sum(row['reason']=='no CASES entry' for row in rows)==581
    assert sum(row['reason']=='fixture variant absent' for row in rows)==500
    assert all(row['stage']=='selection' for row in rows)


def test_pinned_manifest_rejects_tamper(tmp_path):
    stage=_stage(tmp_path)
    for name in ('evidence_static_source_manifest.json','evidence_static_data_manifest.json'):
        path=stage/'peaso/server'/name
        original=path.read_bytes()
        path.write_bytes(original+b' ')
        script=r'''
import importlib.util,sys
from pathlib import Path
path=Path(sys.argv[2])/'peaso/server/evidence_static.py'
spec=importlib.util.spec_from_file_location('evidence_static_tamper',path)
module=importlib.util.module_from_spec(spec)
try:spec.loader.exec_module(module)
except ImportError as error:
 assert 'manifest changed' in str(error),str(error)
else:raise AssertionError('tampered manifest accepted')
'''
        _run(stage,script)
        path.write_bytes(original)


def test_native_registry_imports_after_cold_formatting(tmp_path):
    script=r'''
import gzip,importlib.util,json,sys
from pathlib import Path
path=Path(sys.argv[2])/'peaso/server/evidence_static.py'
spec=importlib.util.spec_from_file_location('evidence_static_then_native',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
rows=[]
with gzip.open(sys.argv[1],'rt',encoding='utf-8') as file:
 for line in file:
  row=json.loads(line)
  if row['kind']=='native-pass' and row['finding']['provider'] not in {x['finding']['provider'] for x in rows}:
   rows.append(row)
  if len(rows)==4:break
for row in rows:assert module.evidence_summary(row['finding'])==row['expected']['value']
assert 'peaso.checks' not in sys.modules and 'peaso.analysis' not in sys.modules
from peaso.checks import CHECKS
from peaso.finding_observation import evidence_summary as original
assert len(CHECKS)>=4000,len(CHECKS)
for row in rows:assert original(row['finding'])==module.evidence_summary(row['finding'])
print('native later',len(CHECKS))
'''
    assert 'native later' in _run(_stage(tmp_path),script)


def test_concurrent_first_import_never_exposes_partial_formatter(monkeypatch):
    import builtins
    from concurrent.futures import ThreadPoolExecutor
    import importlib.util
    from threading import Event
    from peaso.server import evidence_static
    spec = importlib.util.spec_from_file_location('isolated_evidence_thread_test', evidence_static.__file__)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    entered, release, second_started, second_finished = (Event() for _ in range(4))
    def delayed_exec(code, namespace):
        entered.set()
        assert release.wait(10)
        return builtins.exec(code, namespace)
    monkeypatch.setattr(loader, 'exec', delayed_exec, raising=False)
    name = 'checks.aws_ai_recheck_evidence_20261020'
    def concurrent_reader():
        second_started.set()
        try:
            return loader._load_source(name).evidence_summary({})
        finally:
            second_finished.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(loader._load_source, name)
        try:
            assert entered.wait(5)
            second = pool.submit(concurrent_reader)
            assert second_started.wait(5)
            assert not second_finished.wait(0.2)
        finally:
            release.set()
        assert second.result(timeout=5) is None
        assert loader._load_source(name) is first.result(timeout=5)
