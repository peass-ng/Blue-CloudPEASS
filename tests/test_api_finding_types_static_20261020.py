"""Exact metadata parity; no provider collection, external auth or findings."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from peaso import presentation_metadata_20261020 as static

ROOT = Path(__file__).resolve().parents[1]


def test_native_aliases_and_all_taxonomy_cases_are_identical():
    # A fresh process keeps the native reference completely separate from the
    # API rebinding under test. It imports actual reviewed native registrations.
    program = '''
import json
from peaso.checks import CHECK_ALIASES,CHECKS
from peaso.finding_types import type_for,registry
ids=[*sorted(set(registry()['checks'])|set(CHECK_ALIASES)|{'unknown-check',''}),None]
print(json.dumps({'aliases':CHECK_ALIASES,'kinds':{c.id:[c.provider,c.kind] for c in CHECKS},'cases':[[cid,cat,type_for(cid,cat)] for cid in ids for cat in (None,'hardening','exposure','privesc','unknown')]}))
'''
    result = subprocess.run([sys.executable, '-c', program], cwd=ROOT,
                            capture_output=True, text=True, check=True, timeout=180)
    reference = json.loads(result.stdout)
    assert dict(static.ALIASES) == reference['aliases']
    from peaso.server.materialized_catalog import native_kinds
    assert {cid:list(pair) for cid,pair in native_kinds().items()} == reference['kinds']
    assert len(reference['cases']) > 20000
    for cid, category, expected in reference['cases']:
        assert static.type_for(cid, category) == expected, (cid, category)


def test_fresh_api_annotations_do_not_import_native_registry():
    program = '''
import importlib.abc,sys
class BlockNative(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='peaso.checks' or fullname.startswith('peaso.checks.'):
   raise AssertionError('native registry reached')
sys.meta_path.insert(0,BlockNative())
from peaso.server.finding_types_static_20261020 import install,ALIASES
from peaso.finding_types import annotate
install();install()
assert annotate({'check_id':'analysis.internet_exposure'})['finding_type']=='network'
assert annotate({'check_id':'aws.iam.root_mfa'})['finding_type']=='authentication'
assert annotate({'check_id':'unknown','category':'privesc'})['finding_type']=='permissions'
assert annotate({'check_id':'unknown','finding_type':'network'})['finding_type']=='network'
assert annotate({'check_id':'unknown','finding_type':'not-real'})['finding_type']=='unclassified'
for alias in ALIASES: assert annotate({'check_id':alias})['finding_type']!='unclassified'
assert 'peaso.checks' not in sys.modules
'''
    subprocess.run([sys.executable, '-c', program], cwd=ROOT,
                   capture_output=True, text=True, check=True, timeout=30)


def test_pinned_registry_and_predecessor_unchanged():
    assert hashlib.sha256(static.REGISTRY_PATH.read_bytes()).hexdigest() == static.REGISTRY_SHA256
    predecessor = ROOT/'peaso/finding_types.py'
    assert hashlib.sha256(predecessor.read_bytes()).hexdigest() == 'c8f13d627a6a1420b871b7cb2e5fd0684505788caaca7cef65c72c93e784111f'


@pytest.mark.parametrize('damage', ['altered', 'oversize', 'missing'])
def test_tampered_registry_fails_closed(tmp_path, monkeypatch, damage):
    target=tmp_path/'taxonomy.json'
    if damage=='altered': target.write_bytes(static.REGISTRY_PATH.read_bytes()+b' ')
    elif damage=='oversize': target.write_bytes(b' '*(static.MAX_REGISTRY_BYTES+1))
    monkeypatch.setattr(static,'REGISTRY_PATH',target)
    static._checks.cache_clear()
    try:
        with pytest.raises((OSError,ValueError)): static.type_for('analysis.internet_exposure')
    finally: static._checks.cache_clear()


def test_result_roster_and_aliases_are_immutable():
    with pytest.raises(TypeError): static.ALIASES['x']='y'
    with pytest.raises(TypeError): static._checks()['x']='network'


def test_scope_membership_matches_every_native_and_archived_id():
    program = '''
import json
from peaso.checks import CHECK_ALIASES
from peaso.checks.hacktricks_scope import includes,review
ids=[*sorted(set(review()['checks'])|set(CHECK_ALIASES)|{'unknown-check',''}),None]
print(json.dumps([[cid,includes(cid)] for cid in ids]))
'''
    result=subprocess.run([sys.executable,'-c',program],cwd=ROOT,capture_output=True,text=True,check=True,timeout=180)
    cases=json.loads(result.stdout)
    assert len(cases)>4000
    for cid,expected in cases: assert static.includes_in_hacktricks(cid) is expected


def test_api_creation_then_real_native_catalog_in_same_process():
    program = '''
from pathlib import Path
import tempfile
from peaso.server.app import create_app
from peaso.server.config import Settings
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp)
 app=create_app(Settings(state_dir=p/'state',identity_dir=p/'identity'))
 from peaso.engine import get_catalog
 from peaso.checks import CHECKS
 catalog=get_catalog()
 assert len(CHECKS)==4108
 assert len(catalog['checks'])==3490
'''
    result=subprocess.run([sys.executable,'-c',program],cwd=ROOT,capture_output=True,text=True,timeout=180)
    assert result.returncode==0, result.stderr


@pytest.mark.parametrize('damage',['altered','oversize','missing'])
def test_scope_tamper_rejected(tmp_path,monkeypatch,damage):
    target=tmp_path/'scope.json'
    if damage=='altered':target.write_bytes(static.SCOPE_PATH.read_bytes()+b' ')
    elif damage=='oversize':target.write_bytes(b' '*(static.MAX_REGISTRY_BYTES+1))
    monkeypatch.setattr(static,'SCOPE_PATH',target);static._scope.cache_clear()
    try:
        with pytest.raises((OSError,ValueError)):static.includes_in_hacktricks('analysis.internet_exposure')
    finally:static._scope.cache_clear()
