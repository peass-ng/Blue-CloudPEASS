"""Canonical bytes and every distinct file survive the exact export optimization."""
import gzip,hashlib,json,zipfile
from pathlib import Path
import pytest
from scripts import peaso_deploy as deploy
PLAIN='peaso/rulepacks/upstream_manifest.json';GZIP=PLAIN+'.gz'

def test_only_byte_identical_exact_generated_companion_is_omitted():
 raw=b'{"checks":[]}\n';compressed=gzip.compress(raw,mtime=0)
 source={PLAIN:raw,GZIP:compressed,'tests/fixtures/keep.json.gz':compressed,'peaso/privesc/keep.yaml':b'techniques: []\n'}
 before=dict(source);deploy._omit_verified_duplicate_manifest(source)
 assert source=={k:v for k,v in before.items()if k!=GZIP}
 assert source[PLAIN]==raw and before[GZIP]==compressed

@pytest.mark.parametrize('data',[b'not gzip',gzip.compress(b'{"checks":[1]}',mtime=0),gzip.compress(b'{"checks":[]}\nextra',mtime=0),gzip.compress(b'{"checks":[]}\n',mtime=0)[:-4]])
def test_malformed_stale_or_longer_companion_cannot_silently_disappear(data):
 source={PLAIN:b'{"checks":[]}\n',GZIP:data};before=dict(source)
 with pytest.raises(RuntimeError,match='upstream manifest gzip'):deploy._omit_verified_duplicate_manifest(source)
 assert source==before

@pytest.mark.parametrize('name',[PLAIN,GZIP])
def test_unique_provenance_input_is_never_omitted(name):
 source={name:b'distinct bytes'};before=dict(source);deploy._omit_verified_duplicate_manifest(source);assert source==before

def test_actual_freeze_preserves_canonical_and_privilege_bytes(tmp_path,monkeypatch):
 raw=b'{"checks":[]}\n';data={PLAIN:raw,GZIP:gzip.compress(raw,mtime=0),'peaso/privesc/catalog/fixture.yaml':b'techniques: []\n','LICENSE':b'license\n','README.md':b'readme\n','pyproject.toml':b'# fixture\n','bluepeass/__init__.py':b'','bluepeass/k8s.py':b'','bluepeass/k8s_risks.py':b'','scripts/cloud_permission_risks.py':b''}
 root=tmp_path/'repository';build=tmp_path/'build'
 for name,payload in data.items():
  p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(payload)
 monkeypatch.setattr(deploy,'ROOT',root);monkeypatch.setattr(deploy,'BUILD',build)
 release=deploy.freeze_release();archive=build/('peaso-source-'+release['source_version']+'.zip')
 with zipfile.ZipFile(archive)as z:
  assert GZIP not in z.namelist()and PLAIN in z.namelist()
  for name,payload in data.items():
   assert(root/name).read_bytes()==payload
   if name!=GZIP:assert z.read(name)==payload and release['files'][name]==hashlib.sha256(payload).hexdigest()
  assert sum(i.file_size for i in z.infolist())<250000000
 assert release==deploy.freeze_release()

@pytest.mark.parametrize('changed',[PLAIN,GZIP])
def test_source_pair_changed_after_capture_aborts_export(tmp_path,changed):
 raw=b'{"checks":[]}\n';source={PLAIN:raw,GZIP:gzip.compress(raw,mtime=0)}
 for name,content in source.items():
  path=tmp_path/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
 (tmp_path/changed).write_bytes(b'{"checks":[1]}\n'if changed==PLAIN else gzip.compress(raw,mtime=1))
 before=dict(source)
 with pytest.raises(RuntimeError,match='changed during freeze'):deploy._omit_verified_duplicate_manifest(source,tmp_path)
 assert source==before
