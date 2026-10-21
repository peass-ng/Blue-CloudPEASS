"""Directed proofs of this isolated finite transition; no cloud calls."""
import importlib,inspect,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from peaso import checks
from peaso.checks import private_secret_shared_source_successor_20261021 as shared

class FiniteTransition(unittest.TestCase):
 def test_exact_callables_still_bind_live_compilation(self):
  receipt=shared._private_receipt()
  for key,transition in receipt['provider_group_callables'].items():
   with self.subTest(key=key):
    path,name=key.split(':'); module=importlib.import_module(path[:-3].replace('/','.')); fn=module
    for part in name.split('.'):
     fn=getattr(fn,part)
    row=dict(path=path,qualname=name,sha256=transition['predecessor_sha256'],defaults=fn.__defaults__,kwdefaults=fn.__kwdefaults__)
    shared._check_function(fn,row,ROOT,{})
 def test_changed_engine_disk_rejected(self):self._tamper('peaso/engine.py')
 def test_changed_azure_disk_rejected(self):self._tamper('peaso/collectors/azure.py')
 def test_changed_gcp_disk_rejected(self):self._tamper('peaso/collectors/gcp.py')
 def test_changed_aws_disk_rejected(self):self._tamper('peaso/collectors/aws.py')
 def test_changed_api_disk_rejected(self):self._tamper('peaso/server/validation.py')
 def _tamper(self,relative):
  raw=(ROOT/relative).read_bytes()
  with tempfile.TemporaryDirectory(prefix='peaso-finite-epoch-') as directory:
   isolated=Path(directory).resolve()
   path=isolated/relative;path.parent.mkdir(parents=True,exist_ok=True)
   helper=isolated/'peaso/secret_evidence.py';helper.parent.mkdir(parents=True,exist_ok=True)
   helper.write_bytes((ROOT/'peaso/secret_evidence.py').read_bytes())
   changed=raw+b'\n# deliberate finite-epoch negative witness\n';path.write_bytes(changed)
   with self.assertRaises((RuntimeError,ValueError)):
    shared._private_before(relative,changed,isolated)
 def test_engine_runtime_code_replacement_rejected(self):
  from peaso import engine
  fn=engine._selection;old=fn.__code__
  transition=shared._private_receipt()['provider_group_callables']['peaso/engine.py:_selection']
  row=dict(path='peaso/engine.py',qualname='_selection',sha256=transition['predecessor_sha256'],defaults=fn.__defaults__,kwdefaults=fn.__kwdefaults__)
  def forged(*args,**kwargs):return None
  try:
   fn.__code__=forged.__code__
   with self.assertRaises((RuntimeError,ValueError)):
    shared._check_function(fn,row,ROOT,{})
  finally:fn.__code__=old
 def test_unreviewed_callable_row_rejected(self):
  from peaso import engine
  with self.assertRaises(RuntimeError):
   shared._private_row(engine._selection,dict(path='peaso/engine.py',qualname='_selection',sha256='0'*64),ROOT)
 def test_unreviewed_fragment_rejected(self):
  row=shared._private_receipt()['provider_group_callables']['peaso/engine.py:_selection']
  with self.assertRaises(RuntimeError):shared._reverse('def _selection():\n    return True\n',row)

if __name__=='__main__':unittest.main(verbosity=2)
