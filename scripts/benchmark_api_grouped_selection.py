"""Compare complete offline API responses; synthetic rows, no provider calls."""
import argparse, copy, hashlib, importlib.util, json, statistics, sys, tempfile, time, tracemalloc
from pathlib import Path
from fastapi.testclient import TestClient
from peaso.auth import Identity
from peaso.server.config import Settings
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--baseline',type=Path,required=True)
parser.add_argument('--candidate',type=Path,default=ROOT/'peaso/server/app.py')
parser.add_argument('--candidate-first',action='store_true')
args=parser.parse_args()
SCAN='1'*32
class Users:
 def authenticate(self,header):return Identity('alice')
class Store:
 def job(self,tenant,ident):
  assert tenant=='alice' and ident==SCAN
  return {'id':SCAN,'status':'completed','report':'manifest'}
 def public_job(self,row):return {'runtime':{}}
class Artifacts:
 def __init__(self):
  self.rows=[{'id':f'finding-{i:07d}','check_id':f'fixture.check-{i%60:03d}','provider':'aws',
   'scope':f'{100000000000+i%3}/us-east-1','status':('FAIL','PASS','UNKNOWN')[i%3],
   'resource_id':f'resource-{30000-i:07d}','severity':('high','medium','low')[i%3],
   'service':'ec2','category':'hardening'}for i in range(30000)]
  self.meta={f'fixture.check-{i:03d}':{'title':f'Archived title {i:03d}','description':'Synthetic archived description',
   'service':'ec2','category':'hardening','severity':'high'}for i in range(60)}
 def get(self,tenant,reference):
  assert tenant=='alice'
  if reference=='index':return {'items':copy.deepcopy(self.rows)}
  assert reference=='manifest'
  return {'bundle_version':1,'summary':{'provider':'aws','stats':{}},'finding_count':len(self.rows),
   'finding_chunks':[{'index_reference':'index'}],'check_meta':copy.deepcopy(self.meta),
   'check_frameworks':{cid:['Reviewed']for cid in self.meta},'framework_filters':{}}

def load(which):
 path=args.baseline if which=='baseline'else args.candidate
 name='peaso.server._selection_'+which
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
 return module

def run():
 queries=[('findings',{'aggregation':'check','limit':50}),('summary',{'aggregation':'check'}),
  ('findings',{'aggregation':'check','status':'FAIL','sort_by':'title','sort_order':'desc','offset':4,'limit':20}),
  ('findings',{'aggregation':'none','sort_by':'severity','offset':100,'limit':50})]
 outputs={};measurements={}
 for which in (('candidate','baseline')if args.candidate_first else('baseline','candidate')):
  module=load(which)
  with tempfile.TemporaryDirectory()as folder:
   settings=Settings(state_dir=Path(folder)/'state',identity_dir=Path(folder)/'identity')
   with TestClient(module.create_app(settings,store=Store(),authenticator=Users(),artifacts=Artifacts()),base_url='http://127.0.0.1:8000')as client:
    measurements[which]=[];outputs[which]=[]
    for route,params in queries:
     url=f'/api/scans/{SCAN}/{route}'
     def request():
      response=client.get(url,params=params,headers={'Authorization':'Bearer alice'});assert response.status_code==200,response.text
      return response.json()
     value=request();outputs[which].append(value)
     timings=[]
     for _ in range(3):
      cpu=time.process_time();wall=time.perf_counter();assert request()==value
      timings.append({'cpu':time.process_time()-cpu,'wall':time.perf_counter()-wall})
     tracemalloc.start();assert request()==value;_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
     measurements[which].append({'route':route,'params':params,'cpu_median':statistics.median(row['cpu']for row in timings),
       'wall_median':statistics.median(row['wall']for row in timings),'allocation_peak_bytes':peak,'samples':timings})
 assert outputs['baseline']==outputs['candidate']
 print(json.dumps({'synthetic_only':True,'cloud_calls':0,'rows':30000,'parity':True,
  'response_sha256':hashlib.sha256(json.dumps(outputs['baseline'],sort_keys=True).encode()).hexdigest(),'measurements':measurements},indent=2),flush=True)
if __name__=='__main__':run()
