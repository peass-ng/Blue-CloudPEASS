"""Full offline report publication with byte-for-byte artifact conservation.

The deterministic in-memory adapter measures publication CPU/allocations, not
filesystem/S3 latency. Native catalog admission executes normally and is untimed.
"""
import argparse,hashlib,importlib.util,json,statistics,sys,time,tracemalloc
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--baseline',type=Path,required=True)
parser.add_argument('--candidate',type=Path,required=True)
parser.add_argument('--candidate-first',action='store_true')
args=parser.parse_args()
from peaso.storage.artifacts import prefix

class Artifacts:
    def __init__(self):self.documents={}
    def _put(self,tenant,scan,kind,body):
        raw=body.encode();suffix='md'if kind=='markdown'else'json'
        ref=f'{prefix(tenant)}/{scan}/{kind}-{hashlib.sha256(raw).hexdigest()[:32]}.{suffix}'
        self.documents[ref]=raw
        return ref
    def put(self,tenant,scan,kind,value):
        return self._put(tenant,scan,kind,json.dumps(value,separators=(',',':'),ensure_ascii=False,allow_nan=False))
    def put_text(self,tenant,scan,kind,value):return self._put(tenant,scan,kind,value)

report={'schema_version':'1.0','provider':'aws','snapshot_id':'synthetic','created_at':'2026-10-22T00:00:00Z',
    'scopes':['123456789012/us-east-1'],'resources':[],'coverage':[],
    'graphs':{'network':{'nodes':[],'edges':[]},'iam':{'nodes':[],'edges':[]},'privesc':{'nodes':[],'edges':[]}},
    'stats':{},'findings':[{'id':f'finding-{i:07d}','check_id':f'fixture.summary-{i%60:03d}',
        'provider':'aws','category':'hardening','title':f'Synthetic title {i%60}',
        'service':'ec2','severity':'medium','status':'FAIL'if i%3 else'PASS',
        'scope':'123456789012/us-east-1','resource_id':f'synthetic-resource-{i:07d}',
        'native_resource_id':f'synthetic-native-{i:07d}','resource_name':f'Synthetic resource {i}',
        'frameworks':['Synthetic'],'remediation':'Synthetic archived guidance','evidence':{'synthetic':True},
        'evidence_summary':'The synthetic setting is recorded.'}for i in range(30000)]}

def load(name,path):
    spec=importlib.util.spec_from_file_location('peaso.storage._publication_'+name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module

modules={name:load(name,path)for name,path in [('baseline',args.baseline),('candidate',args.candidate)]}
outputs={};metrics={name:{'samples':[]}for name in modules}
order=('candidate','baseline')if args.candidate_first else('baseline','candidate')
def publish(name):
    artifacts=Artifacts();reference=modules[name].publish_report(artifacts,'synthetic','1'*32,report)
    return reference,artifacts.documents
for name in order:outputs[name]=publish(name)
# Alternate order to reduce drift from shared-host activity and allocator cycles.
for cycle in range(3):
    for name in (order+tuple(reversed(order))):
        start=time.perf_counter();cpu=time.process_time();assert publish(name)==outputs[name]
        metrics[name]['samples'].append({'wall':time.perf_counter()-start,'cpu':time.process_time()-cpu})
for name in order:
    samples=metrics[name]['samples']
    metrics[name].update(cpu_median=statistics.median(row['cpu']for row in samples),
        wall_median=statistics.median(row['wall']for row in samples))
    tracemalloc.start();assert publish(name)==outputs[name];_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    metrics[name]['allocation_peak_bytes']=peak
assert outputs['baseline']==outputs['candidate']
reference,documents=outputs['baseline']
digest=hashlib.sha256()
for key,body in sorted(documents.items()):digest.update(key.encode());digest.update(body)
print(json.dumps({'synthetic_only':True,'cloud_calls':0,'findings':30000,'artifact_count':len(documents),
    'artifact_bytes':sum(map(len,documents.values())),'all_artifacts_equal':True,
    'artifact_sha256':digest.hexdigest(),'measurements':metrics},indent=2),flush=True)
