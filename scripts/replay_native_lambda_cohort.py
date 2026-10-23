"""Offline real SDK Stubber -> original Requests.call -> candidate projection.

No registered-evaluator admission is bypassed or claimed here. Root owns that
finite successor gate. Only synthetic responses, counts and safe hashes logged.
"""
import importlib.util,json,resource,sys,time,hashlib,os
FULL_STARTED=time.monotonic()
from pathlib import Path
from contextlib import ExitStack
import boto3
from botocore.stub import Stubber
import peaso,peaso.collectors
from peaso import secret_scanning as scanner,secret_evidence as evidence
from peaso.collectors import aws

ROOT=Path('/candidate')
def load(name,path,parent,attribute):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);setattr(parent,attribute,module);return module
batch=load('peaso.secret_scanning_batch',ROOT/'peaso/secret_scanning_batch.py',peaso,'secret_scanning_batch')
load('peaso.secret_scanning_cohort',ROOT/'peaso/secret_scanning_cohort.py',peaso,'secret_scanning_cohort')
source=load('peaso.collectors.aws_lambda_environment_secret_indicators',ROOT/'peaso/collectors/aws_lambda_environment_secret_indicators.py',peaso.collectors,'aws_lambda_environment_secret_indicators')
scanner._prepared_trufflehog_output=batch.prepared_output
scanner.prepared_content_batch=batch.prepared_content_batch
ACCOUNT='123456789012';REGION='us-east-1';SCOPE=ACCOUNT+'/'+REGION
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
CALLER={'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/offline'}
count=int(os.environ.get('COHORT_TARGETS','32'));positive=os.environ.get('COHORT_POSITIVE','1')=='1'
targets=[f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:Synthetic{i}'for i in range(count)]
options={'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND],'retry_attempts':1,'service_concurrency':8}
requests=aws.Requests(options);requests.content_secret_scan_kinds=frozenset([source.KIND])
native=boto3.Session(aws_access_key_id='offline-native-key',aws_secret_access_key='offline-native-secret',region_name=REGION)
clients={arn:native.client('lambda',region_name=REGION)for arn in targets}
class Router:
    def get_function_configuration(self,**kwargs):return clients[kwargs['FunctionName']].get_function_configuration(**kwargs)
class Session:
    def client(self,service,**kwargs):
        assert service=='lambda' and kwargs['region_name']==REGION
        return Router()
session=Session();started=time.monotonic();cpu_started=time.process_time();batches=[];cipher=evidence.EphemeralCipher()
with ExitStack()as stack:
    stubs=[]
    for index,arn in enumerate(targets):
        stub=stack.enter_context(Stubber(clients[arn]));stubs.append(stub)
        stub.add_response('get_function_configuration',{'FunctionArn':arn,'FunctionName':arn.rsplit(':',1)[1],
            'Version':'$LATEST','RevisionId':'11111111-1111-4111-8111-111111111111',
            'State':'Active','LastUpdateStatus':'Successful','Environment':{'Variables':dict({'Mode':f'synthetic-{index}'},**({'AccessToken':TOKEN}if positive else{}))},
            'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'22222222-2222-4222-8222-222222222222'}},
            {'FunctionName':arn})
    with evidence.capture(cipher,tenant='synthetic',scan_id='1'*32)as sink:
        for offset in range(0,count,8):
            selected=targets[offset:offset+8];planned=dict(options,**{source.OPTION:selected})
            source.initialize(requests,planned,[SCOPE]);began=time.monotonic()
            result=source.collect_selected(requests,session,REGION,CALLER,planned,[SCOPE])
            batches.append({'targets':len(result.items),'complete':sum(item[source.MARKER]['complete']for item in result.items),
                'wall_seconds':time.monotonic()-began,'within_shared_deadline':time.monotonic()-began<=60,'status':result.status})
            assert [item['id']for item in result.items]==[source.identity(arn)for arn in selected]
        locations=[loc for record in sink.records.values()for loc in cipher.decrypt(record)['locations']]
        assert {loc['resource_id']for loc in locations}==(set(targets)if positive else set())
        private_locations=len(locations);capture_incomplete=sink.incomplete
    for stub in stubs:stub.assert_no_pending_responses()
public_cache=[future.result()for future in requests._cache.values()]
assert TOKEN not in json.dumps(public_cache)
assert all(isinstance(item,dict)and source.MARKER in item for item in public_cache)
used=resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps({'synthetic_only':True,'cloud_calls':0,'native_sdk_stubber':True,'requests_class_unmodified':True,
    'registered_successor_admission':'pending_root','targets':count,'positive':positive,'complete':sum(row['complete']for row in batches),
    'private_locations':private_locations,'capture_incomplete':capture_incomplete,'calls':requests.calls,
    'cache_values_projected_only':True,'wall_seconds':time.monotonic()-started,
    'parent_cpu_seconds':time.process_time()-cpu_started,'setup_cpu_seconds':cpu_started,'whole_process_wall_seconds':time.monotonic()-FULL_STARTED,'child_cpu_seconds':used.ru_utime+used.ru_stime,
    'batches':batches,'requests_source_sha256':hashlib.sha256(Path(aws.__file__).read_bytes()).hexdigest()},indent=2),flush=True)
