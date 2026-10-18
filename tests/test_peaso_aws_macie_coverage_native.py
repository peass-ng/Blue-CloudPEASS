"""Actual botocore shapes through real collect_live -> signed frozen engine."""
import copy,json
from datetime import datetime,timezone
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.engine import evaluate_snapshot
CHECK='aws_cis_s3_macie_classification_coverage'
KIND='s3_macie_region_coverage'
BUCKET='native-classification-fixture'
JOB='a'*32

def capture(sdk,monkeypatch,mode='automatic',explicit=False,planned=False,max_calls=None):
 session,add=sdk;sts=add('sts');ec2=add('ec2');s3=add('s3');macie=add('macie2')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':'arn:aws:iam::'+ACCOUNT+':user/reviewer','UserId':'reviewer'}, {})
 regions=[{'RegionName':REGION,'OptInStatus':'opt-in-not-required'},{'RegionName':'us-west-2','OptInStatus':'opted-in'},{'RegionName':'af-south-1','OptInStatus':'not-opted-in'}]
 if mode=='duplicateregion':regions.append(copy.deepcopy(regions[0]))
 if mode=='invalidregion':regions[1]['OptInStatus']='invented'
 if mode=='foreignpartition':regions[1]['RegionName']='cn-north-1'
 if mode=='regionsdenied':ec2.add_client_error('describe_regions','UnauthorizedOperation',http_status_code=403,expected_params={'AllRegions':True})
 else:ec2.add_response('describe_regions',{'Regions':regions},{'AllRegions':True})
 s3.add_response('list_buckets',{'Buckets':[{'Name':BUCKET,'CreationDate':datetime.now(timezone.utc)}]}, {})
 s3.add_response('get_bucket_location',{'LocationConstraint':'us-west-2'}if mode=='westbucket'else{}, {'Bucket':BUCKET})
 for op in ['get_public_access_block','get_bucket_policy_status','get_bucket_policy','get_bucket_encryption','get_bucket_versioning','get_bucket_acl','get_bucket_ownership_controls','get_bucket_logging','get_bucket_lifecycle_configuration','get_bucket_notification_configuration','get_bucket_replication','get_object_lock_configuration','get_bucket_tagging','get_bucket_website']:
  s3.add_client_error(op,'AccessDenied',http_status_code=403,expected_params={'Bucket':BUCKET})
 for n,region in enumerate([REGION,'us-west-2']):
  if mode in ('duplicateregion','invalidregion','foreignpartition','regionsdenied')or explicit:break
  if mode=='sessiondenied'and n==0:
   macie.add_client_error('get_macie_session','AccessDeniedException',http_status_code=403,expected_params={});break
  if mode=='session404'and n==0:
   macie.add_client_error('get_macie_session','ResourceNotFoundException',http_status_code=404,expected_params={});break
  if mode.startswith('serviceoff'):
   macie.add_client_error('get_macie_session','AccessDeniedException',service_message='Macie is not enabled.' if mode=='serviceoffperiod' else 'Macie is not enabled',http_status_code=403,expected_params={})
   if mode=='serviceoffstalejobs':
    macie.add_response('list_classification_jobs',{'items':[{'jobId':JOB}]},{});break
   macie.add_client_error('list_classification_jobs','UnknownOperationException' if mode=='serviceoffunsupported' else 'AccessDeniedException',service_message='Unknown Operation' if mode=='serviceoffunsupported' else 'Access denied' if mode=='serviceoffjobsdenied' else 'Macie is not enabled',http_status_code=403,expected_params={})
   if mode in ('serviceoffjobsdenied','serviceoffunsupported'):break
   continue
  if mode=='similardenial':
   macie.add_client_error('get_macie_session','AccessDeniedException',service_message='Macie is not enabled for this caller',http_status_code=403,expected_params={});break
  macie.add_response('get_macie_session',{'status':'PAUSED'if mode=='paused'else'ENABLED','serviceRole':'arn:aws:iam::'+('999999999999'if mode=='foreignrole'else ACCOUNT)+':role/aws-service-role/macie'}, {})
  if mode=='foreignrole':break
  if mode!='paused':
   if mode=='discoverydenied'and n==0:
    macie.add_client_error('get_automated_discovery_configuration','AccessDeniedException',http_status_code=403,expected_params={});break
   macie.add_response('get_automated_discovery_configuration',{'status':'ENABLED'if mode in ('automatic','scopedautomatic')else'DISABLED',**({'classificationScopeId':'scope-fixture'}if mode=='scopedautomatic'else{})}, {})
  if mode=='unrelateddenied'and n==1:
   macie.add_client_error('list_classification_jobs','AccessDeniedException',http_status_code=403,expected_params={});break
  hasjob=mode in ('job','completejob','wrongbucket','foreignjob','partialjobs','criteria','unsupported','canceled','tags','foreignrole','wrongjobid','detaildenied','missingstatus','wrongjobregion','unrelateddenied','objectscope','partialSampling','missingSampling','boolSampling')and n==0 or mode in('westjob','westbucket')and n==1
  macie.add_response('list_classification_jobs',{'items':[{'jobId':JOB}]if hasjob else[],**({'nextToken':'next'}if mode=='partialjobs'and n==0 else{})}, {})
  if mode=='partialjobs':break
  if hasjob:
   definition={'bucketDefinitions':[{'accountId':ACCOUNT,'buckets':['other-bucket'if mode=='wrongbucket'else BUCKET]}]}
   if mode in ('criteria','unsupported'):
    definition={'bucketCriteria':{'includes':{'and':[{'simpleCriterion':{'key':'S3_BUCKET_EFFECTIVE_PERMISSION'if mode=='unsupported'else'S3_BUCKET_NAME','comparator':'EQ','values':[BUCKET]}}]}}}
   if mode=='tags':definition={'bucketCriteria':{'includes':{'and':[{'tagCriterion':{'comparator':'EQ','tagValues':[{'key':'private-marker','value':'private-marker'}]}}]}}}
   if mode=='detaildenied':
    macie.add_client_error('describe_classification_job','AccessDeniedException',http_status_code=403,expected_params={'jobId':JOB});break
   job={'jobId':JOB,'jobArn':'arn:aws:macie2:'+region+':'+('999999999999'if mode=='foreignjob'else ACCOUNT)+':classification-job/'+JOB,'jobStatus':'CANCELLED'if mode=='canceled'else'COMPLETE'if mode=='completejob'else'RUNNING','s3JobDefinition':definition,'samplingPercentage':100,'name':'private-marker','description':'private-marker'}
   if mode=='objectscope':job['s3JobDefinition']['scoping']={'excludes':{'and':[{'simpleScopeTerm':{'key':'OBJECT_KEY','comparator':'STARTS_WITH','values':['private-marker']}}]}}
   if mode=='partialSampling':job['samplingPercentage']=50
   if mode=='boolSampling':job['samplingPercentage']=True
   if mode=='missingSampling':job.pop('samplingPercentage')
   if mode=='wrongjobregion':job['jobArn']=job['jobArn'].replace(':us-east-1:',':us-west-2:')
   if mode=='wrongjobid':job['jobId']='b'*32
   if mode=='missingstatus':job.pop('jobStatus')
   macie.add_response('describe_classification_job',job,{'jobId':JOB})
   if mode in('wrongjobid','missingstatus','wrongjobregion'):break
   if mode=='foreignjob':break
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture'))
 options={'service_concurrency':1,'retry_attempts':1,**({'max_calls':max_calls}if max_calls else{}),**({'regions':[REGION]}if explicit else{}),**({'max_pages':1}if mode=='partialjobs'else{})}
 connector={'provider':'aws','scopes':[ACCOUNT],'options':options}
 if planned:
  from peaso.engine import collect_snapshot
  snap=collect_snapshot({'connector':connector,'checks':[CHECK]})
 else:snap=collect_live(connector,['bucket',KIND])
 finding=evaluate_snapshot(snap,checks=[CHECK])['findings'][0]
 # Some rejection paths intentionally leave queued read expectations untouched.
 return finding,snap

@pytest.mark.parametrize('mode,expected',[('automatic','UNKNOWN'),('job','PASS'),('completejob','PASS'),('criteria','PASS'),('disabled','FAIL'),('paused','FAIL'),('wrongbucket','FAIL'),('canceled','FAIL'),('unsupported','UNKNOWN'),('foreignjob','UNKNOWN'),('sessiondenied','UNKNOWN'),('session404','UNKNOWN'),('discoverydenied','UNKNOWN'),('unrelateddenied','UNKNOWN'),('partialjobs','UNKNOWN'),('duplicateregion','UNKNOWN'),('invalidregion','UNKNOWN'),('foreignpartition','UNKNOWN'),('regionsdenied','UNKNOWN')])
def test_actual_macie_account_region_native_evidence(sdk,monkeypatch,mode,expected):
 finding,snap=capture(sdk,monkeypatch,mode)
 assert finding['status']==expected,finding
 assert 'private-marker' not in json.dumps(snap)
 if mode in ('sessiondenied','discoverydenied','unrelateddenied','regionsdenied'):
  env=next(c for c in snap['collections']if c['type']==KIND)
  assert env['status']=='denied' and env['items']==[]
 if expected=='PASS':
  env=next(c for c in snap['collections']if c['type']==KIND)
  assert env['scope']==ACCOUNT+'/global'
  assert env['items'][0]['AllEnabledRegionsCollected']is True
  assert {r['Region']for r in env['items'][0]['Regions']}=={REGION,'us-west-2'}

def test_explicit_region_subset_never_becomes_account_wide(sdk,monkeypatch):
 assert capture(sdk,monkeypatch,explicit=True)[0]['status']=='UNKNOWN'


def test_real_collection_planner_selects_native_macie_account_proof(sdk,monkeypatch):
 finding,snapshot=capture(sdk,monkeypatch,mode='job',planned=True)
 assert finding['status']=='PASS'
 assert any(c['type']==KIND and c['status']=='collected'for c in snapshot['collections'])


@pytest.mark.parametrize('mode',['tags','foreignrole','wrongjobid','detaildenied','missingstatus'])
def test_native_projection_identity_and_unavailable_detail_never_pass(sdk,monkeypatch,mode):
 finding,snap=capture(sdk,monkeypatch,mode)
 assert finding['status']=='UNKNOWN'
 assert 'private-marker'not in json.dumps(snap)

def test_scan_call_limit_cannot_be_complete_macie_region_evidence(sdk,monkeypatch):
 finding,snap=capture(sdk,monkeypatch,max_calls=3)
 assert finding['status']=='UNKNOWN'
 assert not any(row.get('AllEnabledRegionsCollected')is True for env in snap['collections']if env['type']==KIND for row in env['items'])


def test_empty_native_jobs_do_not_claim_unperformed_job_detail_operation(sdk,monkeypatch):
 finding,snap=capture(sdk,monkeypatch,mode='disabled')
 assert finding['status']=='FAIL'
 row=next(c for c in snap['collections']if c['type']==KIND)['items'][0]
 assert 'macie2:DescribeClassificationJob'not in row['_provenance']['operations']


@pytest.mark.parametrize('mode,expected',[('westjob','FAIL'),('westbucket','PASS'),('wrongjobregion','UNKNOWN')])
def test_actual_bucket_location_selects_only_same_region_jobs(sdk,monkeypatch,mode,expected):
 finding,snap=capture(sdk,monkeypatch,mode)
 assert finding['status']==expected,finding


def test_automated_enabled_with_scope_id_cannot_claim_bucket_scope(sdk,monkeypatch):
 finding,snap=capture(sdk,monkeypatch,mode='scopedautomatic')
 assert finding['status']=='UNKNOWN'
 env=next(c for c in snap['collections']if c['type']==KIND)
 assert env['status']=='not_collected'and env['items']==[]
 assert env['error']['code']=='macie_automated_scope_unresolved'


@pytest.mark.parametrize('mode,reason',[('objectscope','object_scope_unresolved'),('partialSampling','full_sampling_unproven'),('missingSampling','full_sampling_unproven'),('boolSampling','full_sampling_unproven')])
def test_object_exclusions_or_unproven_full_sampling_never_cover_whole_bucket(sdk,monkeypatch,mode,reason):
 finding,snap=capture(sdk,monkeypatch,mode)
 assert finding['status']=='UNKNOWN'
 assert 'private-marker'not in json.dumps(snap)
 row=next(c for c in snap['collections']if c['type']==KIND)['items'][0]
 job=row['Regions'][0]['Jobs']['items'][0]
 assert job['s3JobDefinition']=={}
 assert job['_provenance']['reason']==reason


@pytest.mark.parametrize('mode,expected',[('serviceoff','FAIL'),('serviceoffperiod','FAIL'),('serviceoffjobsdenied','UNKNOWN'),('serviceoffunsupported','UNKNOWN'),('serviceoffstalejobs','UNKNOWN'),('sessiondenied','UNKNOWN'),('session404','UNKNOWN'),('similardenial','UNKNOWN')])
def test_exact_provider_service_state_requires_independent_native_jobs_read(sdk,monkeypatch,mode,expected):
 finding,snapshot=capture(sdk,monkeypatch,mode)
 assert finding['status']==expected,finding
 assert 'Macie is not enabled'not in json.dumps(snapshot)
 env=next(c for c in snapshot['collections']if c['type']==KIND)
 if expected=='FAIL':
  row=env['items'][0]
  for regional in row['Regions']:
   assert regional['Session']['status']=='DISABLED'
   assert regional['Session']['_provenance']=={'service_state':'service_not_enabled','original_collection_status':'empty'}
   assert regional['Jobs']=={'collection_status':'empty','items':[]}
  assert 'macie2:ListClassificationJobs'in row['_provenance']['operations']
 else:assert env['items']==[]
