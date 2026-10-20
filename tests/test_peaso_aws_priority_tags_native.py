"""Native SDK shapes through collect_live and the unchanged signed SW38 check."""
import copy
import pytest
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live, aws_priority_tags_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot

CHECK='aws_resource_priority_tags_present'
SCOPE=ACCOUNT+'/'+REGION
INSTANCE='i-0123456789abcdef0'
FUNCTION=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:worker'
DATABASE=f'arn:aws:rds:{REGION}:{ACCOUNT}:db:database'
TAGS={'classification':'internal','priority':'high'}
POLICY={'status':'collected','scope':SCOPE,'classification_tag_keys':['classification'],'priority_tag_keys':['priority'],
        'allowed_classification_values':['internal'],'allowed_priority_values':['high']}


def capture(sdk, monkeypatch, mode='good'):
 session,add=sdk;sts=add('sts');ec2=add('ec2');rds=add('rds');functions=add('lambda');s3=add('s3')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/reviewer','UserId':'reviewer'}, {})
 ec2.add_response('describe_instances',{'Reservations':[{'Instances':[{'InstanceId':INSTANCE}]}]}, {})
 tags={}if mode=='untagged'else TAGS
 if mode=='environment_tag':tags={**tags,'Environment':'production'}
 described=[{'ResourceId':INSTANCE,'ResourceType':'instance','Key':k,'Value':v}for k,v in tags.items()]
 if mode=='foreign_instance_tag':described[0]['ResourceId']='i-11111111111111111'
 if mode=='duplicate_instance_tag':described.append(copy.deepcopy(described[0]))
 params={'Filters':[{'Name':'resource-type','Values':['instance']}]}
 if mode=='ec2_tag_denied':ec2.add_client_error('describe_tags','UnauthorizedOperation',expected_params=params)
 else:
  ec2.add_response('describe_tags',{'Tags':described[:1]if mode in('partial_ec2_tags','two_pages')else described,**({'NextToken':'more'}if mode in('partial_ec2_tags','two_pages')else{})},params)
  if mode in('partial_ec2_tags','two_pages'):
   ec2.add_response('describe_tags',{'Tags':described[1:]},dict(params,NextToken='more'))
 db={'DBInstanceIdentifier':'database','DBInstanceArn':DATABASE,'TagList':[{'Key':k,'Value':v}for k,v in tags.items()]}
 if mode=='foreign_database':db['DBInstanceArn']=DATABASE.replace(ACCOUNT,'999999999999')
 if mode=='missing_database_tags':db.pop('TagList')
 if mode=='duplicate_database_tag':db['TagList'].append(copy.deepcopy(db['TagList'][0]))
 # Earlier failure stops conservatively, without making later API calls.
 early=mode in('foreign_instance_tag','duplicate_instance_tag','ec2_tag_denied')
 if not early:
  rds.add_response('describe_db_instances',{'DBInstances':[db]}, {})
 early=early or mode in('foreign_database','missing_database_tags','duplicate_database_tag')
 fn={'FunctionName':'worker','FunctionArn':FUNCTION}
 if mode=='foreign_function':fn['FunctionArn']=FUNCTION.replace(ACCOUNT,'999999999999')
 if mode=='qualified_function':fn['FunctionArn']+=':42'
 if not early:functions.add_response('list_functions',{'Functions':[fn]}, {})
 early=early or mode in('foreign_function','qualified_function')
 if not early:
  if mode=='lambda_denied':functions.add_client_error('list_tags','AccessDeniedException',expected_params={'Resource':FUNCTION})
  else:functions.add_response('list_tags',{}if mode=='missing_lambda_tags'else{'Tags':{mode.removeprefix('lambda_unsafe_'):'DO_NOT_RETAIN'}if mode.startswith('lambda_unsafe_')else tags}, {'Resource':FUNCTION})
 early=early or mode in('lambda_denied','missing_lambda_tags')or mode.startswith('lambda_unsafe_')
 if not early:
  s3.add_response('list_buckets',{'Buckets':[{'Name':'priority-fixture'}]}, {})
  location=({'LocationConstraint':'eu-west-1'}if mode=='other_home'else{'LocationConstraint':'EU'}if mode=='eu_alias'else{'ResponseMetadata':{'HTTPStatusCode':200}})
  location_params={'Bucket':'priority-fixture','ExpectedBucketOwner':ACCOUNT}
  if mode=='location_denied':s3.add_client_error('get_bucket_location','AccessDenied',expected_params=location_params)
  else:s3.add_response('get_bucket_location',{}if mode=='missing_location'else location,location_params)
  if mode not in('location_denied','missing_location','other_home','eu_alias'):
   if mode in('untagged','no_tag_set'):
    s3.add_client_error('get_bucket_tagging','NoSuchTagSet',http_status_code=404,expected_params=location_params)
   elif mode=='bucket_tag_denied':s3.add_client_error('get_bucket_tagging','AccessDenied',expected_params=location_params)
   else:
    tagged=[{'Key':k,'Value':v}for k,v in tags.items()]
    if mode=='duplicate_bucket_tag':tagged.append(copy.deepcopy(tagged[0]))
    s3.add_response('get_bucket_tagging',{'TagSet':tagged},location_params)
 if mode=='missing_bucket_tags':
  original_call=aws.Requests.call
  def missing_required_output(self,session,service,region,operation,**arguments):
   result=original_call(self,session,service,region,operation,**arguments)
   return {}if(service,operation)==('s3','get_bucket_tagging')else result
  monkeypatch.setattr(aws.Requests,'call',missing_required_output)
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture-pinned'))
 policy=copy.deepcopy(POLICY)
 if mode=='foreign_policy':policy['scope']='999999999999/'+REGION
 if mode=='empty_policy':policy['classification_tag_keys']=[]
 if mode=='duplicate_policy':policy['priority_tag_keys']*=2
 options={'service_concurrency':1,'retry_attempts':1,'compliance_policy':{'sw38_policy':policy}}
 if mode=='no_policy':options.pop('compliance_policy')
 if mode=='partial_ec2_tags':options['max_pages']=1
 connector={'provider':'aws','scopes':[SCOPE],'options':options}
 requirements=plan_collection({'connector':connector,'checks':[CHECK]})
 assert 'aws_tagged_resource'in requirements
 snap=collect_live(connector,requirements)
 findings=evaluate_snapshot(snap,checks=[CHECK])['findings']
 if mode=='partial_ec2_tags':
  # All later native reads ARE available: old dropped-cursor behavior would
  # consume them and falsely finish collected. The fixed producer must stop
  # for the actual page_limit, leaving exactly these SDK responses unused.
  assert [len(stub._queue)for stub in(sts,ec2,rds,functions,s3)]==[0,1,1,2,3]
  envelope=next(c for c in snap['collections']if c['type']=='aws_tagged_resource')
  assert envelope['status']=='partial'and envelope['error']['code']=='page_limit'
  assert snap['metadata']['calls']==3
 else:
  for stub in(sts,ec2,rds,functions,s3):stub.assert_no_pending_responses()
 return findings,snap


@pytest.mark.parametrize('mode,status,count', [('good','PASS',4),('environment_tag','PASS',4),('two_pages','PASS',4),('untagged','FAIL',4),('other_home','PASS',3),('eu_alias','PASS',3),('no_policy','UNKNOWN',4),('foreign_policy','UNKNOWN',4),('empty_policy','UNKNOWN',4),('duplicate_policy','UNKNOWN',4)])
def test_real_four_source_inventory_to_frozen_engine(sdk,monkeypatch,mode,status,count):
 findings,snap=capture(sdk,monkeypatch,mode)
 assert len(findings)==count and {f['status']for f in findings}=={status},findings
 envelope=next(c for c in snap['collections']if c['type']=='aws_tagged_resource')
 assert set(envelope['covered_source_kinds'])==set(native.SOURCE_KINDS)
 if mode=='untagged':assert all(row['Tags']=={}for row in envelope['items'])
 if mode=='environment_tag':assert all(row['Tags']['Environment']=='production'for row in envelope['items'])


def test_environment_tag_exception_keeps_runtime_and_credential_redaction():
 projected=aws._safe({'Environment':{'Variables':{'DB_PASSWORD':'DO_NOT_RETAIN'}},
                      'Tags':{'Environment':'production','ClientSecret':'DO_NOT_RETAIN'}})
 assert 'Environment'not in projected
 assert projected['Tags']['Environment']=='production'
 assert 'ClientSecret'not in projected['Tags']
 assert 'DO_NOT_RETAIN'not in str(projected)


@pytest.mark.parametrize('mode',['foreign_instance_tag','duplicate_instance_tag','ec2_tag_denied','partial_ec2_tags','foreign_database','missing_database_tags','duplicate_database_tag','foreign_function','qualified_function','lambda_denied','missing_lambda_tags','location_denied','missing_location','bucket_tag_denied','duplicate_bucket_tag','missing_bucket_tags'])
def test_incomplete_denied_or_foreign_is_never_bad_tag_absence(sdk,monkeypatch,mode):
 findings,snap=capture(sdk,monkeypatch,mode)
 assert findings and not {'PASS','FAIL'}&{f['status']for f in findings},findings
 envelope=next(c for c in snap['collections']if c['type']=='aws_tagged_resource')
 assert 'covered_source_kinds'not in envelope


def test_s3_native_no_tag_set_is_actual_failure(sdk,monkeypatch):
 findings,_=capture(sdk,monkeypatch,'no_tag_set')
 assert {f['status']for f in findings}=={'PASS','FAIL'}
 assert sum(f['status']=='FAIL'for f in findings)==1


def test_owner_policy_by_scope_roundtrip(sdk,monkeypatch):
 _,snap=capture(sdk,monkeypatch)
 snap['metadata']['compliance_policy']['sw38_policy']={'by_scope':{SCOPE:POLICY}}
 snap=make_snapshot(snap['provider'],snap['scopes'],snap['collections'],metadata=snap['metadata'],created_at=snap['created_at'])
 assert {f['status']for f in evaluate_snapshot(snap,checks=[CHECK])['findings']}=={'PASS'}


def test_two_new_read_only_actions_explicitly_require_role_review():
 assert native.READ_ACTIONS=={('ec2','describe_tags'),('lambda','list_tags')}
 assert native.READ_ACTIONS<=aws.READ_ACTIONS
 assert all(operation.startswith(('list_','describe_'))for _,operation in native.READ_ACTIONS)


def test_real_botocore_empty_location_shape_is_measured_us_east_one(sdk):
 session,_=sdk
 from botocore.parsers import ResponseParserFactory
 client=session.client('s3',region_name=REGION)
 model=client.meta.service_model
 parser=ResponseParserFactory().create_parser(model.metadata['protocol'])
 response=parser.parse({'headers':{'content-type':'application/xml'},'status_code':200,'body':b'<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>'},model.operation_model('GetBucketLocation').output_shape)
 assert 'LocationConstraint'not in response and response['ResponseMetadata']['HTTPStatusCode']==200


@pytest.mark.parametrize('service,operation,payload,params',[
 ('lambda','list_tags',{'Tags':{'clientsecret':'DO_NOT_RETAIN'}},{'Resource':FUNCTION}),
 ('ec2','describe_tags',{'Tags':[{'Key':'password','Value':'DO_NOT_RETAIN','ResourceId':INSTANCE,'ResourceType':'instance'}]},{}),
])
def test_new_tag_reads_redact_credential_literals_before_future_cache(sdk,service,operation,payload,params):
 import json
 session,add=sdk;stub=add(service);stub.add_response(operation,payload,params)
 requests=aws.Requests({})
 result=requests.call(session,service,REGION,operation,**params)
 assert 'DO_NOT_RETAIN'not in json.dumps(result)
 for future in requests._cache.values():assert 'DO_NOT_RETAIN'not in json.dumps(future.result())
 stub.assert_no_pending_responses()


@pytest.mark.parametrize('cursor',[None,'',123,False,[],{},' '*3])
def test_malformed_native_pagination_cursor_never_becomes_complete(cursor):
 with pytest.raises(aws.ReadFailure,match='native_tag_cursor_invalid'):
  native.project_tag_response({'Tags':[],'NextToken':cursor},service='ec2')


def test_native_cursor_survives_precache_tag_credential_redaction():
 response=native.project_tag_response({'Tags':[{'ResourceId':INSTANCE,'ResourceType':'instance','Key':'password','Value':'DO_NOT_RETAIN'}],'NextToken':'opaque-page-2'},service='ec2')
 assert response['NextToken']=='opaque-page-2'
 assert response['Tags'][0]['Value']=='[redacted]'
 assert response['Tags'][0]['_coverage']['Value']['status']=='not_collected'


@pytest.mark.parametrize('key',['Password','ClientSecret','Token','Code'])
def test_exact_omitted_lambda_tag_keys_never_become_false_empty(sdk,monkeypatch,key):
 findings,snap=capture(sdk,monkeypatch,'lambda_unsafe_'+key)
 assert findings and not {'PASS','FAIL'}&{f['status']for f in findings},findings
 envelope=next(c for c in snap['collections']if c['type']=='aws_tagged_resource')
 assert envelope['error']['code']=='native_tag_keys_removed_by_redaction'
 assert 'covered_source_kinds'not in envelope
 import json
 assert 'DO_NOT_RETAIN'not in json.dumps(snap)


@pytest.mark.parametrize('key',['Password','ClientSecret','Token','Code'])
def test_omitted_lambda_tag_keys_fail_closed_before_any_cache_payload(sdk,key):
 session,add=sdk;stub=add('lambda');stub.add_response('list_tags',{'Tags':{key:'DO_NOT_RETAIN'}},{'Resource':FUNCTION})
 requests=aws.Requests({})
 with pytest.raises(aws.ReadFailure,match='native_tag_keys_removed_by_redaction'):
  requests.call(session,'lambda',REGION,'list_tags',Resource=FUNCTION)
 for future in requests._cache.values():
  error=future.exception()
  assert error is not None and error.__traceback__ is None and error.__context__ is None
  assert 'DO_NOT_RETAIN'not in str(error)
 stub.assert_no_pending_responses()


@pytest.mark.parametrize('payload',[{'Tags':[],'_coverage':{'Tags':{'status':'not_collected'}}},{'Tags':[{'ResourceId':INSTANCE,'ResourceType':'instance','Key':'classification','Value':'internal','_coverage':{'Value':{'status':'not_collected'}}}]}])
def test_preexisting_redaction_coverage_is_not_dropped_into_native_evidence(payload):
 with pytest.raises(aws.ReadFailure):
  native.project_tag_response(payload,service='ec2')
