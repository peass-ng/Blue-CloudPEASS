"""Real SDK management events, source-boundary privacy and frozen SW36 evaluation."""
import copy,json
from datetime import datetime,timedelta,timezone
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.collectors import aws_ssm_inventory_events_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot
NOW=datetime(2026,10,15,tzinfo=timezone.utc);TIME=NOW-timedelta(minutes=5)
ID='11111111-1111-1111-1111-111111111111';ACTOR=f'arn:aws:iam::{ACCOUNT}:user/inventory-reader'
CHECK='aws_ssm_software_inventory_enumeration';KIND=native.KIND;SCOPE=ACCOUNT+'/'+REGION

def event(mode='good',operation='GetInventory'):
 payload={'eventID':ID,'eventName':operation,'eventTime':TIME.isoformat(),'eventSource':'ssm.amazonaws.com','awsRegion':REGION,'eventType':'AwsApiCall','eventCategory':'Management','managementEvent':True,'readOnly':True,'recipientAccountId':ACCOUNT,'userIdentity':{'arn':ACTOR,'accessKeyId':'DO_NOT_RETAIN'},'requestParameters':{'Filters':['DO_NOT_RETAIN']},'responseElements':{'inventories':'DO_NOT_RETAIN'}}
 if mode=='foreign':payload['recipientAccountId']='999999999999'
 if mode=='foreign_region':payload['awsRegion']='us-west-2'
 if mode=='mismatch_id':payload['eventID']='22222222-2222-2222-2222-222222222222'
 if mode=='wrong_source':payload['eventSource']='secretsmanager.amazonaws.com'
 if mode=='no_actor':payload['userIdentity'].pop('arn')
 if mode=='bad_actor':payload['userIdentity']['arn']='not-an-arn'
 if mode=='no_category':payload.pop('eventCategory')
 if mode=='data_event':payload['eventCategory']='Data'
 if mode=='write_event':payload['readOnly']=False
 if mode=='no_management':payload.pop('managementEvent')
 if mode=='failed':payload.update(errorCode='AccessDeniedException',errorMessage='DO_NOT_RETAIN')
 if mode=='ambiguous_error':payload['errorMessage']='DO_NOT_RETAIN'
 if mode=='null_error':payload['errorCode']=None
 if mode=='old':payload['eventTime']=(NOW-timedelta(days=2)).isoformat()
 if mode=='naive':payload['eventTime']=TIME.replace(tzinfo=None).isoformat()
 raw='{bad'if mode=='bad_json'else json.dumps(payload)
 if mode=='duplicate_key':raw=raw.replace('"recipientAccountId":','"recipientAccountId":"999999999999","recipientAccountId":')
 return {'EventId':ID,'EventName':operation,'EventTime':NOW-timedelta(days=2)if mode=='old'else TIME,'EventSource':'ssm.amazonaws.com','CloudTrailEvent':raw}

def prepare(sdk,mode='good'):
 session,add=sdk;stub=add('cloudtrail');requests=aws.Requests({'max_pages':1 if mode=='partial'else 2,'retry_attempts':1},sleep=lambda _:None);requests.observed_at=NOW
 params={'LookupAttributes':[{'AttributeKey':'EventName','AttributeValue':'GetInventory'}],'StartTime':NOW-timedelta(days=1),'EndTime':NOW}
 if mode=='denied':stub.add_client_error('lookup_events','AccessDeniedException',expected_params=params)
 else:
  response={'Events':[]if mode=='empty'else[event(mode)]}
  if mode=='duplicate':response['Events']*=2
  if mode=='partial':response['NextToken']='next'
  if mode=='paged':stub.add_response('lookup_events',{'Events':[],'NextToken':'next'},params);params={**params,'NextToken':'next'}
  stub.add_response('lookup_events',response,params)
 if mode in('good','failed','empty','paged'):
  stub.add_response('lookup_events',{'Events':[]},{'LookupAttributes':[{'AttributeKey':'EventName','AttributeValue':'ListInventoryEntries'}],'StartTime':NOW-timedelta(days=1),'EndTime':NOW})
 read=native.events(requests,session,REGION,ACCOUNT);stub.assert_no_pending_responses();return read,requests

def snapshot(read,approved=True):
 metadata={'compliance_inputs':{'approved_inventory_reader_arns':[ACTOR]if approved else[f'arn:aws:iam::{ACCOUNT}:user/other']}}
 return make_snapshot('aws',[SCOPE],[{'type':'ssm_managed_instance','scope':SCOPE,'service':'ssm','status':'empty','items':[]},{'type':KIND,'scope':SCOPE,'service':'cloudtrail','status':read.status,'items':read.items,**({'error':read.error}if read.error else{})}],metadata=metadata)

@pytest.mark.parametrize('mode,approved,expected',[('good',True,'PASS'),('good',False,'FAIL'),('failed',False,'PASS'),('empty',True,'PASS'),('paged',False,'FAIL')])
def test_native_window_reaches_frozen_evaluator_with_exact_actor_policy(sdk,mode,approved,expected):
 read,requests=prepare(sdk,mode);snap=snapshot(read,approved);findings=evaluate_snapshot(snap,checks=[CHECK])['findings'];assert len(findings)==1 and findings[0]['status']==expected,findings
 assert'DO_NOT_RETAIN'not in json.dumps(snap)
 for future in requests._cache.values():assert'DO_NOT_RETAIN'not in json.dumps(future.result(),default=str)
 if read.items:assert read.items[0]['_provenance']['window_end']==NOW.isoformat()

@pytest.mark.parametrize('mode',['foreign','foreign_region','mismatch_id','wrong_source','no_actor','bad_actor','no_category','data_event','write_event','no_management','ambiguous_error','null_error','old','naive','bad_json','duplicate_key','duplicate','partial','denied'])
def test_unbound_denied_partial_or_ambiguous_observations_stay_unknown(sdk,mode):
 read,requests=prepare(sdk,mode);assert read.status not in('collected','empty')and read.items==[]
 assert all(f['status'] not in ('PASS','FAIL','NOT_APPLICABLE')for f in evaluate_snapshot(snapshot(read),checks=[CHECK])['findings'])
 for future in requests._cache.values():
  error=future.exception()
  if error is not None:assert error.__traceback__ is None and error.__context__ is None and'DO_NOT_RETAIN'not in str(error)

def test_missing_owner_baseline_is_not_implicitly_approved(sdk):
 read,_=prepare(sdk);snap=snapshot(read);snap['metadata'].pop('compliance_inputs');snap=make_snapshot('aws',snap['scopes'],snap['collections'],metadata=snap['metadata'],created_at=snap['created_at'])
 assert evaluate_snapshot(snap,checks=[CHECK])['findings'][0]['status']=='UNKNOWN'

@pytest.mark.parametrize('values',[None,[],[ACTOR,ACTOR],['invalid'],[True]])
def test_invalid_normative_reader_input_rejected_before_any_auth(monkeypatch,values):
 monkeypatch.setattr(aws,'_session',lambda *args:pytest.fail('invalid owner input reached credentials'))
 with pytest.raises(ValueError):collect_live({'provider':'aws','scopes':[SCOPE],'options':{'compliance_parameters':{'approved_inventory_reader_arns':values}}},[KIND])

@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
def test_collect_live_real_planning_and_normative_projection(sdk,monkeypatch,auth_mode):
 session,add=sdk;sts=add('sts');logs=add('cloudtrail');ssm=add('ssm')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/fixture','UserId':'fixture'},{});ssm.add_response('describe_instance_information',{'InstanceInformationList':[]},{})
 for name in sorted(native.OPERATIONS):logs.add_response('lookup_events',{'Events':[event(operation=name)]if name=='GetInventory'else[]},{'LookupAttributes':[{'AttributeKey':'EventName','AttributeValue':name}],'StartTime':NOW-timedelta(days=1),'EndTime':NOW})
 original=aws.Requests.__init__
 def initialized(self,*args,**kw):kw['sleep']=lambda _:None;original(self,*args,**kw);self.observed_at=NOW
 monkeypatch.setattr(aws.Requests,'__init__',initialized);monkeypatch.setattr(aws,'_session',lambda *args:(session,'fixture'))
 connector={'provider':'aws','scopes':[SCOPE],'options':{'service_concurrency':1,'compliance_parameters':{'approved_inventory_reader_arns':[ACTOR]}}}
 from types import SimpleNamespace
 from peaso.server.validation import validate_connector
 approved_options=copy.deepcopy(connector['options'])
 auth={'method':'assume_role','role_arn':f'arn:aws:iam::{ACCOUNT}:role/InventoryAudit','external_id':'peaso-fixture'}
 validate_connector('aws',auth,connector['options'],SimpleNamespace(auth_mode=auth_mode),server_external_id=True)
 assert connector['options']==approved_options
 captured=collect_live(connector,plan_collection({'connector':connector,'checks':[CHECK]}));findings=evaluate_snapshot(captured,checks=[CHECK])['findings'];assert findings[0]['status']=='PASS',findings
 assert captured['metadata']['compliance_inputs']=={'approved_inventory_reader_arns':[ACTOR]}
 assert'DO_NOT_RETAIN'not in json.dumps(captured);sts.assert_no_pending_responses();logs.assert_no_pending_responses();ssm.assert_no_pending_responses()

@pytest.mark.parametrize('attributes',[[{'AttributeKey':'EventSource','AttributeValue':'ssm.amazonaws.com'}],[{'AttributeKey':'EventName','AttributeValue':'GetInventory','extra':'bad'}],[{'AttributeKey':'EventName','AttributeValue':'PutInventory'}]])
def test_arbitrary_queries_rejected_without_client_creation(monkeypatch,attributes):
 requests=aws.Requests({});monkeypatch.setattr(requests,'client',lambda *args:pytest.fail('unapproved query client'))
 with pytest.raises(aws.ReadFailure):requests.call(object(),'cloudtrail',REGION,'lookup_events',LookupAttributes=attributes,StartTime=TIME,EndTime=NOW)
 assert requests.calls==0

@pytest.mark.parametrize('mode',['second_denied','cross_query_duplicate'])
def test_later_query_failure_discards_earlier_successful_pages(sdk,mode):
 session,add=sdk;stub=add('cloudtrail');requests=aws.Requests({'retry_attempts':1},sleep=lambda _:None);requests.observed_at=NOW
 for name in sorted(native.OPERATIONS):
  params={'LookupAttributes':[{'AttributeKey':'EventName','AttributeValue':name}],'StartTime':NOW-timedelta(days=1),'EndTime':NOW}
  if name=='ListInventoryEntries'and mode=='second_denied':stub.add_client_error('lookup_events','AccessDeniedException',expected_params=params)
  else:stub.add_response('lookup_events',{'Events':[event(operation=name)]},params)
 read=native.events(requests,session,REGION,ACCOUNT);assert read.items==[]and read.status not in('collected','empty');stub.assert_no_pending_responses()
 assert all(f['status']not in('PASS','FAIL')for f in evaluate_snapshot(snapshot(read),checks=[CHECK])['findings'])

def test_query_names_do_not_change_existing_activity_projection():
 assert not native.OPERATIONS&set(aws.activity_event_names(REGION))


@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
def test_approved_reader_namespace_is_admitted_for_aws_intake(auth_mode):
 from types import SimpleNamespace
 from peaso.server.validation import validate_connector
 options={'compliance_parameters':{'approved_inventory_reader_arns':[ACTOR]}}
 original=copy.deepcopy(options)
 auth={'method':'assume_role','role_arn':f'arn:aws:iam::{ACCOUNT}:role/InventoryAudit','external_id':'peaso-fixture'}
 validate_connector('aws',auth,options,SimpleNamespace(auth_mode=auth_mode),server_external_id=True)
 assert options==original


@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
@pytest.mark.parametrize('value', [None, [], [ACTOR, ACTOR], ['invalid'], [True]])
def test_bad_readers_are_rejected_by_normative_intake_before_auth(auth_mode,provider,value):
 from types import SimpleNamespace
 from fastapi import HTTPException
 from peaso.server.validation import validate_connector
 options={'compliance_parameters':{'approved_inventory_reader_arns':copy.deepcopy(value)}}
 with pytest.raises(HTTPException) as error:
  validate_connector(provider,{},options,SimpleNamespace(auth_mode=auth_mode))
 assert error.value.status_code==422
 assert error.value.detail=='Invalid AWS inventory reader owner policy'


@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
@pytest.mark.parametrize('provider', ['gcp', 'azure', 'k8s'])
def test_valid_readers_reject_foreign_provider_before_auth(auth_mode,provider):
 from types import SimpleNamespace
 from fastapi import HTTPException
 from peaso.server.validation import validate_connector
 with pytest.raises(HTTPException) as error:
  validate_connector(provider,{}, {'compliance_parameters':{'approved_inventory_reader_arns':[ACTOR]}},SimpleNamespace(auth_mode=auth_mode))
 assert error.value.status_code==422
 assert error.value.detail=='Invalid AWS inventory reader owner policy'
