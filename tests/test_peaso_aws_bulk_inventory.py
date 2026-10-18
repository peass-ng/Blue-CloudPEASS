"""Real SDK shapes and pagination/failure boundaries for bulk AWS inventory."""
import json
from contextlib import ExitStack
from datetime import datetime, timezone
import boto3
import pytest
from botocore.stub import Stubber
from peaso.collectors import aws
from peaso.collectors import aws_bulk_inventory as facts
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot

ACCOUNT='123456789012'
REGION='us-east-1'
PLAN=f'arn:aws:backup:{REGION}:{ACCOUNT}:restore-testing-plan:qa'
MONITOR=f'arn:aws:ce::{ACCOUNT}:anomalymonitor/qa'
SUBSCRIPTION=f'arn:aws:ce::{ACCOUNT}:anomalysubscription/qa'
API=f'arn:aws:appsync:{REGION}:{ACCOUNT}:apis/qa'
ACL=f'arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/qa/12345678-1234-1234-1234-123456789012'

def web_acl(arn=ACL):
 return {'ARN':arn,'Name':'qa','Id':'12345678-1234-1234-1234-123456789012','DefaultAction':{'Allow':{}},
  'VisibilityConfig':{'SampledRequestsEnabled':True,'CloudWatchMetricsEnabled':True,'MetricName':'qa'}}

@pytest.mark.parametrize('associated,expected',[(True,'PASS'),(False,'FAIL')])
def test_native_appsync_waf_association_and_proven_absence(sdk,associated,expected):
 session,add=sdk;apis=add('appsync');waf=add('wafv2')
 api={'apiId':'qa','arn':API,'name':'qa'}
 apis.add_response('list_graphql_apis',{'graphqlApis':[api]}, {})
 waf.add_response('get_web_acl_for_resource',{'WebACL':web_acl()}if associated else{}, {'ResourceArn':API})
 requests=aws.Requests({});read=facts.FETCHERS['wafv2_appsync_association'](requests,session,REGION,ACCOUNT)
 assert read.status=='collected' and read.items[0]['WebACLArn']==(ACL if associated else'')
 assert requests.pages(session,'appsync',REGION,'list_graphql_apis','graphqlApis').items==[api]
 assert requests.calls==2
 scope=f'{ACCOUNT}/{REGION}'
 snapshot=make_snapshot('aws',[scope],[{'type':'appsync_graphql_api','scope':scope,'service':'appsync','status':'collected','items':[api]},
  {'type':'wafv2_appsync_association','scope':scope,'service':'wafv2','status':read.status,'items':read.items}])
 assert evaluate_snapshot(snapshot,checks=['aws.pci.appsync.waf_web_acl'])['findings'][0]['status']==expected
 apis.assert_no_pending_responses();waf.assert_no_pending_responses()

@pytest.mark.parametrize('failure',['AccessDeniedException','WAFNonexistentItemException'])
def test_appsync_association_errors_cannot_be_treated_as_no_firewall(sdk,failure):
 session,add=sdk;apis=add('appsync');waf=add('wafv2')
 apis.add_response('list_graphql_apis',{'graphqlApis':[{'apiId':'qa','arn':API}]}, {})
 waf.add_client_error('get_web_acl_for_resource',failure,expected_params={'ResourceArn':API})
 read=facts.FETCHERS['wafv2_appsync_association'](aws.Requests({'retries':0}),session,REGION,ACCOUNT)
 assert read.items==[] and read.status not in ('collected','empty')
 apis.assert_no_pending_responses();waf.assert_no_pending_responses()

def test_complete_empty_appsync_inventory_reuses_parent_and_does_not_call_waf(sdk):
 session,add=sdk;apis=add('appsync')
 apis.add_response('list_graphql_apis',{'graphqlApis':[]}, {})
 requests=aws.Requests({});read=facts.FETCHERS['wafv2_appsync_association'](requests,session,REGION,ACCOUNT)
 assert read.status=='empty' and requests.calls==1
 apis.assert_no_pending_responses()

@pytest.mark.parametrize('mode',['denied','truncated','foreign_api','mismatched_id','foreign_acl'])
def test_incomplete_or_foreign_appsync_enumeration_is_never_certified(sdk,mode):
 session,add=sdk;apis=add('appsync');waf=add('wafv2');options={'retries':0}
 row={'apiId':'qa','arn':API}
 if mode=='denied':apis.add_client_error('list_graphql_apis','AccessDeniedException',expected_params={})
 else:
  if mode=='foreign_api':row['arn']=API.replace(ACCOUNT,'999999999999')
  if mode=='mismatched_id':row['apiId']='foreign'
  response={'graphqlApis':[row]}
  if mode=='truncated':response['nextToken']='next';options['max_pages']=1
  apis.add_response('list_graphql_apis',response,{})
  if mode in ('foreign_acl','truncated'):
   waf.add_response('get_web_acl_for_resource',{'WebACL':web_acl(ACL.replace(ACCOUNT,'999999999999'))}if mode=='foreign_acl'else{}, {'ResourceArn':API})
 read=facts.FETCHERS['wafv2_appsync_association'](aws.Requests(options),session,REGION,ACCOUNT)
 assert read.status not in ('collected','empty')
 apis.assert_no_pending_responses();waf.assert_no_pending_responses()

@pytest.mark.parametrize('logging,expected',[('INFO','PASS'),('OFF','UNKNOWN')])
def test_rest_stage_native_alias_has_exact_identity_and_logging_evidence(sdk,logging,expected):
 from peaso.collectors import bulk_evidence
 from peaso.collectors.aws_b_services import FETCHERS
 session,add=sdk;stub=add('apigateway')
 stub.add_response('get_rest_apis',{'items':[{'id':'qa'}]}, {})
 row={'stageName':'prod','methodSettings':{'*/*':{'loggingLevel':logging}},
      'accessLogSettings':{'destinationArn':f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:qa',
                           'format':'$context.requestId $context.requestTime $context.status'}}
 stub.add_response('get_stages',{'item':[row]}, {'restApiId':'qa'})
 read=FETCHERS['rest_api_stage'](aws.Requests({}),session,REGION,ACCOUNT)
 scope=f'{ACCOUNT}/{REGION}'
 class Provider:
  AWS_TYPES={'rest_api_stage'}
  def collect(self,connector,requirements):
   assert requirements == ['rest_api_stage']
   return make_snapshot('aws',[scope],[{'type':'rest_api_stage','scope':scope,'service':'apigateway','status':read.status,'items':read.items}])
 snapshot=bulk_evidence.collect(Provider(),{'provider':'aws','options':{}},['apigateway_stage'])
 finding=evaluate_snapshot(snapshot,checks=['aws_api_customer_log_delivery'])['findings'][0]
 assert finding['status']==expected
 assert snapshot['collections'][-1]['items'][0]['id']==f'arn:aws:apigateway:{REGION}::/restapis/qa/stages/prod'
 stub.assert_no_pending_responses()

def test_denied_rest_stage_alias_cannot_certify_missing_access_logs():
 from peaso.collectors import bulk_evidence
 scope=f'{ACCOUNT}/{REGION}'
 class Provider:
  AWS_TYPES={'rest_api_stage'}
  def collect(self,connector,requirements):
   return make_snapshot('aws',[scope],[{'type':'rest_api_stage','scope':scope,'service':'apigateway','status':'denied','items':[]}])
 snapshot=bulk_evidence.collect(Provider(),{'provider':'aws','options':{}},['apigateway_stage'])
 finding=evaluate_snapshot(snapshot,checks=['aws_api_customer_log_delivery'])['findings'][0]
 assert finding['status']=='DENIED'

@pytest.mark.parametrize('mode,expected',[('native_absence','FAIL'),('unproven_absence','UNKNOWN'),('redacted_field','UNKNOWN'),('partial_inventory','UNKNOWN'),('malformed_proof','UNKNOWN')])
def test_native_optional_access_log_absence_is_independent_of_method_logging(sdk,mode,expected):
 from peaso.collectors.aws_b_services import FETCHERS
 session,add=sdk;stub=add('apigateway')
 stub.add_response('get_rest_apis',{'items':[{'id':'qa'}]}, {})
 stub.add_response('get_stages',{'item':[{'stageName':'prod','methodSettings':{}}]}, {'restApiId':'qa'})
 read=FETCHERS['rest_api_stage'](aws.Requests({}),session,REGION,ACCOUNT)
 row=read.items[0]
 if mode=='unproven_absence':del row['_provenance']['optional_fields_complete']
 if mode=='malformed_proof':row['_provenance']['optional_fields_complete']='accessLogSettings'
 if mode=='redacted_field':row['_coverage']={'accessLogSettings':{'status':'not_collected'}}
 scope=f'{ACCOUNT}/{REGION}'
 snapshot=make_snapshot('aws',[scope],[{'type':'apigateway_stage','scope':scope,'service':'apigateway',
  'status':'partial'if mode=='partial_inventory'else'collected','items':[row]}])
 finding=evaluate_snapshot(snapshot,checks=['aws_api_customer_log_delivery'])['findings'][0]
 assert finding['status']==expected
 stub.assert_no_pending_responses()

@pytest.fixture
def sdk(monkeypatch):
 session=boto3.Session(aws_access_key_id='fixture',aws_secret_access_key='fixture',region_name=REGION)
 with ExitStack() as stack:
  clients={}
  def client(service):
   value=session.client(service,region_name=REGION);clients[service]=value
   return stack.enter_context(Stubber(value))
  monkeypatch.setattr(aws.Requests,'client',lambda self,s,service,region:clients[service])
  yield session,client

def test_cost_anomaly_nonstandard_pagination_and_projection(sdk):
 session,add=sdk;stub=add('ce')
 row={'MonitorArn':MONITOR,'MonitorName':'qa','MonitorType':'DIMENSIONAL','MonitorDimension':'SERVICE'}
 stub.add_response('get_anomaly_monitors',{'AnomalyMonitors':[row],'NextPageToken':'next'}, {})
 stub.add_response('get_anomaly_monitors',{'AnomalyMonitors':[]},{'NextPageToken':'next'})
 read=facts.FETCHERS['cost_anomaly_monitor'](aws.Requests({}),session,REGION,ACCOUNT)
 assert read.status=='collected' and read.items==[row]
 stub.assert_no_pending_responses()

def test_cost_page_limit_preserves_partial_data(sdk):
 session,add=sdk;stub=add('ce');row={'MonitorArn':MONITOR,'MonitorName':'qa','MonitorType':'DIMENSIONAL'}
 stub.add_response('get_anomaly_monitors',{'AnomalyMonitors':[row],'NextPageToken':'next'}, {})
 read=facts.FETCHERS['cost_anomaly_monitor'](aws.Requests({'max_pages':1}),session,REGION,ACCOUNT)
 assert read.status=='partial' and read.items[0]['MonitorArn']==MONITOR
 stub.assert_no_pending_responses()

def test_denied_cost_subscriptions_are_not_empty(sdk):
 session,add=sdk;stub=add('ce');stub.add_client_error('get_anomaly_subscriptions','AccessDeniedException',http_status_code=403)
 read=facts.FETCHERS['cost_anomaly_subscription'](aws.Requests({'retries':0}),session,REGION,ACCOUNT)
 assert read.status=='denied' and read.items==[]
 stub.assert_no_pending_responses()

def test_restore_selection_keeps_exact_plan_binding_and_reuses_parent_read(sdk):
 session,add=sdk;stub=add('backup');plans={'RestoreTestingPlans':[{'RestoreTestingPlanName':'qa','RestoreTestingPlanArn':PLAN,'CreationTime':datetime.now(timezone.utc),'ScheduleExpression':'cron(0 0 ? * * *)'}]}
 selection={'RestoreTestingPlanName':'qa','RestoreTestingSelectionName':'s3','ProtectedResourceType':'S3',
            'IamRoleArn':f'arn:aws:iam::{ACCOUNT}:role/qa','CreationTime':datetime.now(timezone.utc)}
 stub.add_response('list_restore_testing_plans',plans,{})
 stub.add_response('list_restore_testing_selections',{'RestoreTestingSelections':[selection]}, {'RestoreTestingPlanName':'qa'})
 requests=aws.Requests({})
 assert facts.FETCHERS['backup_restore_testing_plan'](requests,session,REGION,ACCOUNT).status=='collected'
 read=facts.FETCHERS['backup_restore_testing_selection'](requests,session,REGION,ACCOUNT)
 assert read.status=='collected' and read.items==[{**selection,'id':'qa/s3'}]
 assert requests.calls==2
 stub.assert_no_pending_responses()

@pytest.mark.parametrize('fail_parent',[True,False])
def test_denied_restore_parent_or_selection_cannot_certify_absence(sdk,fail_parent):
 session,add=sdk;stub=add('backup')
 if fail_parent:stub.add_client_error('list_restore_testing_plans','AccessDeniedException',http_status_code=403)
 else:
  stub.add_response('list_restore_testing_plans',{'RestoreTestingPlans':[{'RestoreTestingPlanName':'qa','RestoreTestingPlanArn':PLAN,'CreationTime':datetime.now(timezone.utc),'ScheduleExpression':'cron(0 0 ? * * *)'}]},{})
  stub.add_client_error('list_restore_testing_selections','AccessDeniedException',http_status_code=403,expected_params={'RestoreTestingPlanName':'qa'})
 read=facts.FETCHERS['backup_restore_testing_selection'](aws.Requests({'retries':0}),session,REGION,ACCOUNT)
 assert read.status=='denied' and not read.items
 stub.assert_no_pending_responses()

def test_restore_jobs_preserve_test_origin_without_leaking_status_messages(sdk):
 session,add=sdk;stub=add('backup');now=datetime.now(timezone.utc)
 job={'RestoreJobId':'job-1','AccountId':ACCOUNT,'Status':'COMPLETED','CompletionDate':now,
      'ResourceType':'S3','CreatedBy':{'RestoreTestingPlanArn':PLAN},'StatusMessage':'sensitive-diagnostic'}
 stub.add_response('list_restore_jobs',{'RestoreJobs':[job]}, {})
 read=facts.FETCHERS['backup_restore_job'](aws.Requests({}),session,REGION,ACCOUNT)
 assert read.items[0]['CreatedBy']=={'RestoreTestingPlanArn':PLAN}
 assert 'StatusMessage' not in read.items[0]
 assert 'sensitive-diagnostic' not in json.dumps(read.items,default=str)
 stub.assert_no_pending_responses()

def test_complete_native_empty_restore_testing_inventory_is_not_applicable():
 scope=f'{ACCOUNT}/{REGION}'
 snapshot=make_snapshot('aws',[scope],[{'type':k,'scope':scope,'status':'empty','items':[]}for k in
  ('backup_restore_job','backup_restore_testing_plan','backup_restore_testing_selection')])
 report=evaluate_snapshot(snapshot,checks=['aws_backup_recent_restore_test'],include_not_applicable=True)
 assert [r['status']for r in report['findings']]==['NOT_APPLICABLE']

@pytest.mark.parametrize('attested',[True,False])
def test_ordinary_restore_job_absence_requires_native_optional_field_coverage(attested):
 scope=f'{ACCOUNT}/{REGION}'
 job={'RestoreJobId':'ordinary','AccountId':ACCOUNT}
 if attested:job['_provenance']={'source_operation':'ListRestoreJobs','read_only':True,'optional_fields_complete':['CreatedBy']}
 snapshot=make_snapshot('aws',[scope],[{'type':k,'scope':scope,'status':'collected'if k=='backup_restore_job'else 'empty',
   'items':[job]if k=='backup_restore_job'else []}for k in ('backup_restore_job','backup_restore_testing_plan','backup_restore_testing_selection')])
 report=evaluate_snapshot(snapshot,checks=['aws_backup_recent_restore_test'],include_not_applicable=True)
 assert [r['status']for r in report['findings']]==['NOT_APPLICABLE'if attested else 'UNKNOWN']

@pytest.mark.parametrize('status',['denied','partial','not_collected'])
def test_incomplete_empty_restore_inventory_stays_unknown(status):
 scope=f'{ACCOUNT}/{REGION}'
 snapshot=make_snapshot('aws',[scope],[{'type':k,'scope':scope,'status':status,'items':[]}for k in
  ('backup_restore_job','backup_restore_testing_plan','backup_restore_testing_selection')])
 report=evaluate_snapshot(snapshot,checks=['aws_backup_recent_restore_test'])
 assert not any(r['status']in ('PASS','NOT_APPLICABLE')for r in report['findings'])


def test_foreign_scope_complete_empty_inventory_cannot_establish_absence():
 own=f'{ACCOUNT}/{REGION}';foreign=f'999999999999/{REGION}'
 snapshot=make_snapshot('aws',[own],[{'type':k,'scope':foreign,'status':'empty','items':[]}for k in
  ('backup_restore_job','backup_restore_testing_plan','backup_restore_testing_selection')])
 report=evaluate_snapshot(snapshot,checks=['aws_backup_recent_restore_test'])
 assert [r['status']for r in report['findings']]==['UNKNOWN']
