"""Complete-account native WAF logging evidence; support-end is never absence."""
import copy
from types import SimpleNamespace
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION,web_acl
from peaso.collectors import aws,collect_live
from peaso.collectors import aws_waf_inventory_native as native
from peaso.engine import evaluate_snapshot,plan_collection
from peaso.snapshot import make_snapshot
KIND='waf_account_acl_inventory';CLASSIC='aws.nist.waf_classic_regional_acl_logging';ALL='aws_nist_waf_web_acl_logging_enabled';ID='11111111-1111-1111-1111-111111111111';SCOPE=ACCOUNT+'/global'

def capture(sdk,family='v2',mode='logging',live=False,monkeypatch=None):
 session,add=sdk;classic=add('waf-regional');v2=add('wafv2');proof=aws.ReadResult([{'RegionName':REGION,'OptInStatus':'opt-in-not-required'}],'collected')
 if mode=='duplicate_region':proof.items*=2
 if mode=='disabled_region':proof.items.append({'RegionName':'us-west-2','OptInStatus':'not-opted-in'})
 if mode in ('missing_region','region_denied','duplicate_region','no_global_region'):
  if mode=='region_denied':proof=aws.ReadResult([],'denied',{'code':'UnauthorizedOperation'})
  if mode=='no_global_region':proof.items=[{'RegionName':'us-west-2','OptInStatus':'opt-in-not-required'}]
  requests=aws.Requests({});requests.backup_region_discovery={}if mode=='missing_region'else{ACCOUNT:proof};return native.inventory(requests,session,REGION,ACCOUNT),None
 classic_summary={'WebACLId':ID,'Name':'fixture'};classic_arn=f'arn:aws:waf-regional:{REGION}:{ACCOUNT}:webacl/{ID}'
 if mode=='classic_list_denied':classic.add_client_error('list_web_acls','WAFInternalErrorException',expected_params={'Limit':100});requests=aws.Requests({'retry_attempts':1});requests.backup_region_discovery={ACCOUNT:proof};return native.inventory(requests,session,REGION,ACCOUNT),None
 classic_rows=[classic_summary]if family=='classic'else[]
 response={'WebACLs':classic_rows}
 if mode=='classic_truncated':response['NextMarker']='more'
 classic.add_response('list_web_acls',response,{'Limit':100})
 if family=='classic':
  body={'WebACLId':ID,'Name':'fixture','MetricName':'fixture','DefaultAction':{'Type':'ALLOW'},'Rules':[],'WebACLArn':classic_arn}
  if mode=='foreign_classic':body['WebACLArn']=classic_arn.replace(ACCOUNT,'999999999999')
  classic.add_response('get_web_acl',{'WebACL':body},{'WebACLId':ID})
  if mode=='foreign_classic':
   requests=aws.Requests({});requests.backup_region_discovery={ACCOUNT:proof};return native.inventory(requests,session,REGION,ACCOUNT),None
  log(classic,'waf-regional',classic_arn,mode)
 for scope in ['REGIONAL','CLOUDFRONT']:
  arn=f'arn:aws:wafv2:{REGION}:{ACCOUNT}:'+('global'if scope=='CLOUDFRONT'else'regional')+'/webacl/fixture/'+ID
  rows=[{'Id':ID,'Name':'fixture','ARN':arn}]if(family=='v2'and scope=='REGIONAL')or(family=='cloudfront'and scope=='CLOUDFRONT')else[]
  if mode=='foreign_v2'and rows:rows[0]['ARN']=arn.replace(ACCOUNT,'999999999999')
  response={'WebACLs':rows}
  if mode=='pagination'and scope=='REGIONAL':v2.add_response('list_web_acls',{'WebACLs':[],'NextMarker':'more'},{'Scope':scope,'Limit':100})
  v2.add_response('list_web_acls',response,{'Scope':scope,'Limit':100,**({'NextMarker':'more'}if mode=='pagination'and scope=='REGIONAL'else{})})
  if mode=='foreign_v2'and rows:break
  if rows:
   body=web_acl(arn);body.update(Id=ID,Name='fixture')
   if mode=='detail_mismatch':body['Id']='22222222-2222-2222-2222-222222222222'
   v2.add_response('get_web_acl',{'WebACL':body},{'Scope':scope,'Name':'fixture','Id':ID})
   if mode=='detail_mismatch':break
   log(v2,'wafv2',arn,mode)
   if mode in ('log_denied','log_foreign'):break
 requests=aws.Requests({'retry_attempts':1,'max_pages':1 if mode=='classic_truncated'else 2});requests.backup_region_discovery={ACCOUNT:proof}
 if live:
  sts=add('sts');ec2=add('ec2');sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/fixture','UserId':'fixture'},{});ec2.add_response('describe_regions',{'Regions':proof.items},{'AllRegions':True})
  global_classic=add('waf');global_classic.add_response('list_web_acls',{'WebACLs':[]},{'Limit':100})
  monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture-pinned'))
  connector={'provider':'aws','scopes':[ACCOUNT],'options':{'service_concurrency':1,'retry_attempts':1}}
  snapshot=collect_live(connector,plan_collection({'connector':connector,'checks':[ALL]}));read=next(c for c in snapshot['collections']if c['type']==KIND);result=aws.ReadResult(read['items'],read['status'],read.get('error'))
 else:
  result=native.inventory(requests,session,REGION,ACCOUNT);snapshot=None
 # Failure aborts intentionally leave future sibling stubs queued; they are not called.
 return result,snapshot

def log(stub,service,arn,mode):
 params={'ResourceArn':arn}
 if mode=='absent':stub.add_client_error('get_logging_configuration','WAFNonexistentItemException',http_status_code=400,expected_params=params)
 elif mode=='log_denied':stub.add_client_error('get_logging_configuration','AccessDeniedException',http_status_code=403,expected_params=params)
 else:stub.add_response('get_logging_configuration',{'LoggingConfiguration':{'ResourceArn':arn.replace(ACCOUNT,'999999999999')if mode=='log_foreign'else arn,'LogDestinationConfigs':[]if mode=='empty_logging'else[f'arn:aws:firehose:{REGION}:{ACCOUNT}:deliverystream/aws-waf-logs-fixture']}},params)

def findings(read):
 s=make_snapshot('aws',[SCOPE],[{'type':KIND,'scope':SCOPE,'service':'wafv2','status':read.status,'items':read.items},{'type':'waf_web_acl','scope':SCOPE,'service':'waf','status':'empty','items':[]}]);return {x['check_id']:x['status']for x in evaluate_snapshot(s,checks=[CLASSIC,ALL])['findings']}

@pytest.mark.parametrize('family',['classic','v2','cloudfront'])
@pytest.mark.parametrize('mode,status',[('logging','PASS'),('absent','FAIL'),('disabled_region','PASS'),('pagination','PASS')])
def test_native_acl_shapes_and_positive_logging_absence(sdk,family,mode,status):
 read,_=capture(sdk,family,mode);assert read.status=='collected';result=findings(read);assert result[ALL]==status
 assert result[CLASSIC]==(status if family=='classic'else'NOT_APPLICABLE')
 assert read.items[0]['_provenance']['regions']==[REGION]

@pytest.mark.parametrize('mode',['missing_region','region_denied','duplicate_region','no_global_region','classic_list_denied','classic_truncated','foreign_classic','foreign_v2','detail_mismatch','log_denied','log_foreign'])
def test_unproven_account_regions_or_child_reads_never_pass(sdk,mode):
 family='classic'if mode in ('foreign_classic','classic_truncated')else'v2';read,_=capture(sdk,family,mode)
 assert read.status not in ('collected','empty')and not read.items
 assert all(x not in ('PASS','FAIL','NOT_APPLICABLE')for x in findings(read).values())

def test_real_dispatcher_requests_global_proof_and_evaluates_global_control(sdk,monkeypatch):
 read,snapshot=capture(sdk,'v2','logging',True,monkeypatch);assert read.status=='collected'
 selected=[x for x in evaluate_snapshot(snapshot,checks=[ALL])['findings']if x['scope']==SCOPE]
 assert selected and selected[0]['status']=='PASS',selected

def test_native_inventory_does_not_add_IAM_grants():
 from scripts.peaso_deploy_customer_policy import build_policy,split_policy,iam_action
 granted={a for d in split_policy(build_policy())for s in d['Statement']for a in([s['Action']]if isinstance(s['Action'],str)else s['Action'])}
 assert native.READ_ACTIONS<=aws.READ_ACTIONS and{iam_action(*pair)for pair in native.READ_ACTIONS}<=granted

@pytest.mark.parametrize('family',['classic','v2','cloudfront'])
def test_malformed_empty_destination_list_stays_unknown(sdk,monkeypatch,family):
 original=aws.Requests.detail
 def malformed(self,session,service,region,operation,**kwargs):
  response=original(self,session,service,region,operation,**kwargs)
  if operation=='get_logging_configuration'and 'LoggingConfiguration'in response:response['LoggingConfiguration']['LogDestinationConfigs']=[]
  return response
 monkeypatch.setattr(aws.Requests,'detail',malformed)
 read,_=capture(sdk,family,'logging');assert read.status=='malformed'and findings(read)[ALL]=='UNKNOWN'

def test_account_scope_dispatch_does_not_expand_to_foreign_accounts():
 from peaso.checks import CHECKS
 check=next(c for c in CHECKS if c.id==ALL)
 snapshot={'provider':'aws','scopes':[ACCOUNT+'/us-east-1',ACCOUNT+'/us-west-2'],'collections':[{'type':KIND,'scope':'999999999999/global'}]}
 assert __import__('peaso.engine',fromlist=['_scope_check_scopes'])._scope_check_scopes(snapshot,check)==[SCOPE]

def test_complete_native_empty_waf_account_is_not_a_security_pass(sdk):
 read,_=capture(sdk,'none','logging');assert read.status=='collected'
 assert findings(read)=={CLASSIC:'NOT_APPLICABLE',ALL:'NOT_APPLICABLE'}

@pytest.mark.parametrize('destination',[
 f'arn:aws:s3:::aws-waf-logs-fixture-{ACCOUNT}',f'arn:aws:s3:::aws-waf-logs-fixture-{ACCOUNT}/prefix/',
 f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:aws-waf-logs-fixture'])
def test_real_supported_log_destination_arn_shapes(sdk,monkeypatch,destination):
 original=aws.Requests.detail
 def destination_response(self,session,service,region,operation,**kwargs):
  response=original(self,session,service,region,operation,**kwargs)
  if operation=='get_logging_configuration'and 'LoggingConfiguration'in response:response['LoggingConfiguration']['LogDestinationConfigs']=[destination]
  return response
 monkeypatch.setattr(aws.Requests,'detail',destination_response);read,_=capture(sdk,'v2','logging');assert read.status=='collected'and findings(read)[ALL]=='PASS'

@pytest.mark.parametrize('destination',['arn:aws:s3:::unrelated-bucket','arn:aws:s3:::aws-waf-logs-bad..bucket','arn:aws:secretsmanager:us-east-1:123456789012:secret/fixture','arn:aws:s3:::aws-waf-logs-test/\ninvalid'])
def test_bad_log_destination_never_becomes_a_native_pass(sdk,monkeypatch,destination):
 original=aws.Requests.detail
 def destination_response(self,session,service,region,operation,**kwargs):
  response=original(self,session,service,region,operation,**kwargs)
  if operation=='get_logging_configuration'and 'LoggingConfiguration'in response:response['LoggingConfiguration']['LogDestinationConfigs']=[destination]
  return response
 monkeypatch.setattr(aws.Requests,'detail',destination_response);read,_=capture(sdk,'v2','logging');assert read.status=='malformed'and findings(read)[ALL]=='UNKNOWN'

@pytest.mark.parametrize('destination',[f'arn:aws:s3:::aws-waf-logs-fixture-{ACCOUNT}',f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:aws-waf-logs-fixture'])
def test_classic_keeps_its_documented_firehose_only_contract(sdk,monkeypatch,destination):
 original=aws.Requests.detail
 def altered(self,session,service,region,operation,**kwargs):
  response=original(self,session,service,region,operation,**kwargs)
  if operation=='get_logging_configuration'and 'LoggingConfiguration'in response:response['LoggingConfiguration']['LogDestinationConfigs']=[destination]
  return response
 monkeypatch.setattr(aws.Requests,'detail',altered);read,_=capture(sdk,'classic','logging');assert read.status=='malformed'and findings(read)[ALL]=='UNKNOWN'
