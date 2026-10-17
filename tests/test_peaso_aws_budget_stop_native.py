"""Real Budgets SDK wire shapes through collector and additive signed evaluator."""
import copy,json
from datetime import datetime,timezone,timedelta
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.engine import evaluate_snapshot,collect_snapshot
from peaso.aws_budget_policy import normalize
CHECK='aws_budgets_stop_action'
ID='11111111-2222-3333-4444-555555555555'
ROLE='arn:aws:iam::'+ACCOUNT+':role/BudgetStop'


def action():
 return {'ActionId':ID,'BudgetName':'reviewed-budget','Status':'STANDBY','ActionType':'RUN_SSM_DOCUMENTS','ApprovalModel':'AUTOMATIC','NotificationType':'ACTUAL','ActionThreshold':{'ActionThresholdType':'PERCENTAGE','ActionThresholdValue':90.0},'ExecutionRoleArn':ROLE,'Definition':{'SsmActionDefinition':{'ActionSubType':'STOP_EC2_INSTANCES','Region':REGION,'InstanceIds':['i-0123456789abcdef0']}},'Subscribers':[{'Address':'private-recipient@example.invalid','SubscriptionType':'EMAIL'}]}


def options():
 now=datetime.now(timezone.utc);a=action()
 return {'regions':[REGION],'service_concurrency':1,'retry_attempts':1,'compliance_parameters':{'aws_budget_stop':{'scope':ACCOUNT+'/global','status':'collected','authorized_by':'security-owner','document_id':'stop-obligation','observed_at':(now-timedelta(minutes=1)).isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),'budgets':{'reviewed-budget':{**a['Definition']['SsmActionDefinition'],**{k:a[k]for k in('ExecutionRoleArn','ApprovalModel','NotificationType','ActionThreshold')}}}}}}


def capture(sdk,monkeypatch,mode='good',planned=False,validated_options=None):
 session,add=sdk;sts=add('sts');budgets=add('budgets')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':'arn:aws:iam::'+ACCOUNT+':user/reviewer','UserId':'reviewer'}, {})
 a=action();opts=copy.deepcopy(options()if validated_options is None else validated_options)
 if mode=='unknown_status':a['Status']='UNKNOWN_NATIVE_STATE'
 if mode=='bad_threshold':a['ActionThreshold']['ActionThresholdValue']=float('inf')
 if mode=='threshold':a['ActionThreshold']['ActionThresholdValue']=95
 if mode=='manual':a['ApprovalModel']='MANUAL'
 if mode=='forecast':a['NotificationType']='FORECASTED'
 if mode=='different_target':a['Definition']['SsmActionDefinition']['InstanceIds']=['i-11111111111111111']
 if mode=='different_region':a['Definition']['SsmActionDefinition']['Region']='us-west-2'
 if mode=='foreign_role':a['ExecutionRoleArn']=a['ExecutionRoleArn'].replace(ACCOUNT,'999999999999')
 if mode=='foreign_partition':a['Definition']['SsmActionDefinition']['Region']='cn-north-1'
 if mode=='different_role':a['ExecutionRoleArn']=ROLE+'Other'
 if mode=='duplicate_target':a['Definition']['SsmActionDefinition']['InstanceIds']*=2
 if mode=='rds':
  a['Definition']['SsmActionDefinition']={'ActionSubType':'STOP_RDS_INSTANCES','Region':REGION,'InstanceIds':['rds-database']}
  opts['compliance_parameters']['aws_budget_stop']['budgets']['reviewed-budget'].update(a['Definition']['SsmActionDefinition'])
 if mode in('PENDING','EXECUTION_IN_PROGRESS','EXECUTION_SUCCESS','EXECUTION_FAILURE','REVERSE_IN_PROGRESS','REVERSE_SUCCESS','REVERSE_FAILURE','RESET_IN_PROGRESS','RESET_FAILURE'):a['Status']=mode
 if mode in('iam','iam_bad_threshold'):a.update(ActionType='APPLY_IAM_POLICY',Definition={'IamActionDefinition':{'PolicyArn':'arn:aws:iam::'+ACCOUNT+':policy/Restrict','Roles':['BudgetStop']}})
 if mode=='iam_bad_threshold':a['ActionThreshold']['ActionThresholdValue']=float('inf')
 if mode=='empty':rows=[]
 else:rows=[copy.deepcopy(a)]
 if mode=='duplicate':rows*=2
 listargs={'AccountId':ACCOUNT}
 if mode=='list_denied':budgets.add_client_error('describe_budget_actions_for_account','AccessDeniedException',http_status_code=400,expected_params=listargs)
 else:budgets.add_response('describe_budget_actions_for_account',{'Actions':rows,**({'NextToken':'next'}if mode in('paged','partial')else{})},listargs)
 if mode=='paged':budgets.add_response('describe_budget_actions_for_account',{'Actions':[]},{**listargs,'NextToken':'next'})
 if mode not in('list_denied','empty'):
  detail={'AccountId':ACCOUNT,'BudgetName':'reviewed-budget','Action':copy.deepcopy(a)}
  if mode=='foreign_account':detail['AccountId']='999999999999'
  if mode=='wrong_id':detail['Action']['ActionId']='99999999-2222-3333-4444-555555555555'
  if mode=='wrong_budget':detail['BudgetName']='foreign-budget'
  if mode=='changed_detail':detail['Action']['ActionThreshold']['ActionThresholdValue']=99
  if mode=='detail_denied':budgets.add_client_error('describe_budget_action','AccessDeniedException',http_status_code=400,expected_params={**listargs,'BudgetName':'reviewed-budget','ActionId':ID})
  else:budgets.add_response('describe_budget_action',detail,{**listargs,'BudgetName':'reviewed-budget','ActionId':ID})
 if mode=='partial':opts['max_pages']=1
 if mode=='no_policy':opts.pop('compliance_parameters')
 if mode=='stale':opts['compliance_parameters']['aws_budget_stop']['expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
 if mode=='foreign_policy':
  opts['compliance_parameters']['aws_budget_stop']['scope']='999999999999/global'
  opts['compliance_parameters']['aws_budget_stop']['budgets']['reviewed-budget']['ExecutionRoleArn']=ROLE.replace(ACCOUNT,'999999999999')
 if mode=='unreviewed_budget':opts['compliance_parameters']['aws_budget_stop']['budgets']={'another-budget':next(iter(opts['compliance_parameters']['aws_budget_stop']['budgets'].values()))}
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture'))
 c={'provider':'aws','scopes':[ACCOUNT],'options':opts}
 snap=collect_snapshot({'connector':c,'checks':[CHECK]})if planned else collect_live(c,['budget_action'])
 findings=evaluate_snapshot(snap,checks=[CHECK],include_not_applicable=True)['findings']
 assert findings and len(findings)==1,findings
 assert 'private-recipient'not in json.dumps(snap)
 assert 'DocumentArn'not in json.dumps(snap)and'TargetRoleArns'not in json.dumps(snap)
 if findings[0]['status']=='PASS':
  sts.assert_no_pending_responses();budgets.assert_no_pending_responses()
 return findings[0],snap


@pytest.mark.parametrize('mode,status',[
 ('unknown_status','UNKNOWN'),('bad_threshold','UNKNOWN'),('good','PASS'),('rds','PASS'),('paged','PASS'),('EXECUTION_IN_PROGRESS','PASS'),
 ('threshold','FAIL'),('manual','FAIL'),('forecast','FAIL'),('different_target','FAIL'),('different_region','FAIL'),('different_role','FAIL'),('PENDING','FAIL'),('EXECUTION_SUCCESS','FAIL'),('EXECUTION_FAILURE','FAIL'),('REVERSE_IN_PROGRESS','FAIL'),('REVERSE_SUCCESS','FAIL'),('REVERSE_FAILURE','FAIL'),('RESET_IN_PROGRESS','FAIL'),('RESET_FAILURE','FAIL'),('iam','FAIL'),('iam_bad_threshold','UNKNOWN'),
 ('foreign_role','UNKNOWN'),('foreign_partition','UNKNOWN'),('duplicate_target','UNKNOWN'),('duplicate','UNKNOWN'),('foreign_account','UNKNOWN'),('wrong_id','UNKNOWN'),('wrong_budget','UNKNOWN'),('changed_detail','UNKNOWN'),('detail_denied','DENIED'),('list_denied','DENIED'),('partial','UNKNOWN'),('no_policy','UNKNOWN'),('stale','UNKNOWN'),('foreign_policy','UNKNOWN'),('unreviewed_budget','UNKNOWN'),('empty','EMPTY')])
def test_actual_budgets_sdk_to_additive_signed_engine(sdk,monkeypatch,mode,status):
 f,s=capture(sdk,monkeypatch,mode)
 assert f['status']==status,f
 if status=='PASS':
  assert next(c for c in s['collections']if c['type']=='budget_action')['scope']==ACCOUNT+'/global'
  assert f['evidence']['evidence_semantics']=='configured native stop action; execution and target instance state not observed'
 if mode in('list_denied','detail_denied'):
  assert next(c for c in s['collections']if c['type']=='budget_action')['status']=='denied'


def test_actual_planner_admits_native_account_global_kind(sdk,monkeypatch):
 assert capture(sdk,monkeypatch,planned=True)[0]['status']=='PASS'


@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_hosted_intake_roundtrip(sdk,monkeypatch,auth_mode):
 from types import SimpleNamespace
 from peaso.server.validation import validate_connector
 opts=options();opts.pop('retry_attempts')
 validate_connector('aws',{'method':'assume_role','role_arn':ROLE,'external_id':'peaso-fixture'},opts,SimpleNamespace(auth_mode=auth_mode),server_external_id=True)
 f,s=capture(sdk,monkeypatch,validated_options=opts)
 assert f['status']=='PASS'
 assert s['metadata']['parameters']['aws_budget_stop']==opts['compliance_parameters']['aws_budget_stop']


@pytest.mark.parametrize('provider',['azure','gcp','k8s'])
@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_reject_foreign_normative_namespace(provider,auth_mode):
 from types import SimpleNamespace
 from fastapi import HTTPException
 from peaso.server.validation import validate_connector
 with pytest.raises(HTTPException):validate_connector(provider,{},options(),SimpleNamespace(auth_mode=auth_mode))


@pytest.mark.parametrize('mode',['bool_threshold','nan_threshold','empty_ids','duplicate_ids','fake_observation','fake_complete','foreign_role','bad_window'])
def test_normative_policy_cannot_manufacture_native_observations(mode):
 o=options();r=o['compliance_parameters']['aws_budget_stop'];d=r['budgets']['reviewed-budget']
 if mode=='bool_threshold':d['ActionThreshold']['ActionThresholdValue']=True
 if mode=='nan_threshold':d['ActionThreshold']['ActionThresholdValue']=float('nan')
 if mode=='empty_ids':d['InstanceIds']=[]
 if mode=='duplicate_ids':d['InstanceIds']*=2
 if mode=='fake_observation':d['Status']='STANDBY'
 if mode=='fake_complete':r['complete']=True
 if mode=='foreign_role':d['ExecutionRoleArn']=ROLE.replace(ACCOUNT,'999999999999')
 if mode=='bad_window':r['observed_at']=r['expires_at']
 with pytest.raises(ValueError):normalize(o)


@pytest.mark.parametrize('tamper',['source_operation','boolean_schema','execution_observed','caller_partition','missing_partition','wrong_schema','unverified_detail','foreign_account','invalid_uuid','ambiguous_definition','missing_status','partial_collection'])
def test_imported_native_facts_keep_exact_type_identity_and_provenance_guards(sdk,monkeypatch,tamper):
 _,snap=capture(sdk,monkeypatch)
 env=next(c for c in snap['collections']if c['type']=='budget_action');a=env['items'][0]
 if tamper=='source_operation':a['_provenance']['source_operations']=['budgets:ExecuteBudgetAction']
 if tamper=='boolean_schema':a['_provenance']['native_budget_action_schema']=True
 if tamper=='execution_observed':a['_provenance']['execution_observed']=True
 if tamper=='caller_partition':snap['metadata']['caller_identities'][0]['Arn']=snap['metadata']['caller_identities'][0]['Arn'].replace('arn:aws:','arn:aws-cn:')
 if tamper=='missing_partition':a['_provenance'].pop('partition')
 if tamper=='wrong_schema':a['_provenance']['native_budget_action_schema']=2
 if tamper=='unverified_detail':a['_provenance']['detail_get_complete']=False
 if tamper=='foreign_account':a['AccountId']='999999999999'
 if tamper=='invalid_uuid':a['ActionId']='not-a-native-UUID'
 if tamper=='ambiguous_definition':a['Definition']['IamActionDefinition']={}
 if tamper=='missing_status':a.pop('Status')
 if tamper=='partial_collection':env['status']='partial'
 snap.pop('snapshot_id')
 assert all(f['status']!='PASS'for f in evaluate_snapshot(snap,checks=[CHECK])['findings'])


def test_exact_read_only_sdk_iam_mappings_are_declared_without_execute_permission():
 from peaso.collectors.aws_budget_stop_native import READ_ACTIONS,SPECS
 from scripts.peaso_deploy_customer_policy import iam_action,build_policy
 pairs=READ_ACTIONS|{SPECS['budget_action'][:2]}
 assert {iam_action(*p)for p in pairs}=={'budgets:DescribeBudgetActionsForAccount','budgets:DescribeBudgetAction'}
 policy=build_policy(pairs,include_credential_report_generation=False)
 actions={a for s in policy['Statement']for a in ([s['Action']]if isinstance(s['Action'],str)else s['Action'])}
 assert actions=={'budgets:DescribeBudgetActionsForAccount','budgets:DescribeBudgetAction'}
