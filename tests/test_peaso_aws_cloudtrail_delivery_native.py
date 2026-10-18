"""Real botocore shapes through collect_live and the signed frozen engine."""
import copy,json
from datetime import datetime,timezone
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.engine import evaluate_snapshot
from peaso.collectors import aws_cloudtrail_delivery_native as native
CHECK='aws_fedramp_cloudtrail_cloudwatch_integration'
TRAIL=f'arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/native-test'
ROLE=f'arn:aws:iam::{ACCOUNT}:role/path/CloudTrailDelivery'
GROUP=f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:cloudtrail/native:*'
STREAM=f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:cloudtrail/native:log-stream:{ACCOUNT}_CloudTrail_{REGION}'

def capture(sdk,monkeypatch,mode='allow',planned=False):
 session,add=sdk;sts,ct,iam=add('sts'),add('cloudtrail'),add('iam')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/reviewer','UserId':'reviewer'}, {})
 trail={'Name':'native-test','TrailARN':TRAIL,'HomeRegion':REGION,'IsMultiRegionTrail':False,'IsOrganizationTrail':False,'CloudWatchLogsRoleArn':ROLE,'CloudWatchLogsLogGroupArn':GROUP}
 if mode=='organization':trail['IsOrganizationTrail']=True
 if mode=='multiregion':trail['IsMultiRegionTrail']=True
 if mode=='missingflags':trail.pop('IsMultiRegionTrail')
 if mode=='missingdestination':trail.pop('CloudWatchLogsRoleArn')
 if mode=='foreigngroup':trail['CloudWatchLogsLogGroupArn']=GROUP.replace(ACCOUNT,'999999999999')
 if mode=='foreigntrail':trail['TrailARN']=TRAIL.replace(ACCOUNT,'999999999999')
 if mode=='foreignregion':trail['HomeRegion']='us-west-2'
 if mode=='trailsdenied':ct.add_client_error('describe_trails','AccessDeniedException',expected_params={'includeShadowTrails':False})
 else:
  trails=[]if mode=='empty'else[trail]
  if mode=='duplicatepair':trails.append({**trail,'Name':'second','TrailARN':TRAIL+'-second'})
  if mode=='duplicatetrail':trails.append(copy.deepcopy(trail))
  ct.add_response('describe_trails',{'trailList':trails},{'includeShadowTrails':False})
  if mode not in ('empty','foreigntrail','foreignregion'):
   for n,t in enumerate(trails):
    if n and mode=='duplicatetrail':break
    if mode=='statusdenied':ct.add_client_error('get_trail_status','AccessDeniedException',expected_params={'Name':t['TrailARN']});break
    ct.add_response('get_trail_status',{'IsLogging':mode!='inactive','LatestDeliveryError':'PRIVATE_PROVIDER_MARKER'},{'Name':t['TrailARN']})
    if mode=='selectorsdenied':ct.add_client_error('get_event_selectors','AccessDeniedException',expected_params={'TrailName':t['TrailARN']});break
    ct.add_response('get_event_selectors',{'TrailARN':t['TrailARN'],'EventSelectors':[{'ReadWriteType':'All','IncludeManagementEvents':True}]},{'TrailName':t['TrailARN']})
 early={'organization','multiregion','missingflags','missingdestination','foreigngroup','foreigntrail','foreignregion','trailsdenied','empty','inactive','duplicatepair','duplicatetrail','statusdenied','selectorsdenied'}
 if mode not in early:
  stmt={'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'Service':'cloudtrail.amazonaws.com'},'Condition':{'StringEquals':{'aws:SourceAccount':ACCOUNT},'ArnEquals':{'aws:SourceArn':TRAIL}}}
  doc={'Version':'2012-10-17','Statement':[stmt]}
  if mode=='wrongtrust':stmt['Principal']={'Service':'ec2.amazonaws.com'}
  if mode=='trustdeny':doc['Statement'].append({**copy.deepcopy(stmt),'Effect':'Deny'})
  if mode=='sourceaccount':stmt['Condition']['StringEquals']['aws:SourceAccount']='999999999999'
  if mode=='sourcearn':stmt['Condition']['ArnEquals']['aws:SourceArn']=TRAIL+'-other'
  if mode=='trustvariable':stmt['Condition']['ArnEquals']['aws:SourceArn']='${aws:SourceArn}'
  if mode=='unknowntrust':stmt['Condition']['StringEquals']['sts:ExternalId']='PRIVATE_PROVIDER_MARKER'
  if mode=='trustwildcard':stmt['Condition']={'ArnLike':{'aws:SourceArn':TRAIL.rsplit('/',1)[0]+'/*'}}
  if mode=='notprincipal':stmt['NotPrincipal']=stmt.pop('Principal')
  role={'Path':'/path/','RoleName':'CloudTrailDelivery','RoleId':'AROA12345678901234567','Arn':ROLE,'CreateDate':datetime(2026,1,1,tzinfo=timezone.utc),'AssumeRolePolicyDocument':json.dumps(doc),'Description':'PRIVATE_PROVIDER_MARKER'}
  if mode=='foreignrole':role['Arn']=ROLE.replace(ACCOUNT,'999999999999')
  if mode.startswith('boundary') or mode=='versionmismatch':role['PermissionsBoundary']={'PermissionsBoundaryType':'Policy','PermissionsBoundaryArn':f'arn:aws:iam::{ACCOUNT}:policy/boundary'}
  if mode=='roledenied':iam.add_client_error('get_role','AccessDenied',expected_params={'RoleName':'CloudTrailDelivery'})
  else:iam.add_response('get_role',{'Role':role},{'RoleName':'CloudTrailDelivery'})
  if mode not in {'roledenied','foreignrole','unknowntrust','notprincipal','trustvariable'}:
   keys=['aws:RequestedRegion']if mode=='requestedregion'else['aws:SourceArn']if mode=='unknownkey'else[]
   if mode=='contextdenied':iam.add_client_error('get_context_keys_for_principal_policy','AccessDenied',expected_params={'PolicySourceArn':ROLE})
   else:iam.add_response('get_context_keys_for_principal_policy',{'ContextKeyNames':keys},{'PolicySourceArn':ROLE})
   if mode not in {'contextdenied','unknownkey'}:
    params={'PolicySourceArn':ROLE,'ActionNames':native.ACTIONS,'ResourceArns':[STREAM]}
    if keys:params['ContextEntries']=[{'ContextKeyName':'aws:RequestedRegion','ContextKeyValues':[REGION],'ContextKeyType':'string'}]
    results=[{'EvalActionName':a,'EvalResourceName':STREAM,'EvalDecision':'allowed','MissingContextValues':[]}for a in native.ACTIONS]
    if mode=='explicitdeny':results[1]['EvalDecision']='explicitDeny'
    if mode=='implicitdeny':results[1]['EvalDecision']='implicitDeny'
    if mode=='missingcontext':results[0]['MissingContextValues']=['aws:SourceAccount']
    if mode=='omittedcontext':results[0].pop('MissingContextValues')
    if mode=='missingaction':results.pop()
    if mode=='duplicateaction':results[1]=copy.deepcopy(results[0])
    if mode=='foreignresult':results[0]['EvalResourceName']=STREAM.replace(ACCOUNT,'999999999999')
    if mode=='unknownaction':results[0]['EvalActionName']='logs:DeleteLogStream'
    if mode=='unknownresult':results[0]['EvalDecision']='invented'
    if mode=='actualwire':
     for result in results:result['ResourceSpecificResults']=[{'EvalResourceName':STREAM,'EvalResourceDecision':'allowed'}]
    if mode=='specificmissing':results[0]['ResourceSpecificResults']=[{'EvalResourceName':STREAM,'EvalResourceDecision':'allowed','MissingContextValues':['aws:SourceArn']}]
    if mode=='boundaryallowed':
     for result in results:result['PermissionsBoundaryDecisionDetail']={'AllowedByPermissionsBoundary':True}
    if mode=='orgconflict':results[0]['OrganizationsDecisionDetail']={'AllowedByOrganizations':False}
    if mode=='boundaryconflict':results[0]['PermissionsBoundaryDecisionDetail']={'AllowedByPermissionsBoundary':False}
    if mode=='simdenied':iam.add_client_error('simulate_principal_policy','AccessDenied',expected_params=params)
    elif mode in {'pagination','partial'}:
     iam.add_response('simulate_principal_policy',{'EvaluationResults':results[:1],'IsTruncated':True,'Marker':'next'},params)
     if mode=='pagination':iam.add_response('simulate_principal_policy',{'EvaluationResults':results[1:],'IsTruncated':False},{**params,'Marker':'next'})
    else:iam.add_response('simulate_principal_policy',{'EvaluationResults':results,'IsTruncated':False},params)
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture'))
 options={'regions':[REGION],'service_concurrency':1,'retry_attempts':1,**({'max_pages':1}if mode=='partial'else{})}
 connector={'provider':'aws','scopes':[ACCOUNT],'options':options}
 if planned:
  from peaso.engine import collect_snapshot
  snap=collect_snapshot({'connector':connector,'checks':[CHECK]})
 else:snap=collect_live(connector,['cloudtrail_trail','cloudtrail_delivery_permission'])
 finding=evaluate_snapshot(snap,checks=[CHECK])['findings'][0]
 assert 'PRIVATE_PROVIDER_MARKER'not in json.dumps(snap)
 for stub in (sts,ct,iam):stub.assert_no_pending_responses()
 return finding,snap

@pytest.mark.parametrize('mode,expected',[
 ('actualwire','PASS'),('trustvariable','UNKNOWN'),('orgconflict','UNKNOWN'),('allow','PASS'),('explicitdeny','FAIL'),('implicitdeny','FAIL'),('wrongtrust','FAIL'),('trustdeny','FAIL'),('sourceaccount','FAIL'),('sourcearn','FAIL'),('unknowntrust','UNKNOWN'),('unknownkey','UNKNOWN'),('requestedregion','PASS'),('trustwildcard','PASS'),('notprincipal','UNKNOWN'),('missingcontext','UNKNOWN'),('omittedcontext','UNKNOWN'),('missingaction','UNKNOWN'),('duplicateaction','UNKNOWN'),('foreignresult','UNKNOWN'),('unknownaction','UNKNOWN'),('unknownresult','UNKNOWN'),('specificmissing','UNKNOWN'),('pagination','PASS'),('partial','UNKNOWN'),('boundaryallowed','PASS'),('boundarymissing','UNKNOWN'),('boundaryconflict','UNKNOWN'),('organization','UNKNOWN'),('multiregion','UNKNOWN'),('missingflags','UNKNOWN'),('duplicatepair','UNKNOWN'),('foreignrole','UNKNOWN'),('foreigngroup','UNKNOWN'),('foreigntrail','UNKNOWN'),('foreignregion','UNKNOWN'),('duplicatetrail','UNKNOWN'),('trailsdenied','DENIED'),('statusdenied','DENIED'),('selectorsdenied','DENIED'),('roledenied','UNKNOWN'),('contextdenied','UNKNOWN'),('simdenied','UNKNOWN'),('missingdestination','FAIL'),('inactive','NOT_APPLICABLE')])
def test_native_collect_to_signed_evaluate(sdk,monkeypatch,mode,expected):
 finding,snap=capture(sdk,monkeypatch,mode)
 assert finding['status']==expected,finding
 if mode in {'roledenied','contextdenied','simdenied'}:
  env=next(e for e in snap['collections']if e['type']=='cloudtrail_delivery_permission')
  assert env['status']=='denied'and env['items']==[]
 if expected=='PASS':
  row=next(e for e in snap['collections']if e['type']=='cloudtrail_delivery_permission')['items'][0]
  assert row['simulation_context_complete']is True and row['_provenance']['simulated_resource_arn']==STREAM
  assert row['_provenance']['SCP_RCP_verified']is False and row['_provenance']['effective_live_delivery_verified']is False

def test_real_collection_planner(sdk,monkeypatch):
 assert capture(sdk,monkeypatch,planned=True)[0]['status']=='PASS'

@pytest.mark.parametrize('field,value',[
 ('PolicyInputList',['{}']),('ResourcePolicy','{}'),('PolicyExclusionList',[]),('PermissionsBoundaryPolicyInputList',['{}']),('ActionNames',['logs:PutLogEvents']),('ActionNames',['iam:CreateRole']),('ResourceArns',[GROUP]),('ResourceArns',[STREAM.replace(ACCOUNT,'999999999999')]),('CallerArn',ROLE),('ContextEntries',[{'ContextKeyName':'aws:SourceArn','ContextKeyValues':[TRAIL],'ContextKeyType':'string'}])])
def test_simulation_exception_rejects_overrides(sdk,field,value):
 session,_=sdk;args={'PolicySourceArn':ROLE,'ActionNames':native.ACTIONS,'ResourceArns':[STREAM],field:value}
 result=aws.Requests({}).detail(session,'iam',REGION,'simulate_principal_policy',**args)
 assert result['collection_status']=='not_collected'and result['error']['code']=='undeclared_cloudtrail_delivery_simulation'

def test_other_simulation_or_mutation_remains_prohibited(sdk):
 session,_=sdk
 for operation in ['simulate_custom_policy','create_role','attach_role_policy','put_role_policy']:
  result=aws.Requests({}).detail(session,'iam',REGION,operation)
  assert result['collection_status']=='not_collected'and result['error']['code']=='non_read_operation'


@pytest.mark.parametrize('mode,proven',[
 ('broad',True),('attached',True),('baseonly',False),('conditional',False),('deny',False),
 ('boundary',True),('boundarybase',False),('boundarydeny',False),('versionmismatch',False),
])
def test_full_role_scope_offline(sdk,monkeypatch,mode,proven):
 session,add=sdk;sts,ct,iam=add('sts'),add('cloudtrail'),add('iam')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/reviewer','UserId':'reviewer'}, {})
 trail={'Name':'native-test','TrailARN':TRAIL,'HomeRegion':REGION,'IsMultiRegionTrail':False,'IsOrganizationTrail':False,'CloudWatchLogsRoleArn':ROLE,'CloudWatchLogsLogGroupArn':GROUP}
 ct.add_response('describe_trails',{'trailList':[trail]},{'includeShadowTrails':False})
 ct.add_response('get_trail_status',{'IsLogging':True},{'Name':TRAIL})
 ct.add_response('get_event_selectors',{'EventSelectors':[]},{'TrailName':TRAIL})
 trust={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'Service':'cloudtrail.amazonaws.com'}}]}
 boundary_arn=f'arn:aws:iam::{ACCOUNT}:policy/boundary'
 role={'Path':'/path/','RoleName':'CloudTrailDelivery','RoleId':'AROA12345678901234567','Arn':ROLE,'CreateDate':datetime(2026,1,1,tzinfo=timezone.utc),'AssumeRolePolicyDocument':json.dumps(trust)}
 if mode.startswith('boundary') or mode=='versionmismatch':role['PermissionsBoundary']={'PermissionsBoundaryType':'Policy','PermissionsBoundaryArn':boundary_arn}
 iam.add_response('get_role',{'Role':role},{'RoleName':'CloudTrailDelivery'})
 iam.add_response('get_context_keys_for_principal_policy',{'ContextKeyNames':[]},{'PolicySourceArn':ROLE})
 results=[{'EvalActionName':a,'EvalResourceName':STREAM,'EvalDecision':'allowed','MissingContextValues':[]}for a in native.ACTIONS]
 if mode.startswith('boundary') or mode=='versionmismatch':
  for result in results:result['PermissionsBoundaryDecisionDetail']={'AllowedByPermissionsBoundary':True}
 iam.add_response('simulate_principal_policy',{'EvaluationResults':results,'IsTruncated':False},{'PolicySourceArn':ROLE,'ActionNames':native.ACTIONS,'ResourceArns':[STREAM]})
 iam.add_response('list_role_policies',{'PolicyNames':[] if mode=='attached' else ['delivery'],'IsTruncated':False},{'RoleName':'CloudTrailDelivery'})
 iam.add_response('list_attached_role_policies',{'AttachedPolicies':[{'PolicyName':'delivery','PolicyArn':boundary_arn}] if mode=='attached' else [],'IsTruncated':False},{'RoleName':'CloudTrailDelivery'})
 resource=STREAM if mode=='baseonly' else STREAM+'*'
 stmt={'Effect':'Allow','Action':native.ACTIONS,'Resource':resource}
 if mode=='conditional':stmt['Condition']={'StringEquals':{'aws:RequestedRegion':REGION}}
 statements=[stmt]
 if mode=='deny':statements.append({'Effect':'Deny','Action':'logs:PutLogEvents','Resource':'*'})
 if mode!='attached':iam.add_response('get_role_policy',{'RoleName':'CloudTrailDelivery','PolicyName':'delivery','PolicyDocument':json.dumps({'Version':'2012-10-17','Statement':statements})},{'RoleName':'CloudTrailDelivery','PolicyName':'delivery'})
 if mode.startswith('boundary') or mode=='attached' or mode=='versionmismatch':
  iam.add_response('get_policy',{'Policy':{'Arn':boundary_arn,'PolicyName':'delivery' if mode=='attached' else 'boundary','DefaultVersionId':'v2'}},{'PolicyArn':boundary_arn})
  bstmt={'Effect':'Allow','Action':native.ACTIONS,'Resource':STREAM if mode=='boundarybase' else STREAM+'*'}
  if mode=='boundarydeny':bstatements=[bstmt,{'Effect':'Deny','Action':'logs:PutLogEvents','Resource':'*'}]
  else:bstatements=[bstmt]
  iam.add_response('get_policy_version',{'PolicyVersion':{'VersionId':'v2','IsDefaultVersion':mode!='versionmismatch','Document':json.dumps({'Version':'2012-10-17','Statement':bstatements})}},{'PolicyArn':boundary_arn,'VersionId':'v2'})
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture'))
 snap=collect_live({'provider':'aws','scopes':[ACCOUNT],'options':{'regions':[REGION],'service_concurrency':1,'retry_attempts':1}},['cloudtrail_delivery_role_scope'])
 envelope=next(e for e in snap['collections']if e['type']=='cloudtrail_delivery_role_scope')
 assert envelope['status']=='collected',envelope
 row=envelope['items'][0]
 assert row['full_role_stream_scope_proven'] is proven
 if proven:
  assert row['supported_stream_prefix']==STREAM+'*'
  assert len(row['_provenance']['operations'])==6
  proof=row['_provenance']['role_scope_proof']
  assert proof['method']=='complete_native_role_policies_v1'
  assert {'ListRolePolicies','ListAttachedRolePolicies'}.issubset(proof['operations'])
  assert ('GetPolicyVersion' if mode=='attached' else 'GetRolePolicy') in proof['operations']
 for stub in (sts,ct,iam):stub.assert_no_pending_responses()


def test_full_role_scope_denied_inventory(sdk,monkeypatch):
 session,add=sdk;sts,ct,iam=add('sts'),add('cloudtrail'),add('iam')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/reviewer','UserId':'reviewer'}, {})
 trail={'Name':'native-test','TrailARN':TRAIL,'HomeRegion':REGION,'IsMultiRegionTrail':False,'IsOrganizationTrail':False,'CloudWatchLogsRoleArn':ROLE,'CloudWatchLogsLogGroupArn':GROUP}
 ct.add_response('describe_trails',{'trailList':[trail]},{'includeShadowTrails':False})
 ct.add_response('get_trail_status',{'IsLogging':True},{'Name':TRAIL})
 ct.add_response('get_event_selectors',{'EventSelectors':[]},{'TrailName':TRAIL})
 role={'Path':'/path/','RoleName':'CloudTrailDelivery','RoleId':'AROA12345678901234567','Arn':ROLE,'CreateDate':datetime(2026,1,1,tzinfo=timezone.utc),'AssumeRolePolicyDocument':json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'Service':'cloudtrail.amazonaws.com'}}]})}
 iam.add_response('get_role',{'Role':role},{'RoleName':'CloudTrailDelivery'})
 iam.add_response('get_context_keys_for_principal_policy',{'ContextKeyNames':[]},{'PolicySourceArn':ROLE})
 iam.add_response('simulate_principal_policy',{'EvaluationResults':[{'EvalActionName':a,'EvalResourceName':STREAM,'EvalDecision':'allowed','MissingContextValues':[]}for a in native.ACTIONS],'IsTruncated':False},{'PolicySourceArn':ROLE,'ActionNames':native.ACTIONS,'ResourceArns':[STREAM]})
 iam.add_client_error('list_role_policies','AccessDenied',expected_params={'RoleName':'CloudTrailDelivery'})
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture'))
 snap=collect_live({'provider':'aws','scopes':[ACCOUNT],'options':{'regions':[REGION],'service_concurrency':1,'retry_attempts':1}},['cloudtrail_delivery_role_scope'])
 env=next(e for e in snap['collections']if e['type']=='cloudtrail_delivery_role_scope')
 assert env['status']=='denied' and env['items']==[]
 for stub in (sts,ct,iam):stub.assert_no_pending_responses()
