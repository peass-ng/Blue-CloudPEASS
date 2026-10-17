"""Real SDK collect_live -> analyze with explicit, fresh reviewed instance control."""
import copy,json
from datetime import datetime,timezone,timedelta
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso import privesc
from peaso.privesc.effective_permissions.ec2_profile_association import TECHNIQUE
SCOPE=ACCOUNT+'/'+REGION
P='arn:aws:iam::'+ACCOUNT+':'
SOURCE=P+'role/actor';ROLE=P+'role/target';PROFILE=P+'instance-profile/target';CURRENT=P+'instance-profile/old'
IID='i-1234567890abcdef0';INSTANCE='arn:aws:ec2:'+REGION+':'+ACCOUNT+':instance/'+IID
TIME=datetime(2026,10,15,10,tzinfo=timezone.utc)
ASSOC='iip-assoc-1234567890abcdef0'


def role(name,actions=(),profile=None):
 trust={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'Service':'ec2.amazonaws.com'}}]}
 r={'Path':'/','RoleName':name,'RoleId':'AROA1234567890ABCDEF'+name,'Arn':P+'role/'+name,'CreateDate':TIME,
    'AssumeRolePolicyDocument':json.dumps(trust),'RolePolicyList':[],'AttachedManagedPolicies':[],'InstanceProfileList':[]}
 if actions:r['RolePolicyList']=[{'PolicyName':'limited','PolicyDocument':json.dumps({'Version':'2012-10-17','Statement':list(actions)})}]
 if profile:r['InstanceProfileList']=[{'Path':'/','InstanceProfileName':name,'InstanceProfileId':'AIPA1234567890ABCDEF'+name,'Arn':profile,'CreateDate':TIME,'Roles':[{k:copy.deepcopy(v)for k,v in r.items()if k not in ('RolePolicyList','AttachedManagedPolicies','InstanceProfileList')}]}]
 return r


def capture(sdk,monkeypatch,branch='associate',mode='good'):
 session,add=sdk;sts,iam,ec2=add('sts'),add('iam'),add('ec2')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':SOURCE,'UserId':'actor'}, {})
 ops={'associate':['AssociateIamInstanceProfile'],'replace':['ReplaceIamInstanceProfileAssociation'],'detach_attach':['DisassociateIamInstanceProfile','AssociateIamInstanceProfile']}[branch]
 selected=ops[:-1]if mode=='missing_operation'else ops
 actions=[{'Effect':'Allow','Action':'iam:PassRole','Resource':ROLE}]+[{'Effect':'Allow','Action':'ec2:'+op,'Resource':INSTANCE+'f'if mode=='wrong_permission_instance'else INSTANCE}for op in selected]
 if mode in ('old_profile_allow','profile_null_false','profile_null_true','new_profile_matches'):
  for st in actions:
   if st['Action']=='ec2:AssociateIamInstanceProfile':
    st['Condition']=({'ArnEquals':{'ec2:InstanceProfile':CURRENT}}if mode=='old_profile_allow'else
        {'Null':{'ec2:InstanceProfile':'false'}}if mode=='profile_null_false'else
        {'Null':{'ec2:InstanceProfile':'true'},'ArnLike':{'ec2:NewInstanceProfile':PROFILE}}if mode=='profile_null_true'else
        {'ArnEquals':{'ec2:NewInstanceProfile':PROFILE}})
 if mode=='stopped':actions.append({'Effect':'Allow','Action':'ec2:StartInstances','Resource':INSTANCE})
 if mode=='denied':actions.append({'Effect':'Deny','Action':'iam:PassRole','Resource':ROLE})
 if mode=='new_profile_deny':actions.append({'Effect':'Deny','Action':'ec2:'+ops[-1],'Resource':INSTANCE,'Condition':{'ArnEquals':{'ec2:NewInstanceProfile':PROFILE}}})
 roles=[role('actor',actions),role('target',profile=PROFILE)]
 if branch!='associate':roles.append(role('old',profile=CURRENT))
 if mode=='member_missing':roles[1]['InstanceProfileList'][0]['Roles']=[]
 if mode=='member_conflict':roles[1]['InstanceProfileList'][0]['Roles'][0]['RoleId']='AROA1234567890DIFFERENT'
 if mode=='foreign_profile':roles[1]['InstanceProfileList'][0]['Arn']=PROFILE.replace(ACCOUNT,'999999999999')
 iam.add_response('get_account_authorization_details',{'UserDetailList':[],'GroupDetailList':[],'RoleDetailList':roles,'Policies':[],'IsTruncated':False},{})
 assoc={'AssociationId':ASSOC,'InstanceId':IID,'State':'associated','IamInstanceProfile':{'Arn':CURRENT,'Id':'AIPA1234567890ABCDEFold'}}
 assocs=[]if branch=='associate'else[copy.deepcopy(assoc)]
 instance={'InstanceId':IID,'State':{'Name':'running','Code':16},'MetadataOptions':{'HttpEndpoint':'enabled','State':'applied','HttpTokens':'required'}}
 if branch!='associate':instance['IamInstanceProfile']=copy.deepcopy(assoc['IamInstanceProfile'])
 if mode in ('stopped','stopped_no_start'):instance['State']={'Name':'stopped','Code':80}
 if mode=='imds_disabled':instance['MetadataOptions']['HttpEndpoint']='disabled'
 if mode=='imds_transition':instance['MetadataOptions']['State']='pending'
 if mode=='terminated':instance['State']={'Name':'terminated','Code':48}
 if mode=='association_mismatch'and assocs:assocs[0]['IamInstanceProfile']['Arn']=PROFILE
 if mode=='association_transition'and assocs:assocs[0]['State']='associating'
 if mode=='association_duplicate'and assocs:
  duplicate=copy.deepcopy(assocs[0]);duplicate['State']='associating';assocs.append(duplicate)
 if mode=='false_absence':instance['IamInstanceProfile']={'Arn':CURRENT,'Id':'AIPA1234567890ABCDEFold'}
 if mode=='association_denied':ec2.add_client_error('describe_iam_instance_profile_associations','UnauthorizedOperation',expected_params={})
 else:ec2.add_response('describe_iam_instance_profile_associations',{'IamInstanceProfileAssociations':assocs,**({'NextToken':'next-native'}if mode=='native_page_limit'else{})},{})
 ec2.add_response('describe_instances',{'Reservations':[{'Instances':[instance]}]}, {})
 ec2.add_response('describe_instance_attribute',{'InstanceId':IID,'UserData':{}},{'InstanceId':IID,'Attribute':'userData'})
 ec2.add_response('describe_instance_attribute',{'InstanceId':IID,'DisableApiTermination':{'Value':False}},{'InstanceId':IID,'Attribute':'disableApiTermination'})
 if mode=='native_page_limit':ec2.add_response('describe_iam_instance_profile_associations',{'IamInstanceProfileAssociations':[]},{'NextToken':'next-native'})
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture-pinned'))
 snapshot=collect_live({'provider':'aws','scopes':[SCOPE],'options':{'service_concurrency':1,'retry_attempts':1,**({'max_pages':1}if mode=='native_page_limit'else{})}},['iam_user','iam_group','iam_role','iam_policy','instance','ec2_instance_profile_association'])
 sts.assert_no_pending_responses();iam.assert_no_pending_responses()
 if mode=='native_page_limit':
  assert len(ec2._queue)==1 and ec2._queue[0]['expected_params']=={'NextToken':'next-native'}
  env=next(c for c in snapshot['collections']if c['type']=='ec2_instance_profile_association')
  assert env['status']not in ('collected','empty')and env['error']['code']=='page_limit'
 else:ec2.assert_no_pending_responses()
 assert next(c for c in snapshot['collections']if c['type']=='instance')['status']=='collected'
 # Malformed imported snapshot guard, after SDK validation/real collection.
 if mode=='member_ids_missing':
  target=next(r for c in snapshot['collections']if c['type']=='iam_role' for r in c['items']if r['Arn']==ROLE)
  target.pop('RoleId');target['InstanceProfileList'][0]['Roles'][0].pop('RoleId')
 snapshot['created_at']=TIME.isoformat()
 snapshot['collections'] += [{'type':kind,'scope':ACCOUNT+'/global','service':'organizations','status':'empty','items':[]}for kind in ['scp_policy','rcp_policy']]
 proof={'TechniqueId':TECHNIQUE,'SourceId':SOURCE,'TargetKind':'aws_role','TargetId':ROLE,'TargetScope':SCOPE,'TargetProfileArn':PROFILE,'TargetProfileId':'AIPA1234567890ABCDEFtarget','InstanceArn':INSTANCE,'Status':'verified','InstanceControlled':True,'ImdsRoleCredentialsReachable':True,'VerifiedPreconditions':True,'EvidenceRef':'fixture-review','EvidenceObservedAt':(TIME-timedelta(minutes=1)).isoformat(),'EvidenceExpiresAt':(TIME+timedelta(minutes=5)).isoformat()}
 mutations={'wrong_source':('SourceId',P+'role/other'),'wrong_target':('TargetId',P+'role/old'),'wrong_proof_instance':('InstanceArn',INSTANCE+'f'),'wrong_proof_profile':('TargetProfileArn',CURRENT),'uncontrolled':('InstanceControlled',False),'imds_unavailable':('ImdsRoleCredentialsReachable',False),'unreviewed':('VerifiedPreconditions',False),'stale':('EvidenceObservedAt',(TIME-timedelta(minutes=20)).isoformat()),'future':('EvidenceObservedAt',(TIME+timedelta(minutes=1)).isoformat()),'expired':('EvidenceExpiresAt',(TIME-timedelta(seconds=1)).isoformat()),'foreign_scope':('TargetScope',SCOPE.replace(ACCOUNT,'999999999999')),'recreated_profile':('TargetProfileId','AIPA_REPLACED')}
 if mode in mutations:key,value=mutations[mode];proof[key]=value
 records=[]if mode=='no_proof'else[proof]
 if mode=='duplicate_proof':records*=2
 snapshot['collections'].append({'type':'aws_privesc_challenge_evidence','scope':SCOPE,'service':'review','status':'partial'if mode=='partial_proof'else'collected','items':records})
 if mode=='invalid_empty_native':next(c for c in snapshot['collections']if c['type']=='ec2_instance_profile_association')['status']='empty'
 if mode=='partial_native':next(c for c in snapshot['collections']if c['type']=='ec2_instance_profile_association')['status']='partial'
 result=privesc.analyze(snapshot)
 edges=[e for e in result['graph']['edges']if TECHNIQUE in e['techniques']and e['source']==SOURCE]
 return edges,result,snapshot


@pytest.mark.parametrize('branch',['associate','replace','detach_attach'])
@pytest.mark.parametrize('mode',['good','stopped'])
def test_actual_sdk_three_branches(sdk,monkeypatch,branch,mode):
 edges,result,snapshot=capture(sdk,monkeypatch,branch,mode)
 assert len(edges)==1 and edges[0]['confidence']=='conditional'
 nodes={n['id']:n for n in result['graph']['nodes']};node=nodes[edges[0]['target']]
 assert ROLE==node['id']or ROLE in node.get('members',[])


@pytest.mark.parametrize('mode',['missing_operation','denied','new_profile_deny','wrong_permission_instance','foreign_profile','terminated','false_absence','association_denied','wrong_source','wrong_target','wrong_proof_instance','wrong_proof_profile','uncontrolled','imds_unavailable','unreviewed','stale','future','expired','foreign_scope','no_proof','duplicate_proof','partial_proof','partial_native','stopped_no_start','imds_disabled','imds_transition','recreated_profile','native_page_limit','member_missing','member_conflict','member_ids_missing'])
def test_incomplete_or_wrong_evidence_never_draws_principal_edge(sdk,monkeypatch,mode):
 edges,result,snapshot=capture(sdk,monkeypatch,'associate',mode)
 assert edges==[]
 assert any(TECHNIQUE+' exact native/control join unavailable'in c['reason']for c in result['coverage'])


@pytest.mark.parametrize('mode',['association_mismatch','association_transition','association_duplicate'])
@pytest.mark.parametrize('branch',['replace','detach_attach'])
def test_current_profile_state_bound(sdk,monkeypatch,branch,mode):
 assert capture(sdk,monkeypatch,branch,mode)[0]==[]


def test_invalid_empty_envelope_with_rows_cannot_prove_attachment(sdk,monkeypatch):
 assert capture(sdk,monkeypatch,'replace','invalid_empty_native')[0]==[]


@pytest.mark.parametrize('mode,positive',[('old_profile_allow',False),('profile_null_false',False),
 ('profile_null_true',True),('new_profile_matches',True)])
def test_detach_then_associate_uses_actual_post_detach_request_context(sdk,monkeypatch,mode,positive):
 edges,_,_=capture(sdk,monkeypatch,'detach_attach',mode)
 assert bool(edges) is positive
