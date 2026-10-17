"""Actual SDK-shaped metadata fetchers -> frozen signed Lightsail evaluator."""
import copy
import json
from datetime import datetime, timedelta, timezone
from contextlib import ExitStack
from urllib.parse import quote
import boto3
from botocore.stub import Stubber
import pytest
from peaso.collectors import aws, aws_lightsail_iam_native as native
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.aws_lightsail_owner_policy import normalize, owner_metadata

ACCOUNT='123456789012';REGION='us-east-1';SCOPE=ACCOUNT+'/'+REGION
ARN=f'arn:aws:lightsail:{REGION}:{ACCOUNT}:Bucket/12345678-1234-1234-1234-123456789012'
ROLE=f'arn:aws:iam::{ACCOUNT}:role/team/approved';USER=f'arn:aws:iam::{ACCOUNT}:user/team/owned'
GROUP=f'arn:aws:iam::{ACCOUNT}:group/team/reviewers';POLICY=f'arn:aws:iam::{ACCOUNT}:policy/team/bucket'
CHECK='aws_cis_lightsail_bucket_iam_policy'

APPROVED = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()

def owner():
 raw={'status':'collected','scope':SCOPE,'observed_at':APPROVED,'max_age_seconds':86400,
      'parameters':{'iam_required_lightsail_bucket_arns':[ARN],
                    'approved_lightsail_principals':[ROLE,USER],'approved_lightsail_actions':['lightsail:UpdateBucket']}}
 return owner_metadata(normalize({'compliance_parameters':{'aws_lightsail_bucket_iam':raw}}),datetime.now(timezone.utc))


def document():return {'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'lightsail:UpdateBucket','Resource':ARN}]}

def response(mode):
 doc=document();role={'Arn':ROLE,'RoleName':'approved','RolePolicyList':[{'PolicyName':'bucket','PolicyDocument':json.dumps(doc)}]}
 v={'UserDetailList':[],'GroupDetailList':[],'RoleDetailList':[role],'Policies':[],'IsTruncated':False}
 if mode.startswith('managed'):
  role['RolePolicyList']=[];role['AttachedManagedPolicies']=[{'PolicyArn':POLICY,'PolicyName':'bucket'}]
  v['Policies']=[{'Arn':POLICY,'DefaultVersionId':'v2','PolicyVersionList':[{'VersionId':'v2','IsDefaultVersion':True,'Document':json.dumps(doc)}]}]
  if mode=='managed-missing':v['Policies']=[]
  if mode=='managed-foreign':v['Policies'][0]['Arn']=POLICY.replace(ACCOUNT,'999999999999')
  if mode=='managed-wrongversion':v['Policies'][0]['DefaultVersionId']='v3'
  if mode=='managed-duplicate':role['AttachedManagedPolicies']*=2
  if mode=='managed-ambiguous':v['Policies'][0]['PolicyVersionList'].append({'VersionId':'v1','IsDefaultVersion':True,'Document':json.dumps(doc)})
  return v
 if mode=='group':
  v['RoleDetailList']=[];v['UserDetailList']=[{'Arn':USER,'UserName':'owned','GroupList':['reviewers']}]
  v['GroupDetailList']=[{'Arn':GROUP,'GroupName':'reviewers','GroupPolicyList':[{'PolicyName':'bucket','PolicyDocument':json.dumps(doc)}]}];return v
 if mode=='empty':v['RoleDetailList']=[]
 if mode=='two-roles':
  other=copy.deepcopy(role);other.update(Arn=ROLE.replace('approved','other'),RoleName='other');v['RoleDetailList'].append(other)
 if mode=='unapproved':role.update(Arn=ROLE.replace('approved','outsider'),RoleName='outsider')
 if mode=='wider':doc['Statement'][0]['Resource']=[ARN,ARN+'-other']
 if mode=='wildcard':doc['Statement'][0]['Resource']='*'
 if mode=='unrelated-wildcard':doc['Statement'].append({'Effect':'Allow','Action':'ec2:DescribeInstances','Resource':'*'})
 if mode=='condition':doc['Statement'][0]['Condition']={'StringEquals':{'aws:PrincipalTag/environment':'owned'}}
 if mode=='notaction':doc['Statement'][0].pop('Action');doc['Statement'][0]['NotAction']='iam:*'
 if mode=='notresource':doc['Statement'][0].pop('Resource');doc['Statement'][0]['NotResource']=ARN
 if mode=='foreign':role['Arn']=ROLE.replace(ACCOUNT,'999999999999')
 if mode=='wrongname':role['RoleName']='different'
 if mode=='duplicate':v['RoleDetailList']*=2
 if mode=='duplicate-inline':role['RolePolicyList']*=2
 if mode=='boundary':role['PermissionsBoundary']={'PermissionsBoundaryType':'Policy','PermissionsBoundaryArn':POLICY}
 if mode=='missing-group':v['UserDetailList']=[{'Arn':USER,'UserName':'owned','GroupList':['missing']}]
 role['RolePolicyList'][0]['PolicyDocument']=quote(json.dumps(doc)) if mode=='encoded'else json.dumps(doc)
 if mode in ('question-resource','variable-resource'):
  other=copy.deepcopy(role);other.update(Arn=ROLE.replace('approved','outsider'),RoleName='outsider')
  dynamic=ARN[:-1]+'?'if mode=='question-resource'else ARN.rsplit('/',1)[0]+'/${aws:PrincipalTag/bucket}'
  other['RolePolicyList']=[{'PolicyName':'dynamic-bucket','PolicyDocument':json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'lightsail:UpdateBucket','Resource':dynamic}]})}]
  v['RoleDetailList'].append(other)
 if mode=='bad-json':role['RolePolicyList'][0]['PolicyDocument']='!invalid-json'
 if mode=='duplicate-json':role['RolePolicyList'][0]['PolicyDocument']='{"Statement":[],"Statement":[]}'
 return v

def capture(monkeypatch,mode='inline',limits=None):
 session=boto3.Session(aws_access_key_id='INERT',aws_secret_access_key='INERT',region_name=REGION)
 request=aws.Requests({'retry_attempts':1,'service_concurrency':1,**(limits or{})});request.lightsail_iam_policy=owner()
 clients={};stubs={};calls=[]
 with ExitStack()as stack:
  original=session.client
  def client(service,**kwargs):
   if service not in clients:
    clients[service]=original(service,region_name=REGION);stubs[service]=stack.enter_context(Stubber(clients[service]))
   return clients[service]
  monkeypatch.setattr(session,'client',client);client('iam');client('lightsail')
  bucket={'name':'owned-bucket','arn':ARN,'resourceType':'Bucket','location':{'regionName':REGION}}
  if mode=='bucket-foreign':bucket['arn']=ARN.replace(ACCOUNT,'999999999999')
  if mode=='bucket-region':bucket['location']['regionName']='eu-west-1'
  if mode=='bucket-sensitive':bucket['url']='NEVER_COPY_SENSITIVE';bucket['tags']=[{'key':'private','value':'NEVER_COPY_SENSITIVE'}]
  if mode=='bucket-denied':stubs['lightsail'].add_client_error('get_buckets','AccessDeniedException',expected_params={})
  elif mode=='bucket-paged':
   stubs['lightsail'].add_response('get_buckets',{'buckets':[],'nextPageToken':'more'},{});stubs['lightsail'].add_response('get_buckets',{'buckets':[bucket]},{'pageToken':'more'})
  else:stubs['lightsail'].add_response('get_buckets',{'buckets':[bucket]*(2 if mode=='bucket-duplicate'else 1)},{})
  if mode=='denied':stubs['iam'].add_client_error('get_account_authorization_details','AccessDenied',expected_params={})
  elif mode in('paged','repeat','page-limit'):
   first=response('empty');first.update(IsTruncated=True,Marker='more');second=response('inline')
   if mode=='repeat':second.update(IsTruncated=True,Marker='more')
   stubs['iam'].add_response('get_account_authorization_details',first,{});stubs['iam'].add_response('get_account_authorization_details',second,{'Marker':'more'})
  else:stubs['iam'].add_response('get_account_authorization_details',response(mode),{})
  original_call=request.call
  def observe(session,service,region,operation,**kwargs):calls.append((service,operation));return original_call(session,service,region,operation,**kwargs)
  monkeypatch.setattr(request,'call',observe)
  buckets=native.bucket_metadata(request,session,REGION,ACCOUNT);attachments=native.collect(request,session,REGION,ACCOUNT)
  if mode=='cache-isolation':
   cache_view=lambda:{k:copy.deepcopy(v.result()if hasattr(v,'result')else v)for k,v in request._cache.items()}
   cached=cache_view();attachments.items[0]['PolicyDocument']['Statement'][0]['Action']='lightsail:DeleteBucket'
   attachments=native.collect(request,session,REGION,ACCOUNT)
   assert attachments.items[0]['PolicyDocument']['Statement'][0]['Action']=='lightsail:UpdateBucket'
   assert cache_view()==cached
   assert request.calls==2  # One native bucket + one cached native IAM response.
  collections=[{'type':'lightsail_bucket','scope':SCOPE,'status':buckets.status,'items':buckets.items},{'type':native.KIND,'scope':SCOPE,'status':attachments.status,'items':attachments.items}]
  snap=make_snapshot('aws',[SCOPE],collections,metadata={'compliance_policy':owner()})
  findings=evaluate_snapshot(snap,checks=[CHECK],include_not_applicable=True)['findings'];assert len(findings)==1
  assert all(pair in native.READ_ACTIONS for pair in calls);assert 'NEVER_COPY_SENSITIVE'not in json.dumps(snap)
  return findings[0]['status'],attachments,buckets,calls,snap

@pytest.mark.parametrize('mode,expected',[
 ('inline','PASS'),('encoded','PASS'),('managed','PASS'),('group','PASS'),('paged','PASS'),('bucket-paged','PASS'),('bucket-sensitive','PASS'),
 ('empty','FAIL'),('unapproved','FAIL'),('wider','FAIL'),('wildcard','UNKNOWN'),('unrelated-wildcard','UNKNOWN'),
 ('condition','UNKNOWN'),('notaction','UNKNOWN'),('notresource','UNKNOWN'),('bad-json','UNKNOWN'),('duplicate-json','UNKNOWN'),
 ('foreign','UNKNOWN'),('wrongname','UNKNOWN'),('duplicate','UNKNOWN'),('duplicate-inline','UNKNOWN'),('boundary','UNKNOWN'),('missing-group','UNKNOWN'),
 ('managed-missing','UNKNOWN'),('managed-foreign','UNKNOWN'),('managed-wrongversion','UNKNOWN'),('managed-duplicate','UNKNOWN'),('managed-ambiguous','UNKNOWN'),
 ('bucket-foreign','UNKNOWN'),('bucket-region','UNKNOWN'),('bucket-duplicate','UNKNOWN'),('repeat','UNKNOWN'),('denied','UNKNOWN'),('bucket-denied','DENIED')])
def test_native_fetch_into_frozen_signed_engine(monkeypatch,mode,expected):
 status,read,buckets,calls,snap=capture(monkeypatch,mode);assert status==expected,(read.status,read.error)
 assert not any(op=='get_bucket_access_keys'for _,op in calls)
 if mode in('inline','managed','group'):
  assert read.items[0]['PolicyDocument']['Statement'][0]['Action']=='lightsail:UpdateBucket'
  assert read.items[0]['_provenance']['source_scope']==ACCOUNT+'/global'
  if mode=='group':assert read.items[0]['PrincipalArn']==USER and read.items[0]['_provenance']['native_group_arn']==GROUP
  if mode=='managed':assert read.items[0]['_provenance']['source_identity']['version_id']=='v2'
 if mode=='denied':assert read.status=='denied'and read.items==[]

@pytest.mark.parametrize('mode',['missing','foreign','observations'])
def test_unapproved_scope_never_requests_iam(monkeypatch,mode):
 requests=aws.Requests({});session=boto3.Session(aws_access_key_id='INERT',aws_secret_access_key='INERT')
 if mode!='missing':
  requests.lightsail_iam_policy=owner()
  if mode=='foreign':requests.lightsail_iam_policy['scope']=ACCOUNT+'/eu-west-1'
  else:requests.lightsail_iam_policy['observations']=True
 monkeypatch.setattr(requests,'pages',lambda*a,**kw:pytest.fail('IAM read forbidden without exact policy scope'))
 read=native.collect(requests,session,REGION,ACCOUNT);assert read.status=='not_collected'and read.items==[]and requests.calls==0

@pytest.mark.parametrize('limits',[{'max_pages':1},{'max_calls':1},{'max_resources':1}])
def test_budget_never_becomes_complete(monkeypatch,limits):
 status,read,_,_,_=capture(monkeypatch,'page-limit'if'max_pages'in limits else'two-roles'if'max_resources'in limits else'inline',limits)
 assert status in('UNKNOWN','DENIED')and read.status not in('collected','empty')

def test_output_cap_unknown(monkeypatch):
 monkeypatch.setattr(native,'MAX_OUTPUT_BYTES',1);status,read,_,_,_=capture(monkeypatch);assert status=='UNKNOWN'and read.items==[]


def test_cached_native_documents_are_not_mutated_or_shared_with_output(monkeypatch):
 status,read,_,_,_=capture(monkeypatch,'cache-isolation')
 assert status=='PASS'and read.status=='collected'


def test_aggregate_identity_bound_is_not_complete(monkeypatch):
 monkeypatch.setattr(native,'MAX_IDENTITIES',1)
 status,read,_,_,_=capture(monkeypatch,'two-roles')
 assert status=='UNKNOWN'and read.items==[]and read.status=='not_collected'


@pytest.mark.parametrize('mode',['expired','future','unknown','missing-clock','bool-age'])
def test_real_owner_projection_and_freshness_skip_without_iam(monkeypatch,mode):
 requests=aws.Requests({});policy=owner()
 if mode=='expired':policy['observed_at']=(requests.observed_at-timedelta(days=2)).isoformat()
 if mode=='future':policy['observed_at']=(requests.observed_at+timedelta(minutes=1)).isoformat()
 if mode=='unknown':policy.update(status='unknown',owner_authority_status='stale_or_future')
 if mode=='missing-clock':policy.pop('observed_at')
 if mode=='bool-age':policy['max_age_seconds']=True
 requests.lightsail_iam_policy=policy
 monkeypatch.setattr(requests,'pages',lambda*a,**kw:pytest.fail('Unapproved/stale policy cannot start IAM'))
 session=boto3.Session(aws_access_key_id='INERT',aws_secret_access_key='INERT')
 result=native.collect(requests,session,REGION,ACCOUNT)
 assert result.status=='not_collected'and result.items==[]and requests.calls==0


@pytest.mark.parametrize('mode',['question-resource','variable-resource'])
def test_dynamic_resource_cannot_hide_unapproved_attachment(monkeypatch,mode):
 # Approved literal role alone could PASS; the second real-shaped role must
 # prevent a complete claim when its Resource can resolve onto this bucket.
 status,read,_,_,_=capture(monkeypatch,mode)
 assert status=='UNKNOWN'and read.status=='not_collected'and read.items==[]
