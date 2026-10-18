"""Owner criteria remain separate from observed Lightsail IAM attachments."""
import copy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from peaso import aws_lightsail_owner_policy as policy
from peaso.collectors import aws
from peaso.server.validation import validate_connector

ACCOUNT='111122223333'
REGION='us-east-1'
SCOPE=ACCOUNT+'/'+REGION
NOW=datetime(2026,10,16,12,tzinfo=timezone.utc)
BUCKET='arn:aws:lightsail:'+REGION+':'+ACCOUNT+':Bucket/01234567-abcd-4321-abcd-012345678901'
PRINCIPAL='arn:aws:iam::'+ACCOUNT+':role/team/fixture-reader'


def owner():
    return {'status':'collected','scope':SCOPE,'observed_at':NOW.isoformat(),'max_age_seconds':3600,
            'parameters':{'iam_required_lightsail_bucket_arns':[BUCKET],
                'approved_lightsail_principals':[PRINCIPAL],
                'approved_lightsail_actions':['lightsail:UpdateBucket']}}


def options(raw=None):
    return {'retries':1,'compliance_parameters':{policy.NAMESPACE:owner()if raw is None else raw}}


def intake(value,auth_mode='cognito',provider='aws'):
    auth={'method':'assume_role','role_arn':'arn:aws:iam::'+ACCOUNT+':role/fixture-reader','external_id':'peaso-owned-fixture-external'}if provider=='aws'else{}
    validate_connector(provider,auth,value,SimpleNamespace(auth_mode=auth_mode),server_external_id=True)


@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_valid_real_intake_schema_preserves_original_criteria(auth_mode):
    value=options();before=copy.deepcopy(value)
    intake(value,auth_mode)
    assert value==before and policy.normalize(value)==owner()
    assert value['retries']==1


def test_absence_is_not_synthesized():
    assert policy.normalize({})is None
    assert policy.normalize({'compliance_parameters':{'unrelated':{}}})is None
    assert policy.owner_metadata(None,NOW)is None
    metadata={'unrelated':{'value':1}};policy.merge_metadata(metadata,None)
    assert metadata=={'unrelated':{'value':1}}


@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('mode',[
    'null','list','extra_root','missing_status','wrong_status','null_scope','global_scope',
    'null_stamp','naive_stamp','malformed_stamp','oversized_stamp','bool_age','zero_age','oversized_age',
    'null_parameters','missing_parameter','extra_parameter','observed_policy','attachments',
    'null_buckets','empty_buckets','string_buckets','duplicate_buckets','too_many_buckets','foreign_bucket_account',
    'foreign_bucket_region','foreign_bucket_partition','bucket_wildcard','bucket_wrong_type','bucket_extra_path','oversized_string',
    'null_principals','empty_principals','duplicate_principals','too_many_principals','foreign_principal_account',
    'foreign_principal_partition','root_principal','sts_principal','wildcard_principal','null_principal',
    'null_actions','empty_actions','bool_action','casefold_duplicate_actions','wildcard_action','wrong_service',
    'get_instance_unsupported','create_bucket_unsupported','get_access_keys_unsupported','too_many_actions'])
def test_strict_owner_shape_and_native_resource_support_rejected(mode,auth_mode):
    raw=owner()
    if mode=='null':raw=None
    elif mode=='list':raw=[]
    elif mode=='extra_root':raw['approved']=True
    elif mode=='missing_status':raw.pop('status')
    elif mode=='wrong_status':raw['status']='unknown'
    elif mode=='null_scope':raw['scope']=None
    elif mode=='global_scope':raw['scope']=ACCOUNT+'/global'
    elif mode=='null_stamp':raw['observed_at']=None
    elif mode=='naive_stamp':raw['observed_at']='2026-10-16T12:00:00'
    elif mode=='malformed_stamp':raw['observed_at']='invalid'
    elif mode=='oversized_stamp':raw['observed_at']='1'*65
    elif mode=='bool_age':raw['max_age_seconds']=True
    elif mode=='zero_age':raw['max_age_seconds']=0
    elif mode=='oversized_age':raw['max_age_seconds']=policy.MAX_AGE+1
    elif mode=='null_parameters':raw['parameters']=None
    elif mode=='missing_parameter':raw['parameters'].pop('approved_lightsail_actions')
    elif mode=='extra_parameter':raw['parameters']['complete']=True
    elif mode=='observed_policy':raw['PolicyDocument']={'Statement':[]}
    elif mode=='attachments':raw['attachments']=[{'attached':True}]
    else:
        params=raw['parameters'];b='iam_required_lightsail_bucket_arns';p='approved_lightsail_principals';a='approved_lightsail_actions'
        if mode=='null_buckets':params[b]=None
        elif mode=='empty_buckets':params[b]=[]
        elif mode=='string_buckets':params[b]=BUCKET
        elif mode=='duplicate_buckets':params[b]=[BUCKET,BUCKET]
        elif mode=='too_many_buckets':params[b]=[BUCKET+str(n)for n in range(1001)]
        elif mode=='foreign_bucket_account':params[b]=[BUCKET.replace(ACCOUNT,'444455556666')]
        elif mode=='foreign_bucket_region':params[b]=[BUCKET.replace(REGION,'eu-west-1')]
        elif mode=='foreign_bucket_partition':params[b]=[BUCKET.replace('arn:aws:','arn:aws-cn:')]
        elif mode=='bucket_wildcard':params[b]=[BUCKET+'*']
        elif mode=='bucket_wrong_type':params[b]=[BUCKET.replace(':Bucket/',':Instance/')]
        elif mode=='bucket_extra_path':params[b]=[BUCKET+'/other']
        elif mode=='oversized_string':params[b]=['a'*2049]
        elif mode=='null_principals':params[p]=None
        elif mode=='empty_principals':params[p]=[]
        elif mode=='duplicate_principals':params[p]=[PRINCIPAL,PRINCIPAL]
        elif mode=='too_many_principals':params[p]=[PRINCIPAL+str(n)for n in range(1001)]
        elif mode=='foreign_principal_account':params[p]=[PRINCIPAL.replace(ACCOUNT,'444455556666')]
        elif mode=='foreign_principal_partition':params[p]=[PRINCIPAL.replace('arn:aws:','arn:aws-us-gov:')]
        elif mode=='root_principal':params[p]=['arn:aws:iam::'+ACCOUNT+':root']
        elif mode=='sts_principal':params[p]=['arn:aws:sts::'+ACCOUNT+':assumed-role/fixture/session']
        elif mode=='wildcard_principal':params[p]=['*']
        elif mode=='null_principal':params[p]=[None]
        elif mode=='null_actions':params[a]=None
        elif mode=='empty_actions':params[a]=[]
        elif mode=='bool_action':params[a]=[True]
        elif mode=='casefold_duplicate_actions':params[a]=['lightsail:UpdateBucket','LIGHTSAIL:UPDATEBUCKET']
        elif mode=='wildcard_action':params[a]=['lightsail:*']
        elif mode=='wrong_service':params[a]=['s3:PutObject']
        elif mode=='get_instance_unsupported':params[a]=['lightsail:GetInstance']
        elif mode=='create_bucket_unsupported':params[a]=['lightsail:CreateBucket']
        elif mode=='get_access_keys_unsupported':params[a]=['lightsail:GetBucketAccessKeys']
        elif mode=='too_many_actions':params[a]=['lightsail:'+str(n)for n in range(len(policy.BUCKET_ACTIONS)+1)]
    value={'retries':1,'compliance_parameters':{policy.NAMESPACE:raw}}
    with pytest.raises(ValueError):policy.normalize(value)
    with pytest.raises(HTTPException)as caught:intake(value,auth_mode)
    assert caught.value.status_code==422


@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('provider',['azure','gcp','k8s'])
def test_wrong_provider_rejected_before_auth(auth_mode,provider):
    with pytest.raises(HTTPException)as caught:intake(options(),auth_mode,provider)
    assert caught.value.status_code==422


@pytest.mark.parametrize('partition,region',[('aws','eu-west-1'),('aws-cn','cn-north-1'),('aws-us-gov','us-gov-west-1')])
def test_arn_partition_account_region_consistency(partition,region):
    raw=owner();raw['scope']=ACCOUNT+'/'+region
    raw['parameters']['iam_required_lightsail_bucket_arns']=[BUCKET.replace('arn:aws:','arn:'+partition+':').replace(REGION,region)]
    raw['parameters']['approved_lightsail_principals']=[PRINCIPAL.replace('arn:aws:','arn:'+partition+':')]
    assert policy.normalize(options(raw))==raw
    raw['parameters']['approved_lightsail_principals']=[PRINCIPAL.replace('arn:aws:','arn:wrong:')]
    with pytest.raises(ValueError):policy.normalize(options(raw))


@pytest.mark.parametrize('action',sorted(policy.BUCKET_ACTIONS))
def test_supported_resource_actions_accept_case_insensitive_names_without_executing_them(action):
    raw=owner();raw['parameters']['approved_lightsail_actions']=['LIGHTSAIL:'+action.upper()]
    assert policy.normalize(options(raw))==raw


@pytest.mark.parametrize('scopes',[[],[ACCOUNT],[ACCOUNT+'/eu-west-1'],['444455556666/'+REGION],[SCOPE,SCOPE],[SCOPE,ACCOUNT+'/eu-west-1']])
def test_selected_scope_mismatch_rejected_before_credentials(scopes,monkeypatch):
    calls=[]
    def forbidden(*args,**kwargs):calls.append((args,kwargs));raise AssertionError('Credential construction forbidden')
    monkeypatch.setattr(aws,'_session',forbidden)
    with pytest.raises(ValueError,match='one exact selected'):aws.collect({'provider':'aws','auth':{},'scopes':scopes,'options':options()},requirements=[])
    assert calls==[]


def test_exact_selected_scope_and_absent_owner_binding():
    policy.bind_scopes(policy.normalize(options()),[SCOPE])
    policy.bind_scopes(None,[])


@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('field',sorted(policy.AUTHORITY|policy.PARAMETERS|{'parameters'}))
def test_raw_flat_owner_conflict_even_matching_values_is_rejected(field,auth_mode,monkeypatch):
    raw=owner();value=options();value['compliance_policy']={field:copy.deepcopy(raw.get(field,raw['parameters'].get(field)))}
    with pytest.raises(ValueError):policy.normalize(value)
    with pytest.raises(HTTPException)as caught:intake(value,auth_mode)
    assert caught.value.status_code==422
    calls=[]
    def forbidden(*args,**kwargs):calls.append(True);raise AssertionError('No credential access')
    monkeypatch.setattr(aws,'_session',forbidden)
    with pytest.raises(ValueError,match='owner criteria'):aws.collect({'provider':'aws','auth':{},'scopes':[SCOPE],'options':value},requirements=[])
    assert calls==[]


@pytest.mark.parametrize('seconds,expected',[(0,'collected'),(3600,'collected'),(3601,'unknown'),(-1,'unknown')])
def test_fresh_expired_future_metadata_preserves_clock_and_separates_unknown(seconds,expected):
    raw=owner();normalized=policy.normalize(options(raw));observed=NOW+timedelta(seconds=seconds)
    projected=policy.owner_metadata(normalized,observed)
    assert projected['status']==expected and projected['observed_at']==raw['observed_at']
    assert projected['scope']==SCOPE and projected['max_age_seconds']==3600
    assert {k:projected[k]for k in policy.PARAMETERS}==raw['parameters']
    assert ('owner_authority_status'in projected)==(expected=='unknown')


def test_normalize_metadata_and_merge_deepcopy_unrelated_namespaced_policy():
    value=options();namespace={'aws_organizations':{'status':'collected','scope':ACCOUNT+'/global','audited_account_ids':[ACCOUNT]}}
    value['compliance_policy']=copy.deepcopy(namespace)
    normalized=policy.normalize(value);projected=policy.owner_metadata(normalized,NOW)
    metadata={'other':{'a':1},'compliance_policy':copy.deepcopy(namespace)}
    policy.merge_metadata(metadata,projected)
    assert metadata['compliance_policy']=={**namespace,**projected}and metadata['other']=={'a':1}
    projected['approved_lightsail_principals'].append('later')
    assert 'later'not in metadata['compliance_policy']['approved_lightsail_principals']
    normalized['parameters']['approved_lightsail_actions'].append('later')
    assert value['compliance_parameters'][policy.NAMESPACE]==owner()
    for auth_mode in ['local','cognito']:intake(value,auth_mode)


@pytest.mark.parametrize('field',sorted(policy.AUTHORITY|policy.PARAMETERS))
def test_internal_merge_conflict_preserves_existing_metadata(field):
    projected=policy.owner_metadata(policy.normalize(options()),NOW)
    prior=copy.deepcopy(projected);prior[field]='DIFFERENT';metadata={'compliance_policy':prior};before=copy.deepcopy(metadata)
    with pytest.raises(ValueError):policy.merge_metadata(metadata,projected)
    assert metadata==before
