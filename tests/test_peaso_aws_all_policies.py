"""Full native policy producer -> signed configuration evaluator contracts."""
import copy
import json
from types import SimpleNamespace
import boto3
from botocore.stub import Stubber
import pytest
from peaso.collectors import aws
from peaso.collectors.aws_all_policies import collect
from peaso.checks import evaluate_check
from peaso.checks.aws_all_policies import MODES

ACCOUNT='123456789012'
ARN='arn:aws:iam::aws:policy/TestPolicy'


def produce(document=None, deny=False):
    session=boto3.Session(aws_access_key_id='fake',aws_secret_access_key='fake',region_name='us-east-1')
    client=session.client('iam')
    requests=aws.Requests({'concurrency':1})
    requests.client=lambda *args:client
    with Stubber(client) as stub:
        stub.add_response('list_policies',{'Policies':[{'Arn':ARN,'DefaultVersionId':'v1'}],'IsTruncated':True,'Marker':'next'}, {'Scope':'All','OnlyAttached':False})
        stub.add_response('list_policies',{'Policies':[],'IsTruncated':False},{'Scope':'All','OnlyAttached':False,'Marker':'next'})
        if deny:stub.add_client_error('get_policy_version',service_error_code='AccessDenied',expected_params={'PolicyArn':ARN,'VersionId':'v1'})
        else:stub.add_response('get_policy_version',{'PolicyVersion':{'VersionId':'v1','IsDefaultVersion':True,'Document':json.dumps(document or {'Statement':[{'Effect':'Allow','Action':'s3:GetObject','Resource':'arn:aws:s3:::bucket/object'}]})}},{'PolicyArn':ARN,'VersionId':'v1'})
        result=collect(requests,session,'us-east-1',ACCOUNT)
        stub.assert_no_pending_responses()
    return result


def index(read):
    scope=ACCOUNT+'/global'
    kinds={'iam_managed_policy':read.items,'iam_user':[],'iam_group':[],'iam_role':[]}
    return {'context':{'provider':'aws','Account':ACCOUNT,'scope':scope},
      'collections':{k:[{'type':k,'scope':scope,'status':read.status if k=='iam_managed_policy' else 'empty','items':v}]for k,v in kinds.items()},
      **{k:[{'type':k,'scope':scope,'data':r}for r in v]for k,v in kinds.items()}}


def grade(ident,facts):return evaluate_check(ident,{'scope':ACCOUNT+'/global'},facts)[0]


@pytest.mark.parametrize('ident',MODES)
def test_real_sdk_paged_producer_pass_fail_unknown(ident):
    safe=produce();assert grade(ident,index(safe))=='PASS'
    resource='arn:aws:s3:::bucket/object' if MODES[ident]=='scoped_service'else '*'
    action='s3:*'if MODES[ident]in ('service','managed_service','scoped_service')else '*'
    bad=produce({'Statement':[{'Effect':'Allow','Action':action,'Resource':resource}]})
    facts=index(bad);before=copy.deepcopy(facts);assert grade(ident,facts)=='FAIL';assert facts==before
    assert grade(ident,index(produce(deny=True)))=='UNKNOWN'
    partial=index(safe);partial['collections']['iam_managed_policy'][0]['status']='partial';assert grade(ident,partial)=='UNKNOWN'
    foreign=index(safe);foreign['collections']['iam_managed_policy'][0]['scope']='999999999999/global';assert grade(ident,foreign)=='UNKNOWN'
    duplicate=index(safe);duplicate['iam_managed_policy']*=2;assert grade(ident,duplicate)=='UNKNOWN'


@pytest.mark.parametrize('ident',[i for i,m in MODES.items()if m!='managed_service'])
def test_inline_policy_is_scanned_and_missing_principal_inventory_is_unknown(ident):
    facts=index(produce());scope=ACCOUNT+'/global'
    action='s3:*'if MODES[ident]in ('service','scoped_service')else '*'
    resource='arn:aws:s3:::bucket/object'if MODES[ident]=='scoped_service'else '*'
    row={'Arn':f'arn:aws:iam::{ACCOUNT}:role/Test','_provenance':{'operation':'iam:GetAccountAuthorizationDetails','native_response_complete':True},'RolePolicyList':[{'PolicyName':'inline','PolicyDocument':{'Statement':[{'Effect':'Allow','Action':action,'Resource':resource}]}}]}
    facts['iam_role']=[{'type':'iam_role','scope':scope,'data':row}];facts['collections']['iam_role'][0].update(status='collected',items=[row])
    assert grade(ident,facts)=='FAIL'
    facts['collections']['iam_role'][0]['status']='denied';assert grade(ident,facts)=='UNKNOWN'


@pytest.mark.parametrize('ident',MODES)
def test_notaction_and_malformed_document_are_unknown(ident):
    assert grade(ident,index(produce({'Statement':[{'Effect':'Allow','NotAction':'iam:*','Resource':'*'}]})))=='UNKNOWN'
    assert grade(ident,index(produce({'Statement':['bad']})))=='UNKNOWN'
