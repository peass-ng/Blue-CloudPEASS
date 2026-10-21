"""Selected CloudFormation/CodePipeline reads through SDK and existing consumer."""
from copy import deepcopy
from types import SimpleNamespace
from threading import RLock
import json
import socket
import boto3
from botocore.stub import Stubber
import pytest
from peaso import secret_scanning
from peaso.collectors import aws_selected_configuration_secret_indicators as source
from peaso.checks import aws_selected_configuration_secret_review_20261020 as consumer

ACCOUNT='123456789012';REGION='us-east-1';SCOPE=ACCOUNT+'/'+REGION
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
CALLER={'Account':ACCOUNT,'Arn':'arn:aws:iam::'+ACCOUNT+':user/reviewer','UserId':'synthetic-reviewer'}


def target(surface):
    if surface=='cloudformation_template':
        return {'surface':surface,'scope':SCOPE,'resource_id':'arn:aws:cloudformation:'+REGION+':'+ACCOUNT+':stack/ReviewStack/11111111-1111-4111-8111-111111111111'}
    return {'surface':surface,'scope':SCOPE,'resource_id':'arn:aws:codepipeline:'+REGION+':'+ACCOUNT+':ReviewPipeline','version':7}


def response(surface,positive=False):
    value=TOKEN if positive else 'ordinary-mode'
    if surface=='cloudformation_template':
        return {'TemplateBody':'Resources:\n  Example:\n    Type: AWS::SSM::Parameter\n    Properties:\n      Value: '+value+'\n','StagesAvailable':['Original','Processed']}
    return {'metadata':{'pipelineArn':target(surface)['resource_id']},'pipeline':{
        'name':'ReviewPipeline','version':7,'roleArn':'arn:aws:iam::'+ACCOUNT+':role/pipeline',
        'artifactStore':{'type':'S3','location':'selected-artifacts'},
        'stages':[{'name':'Source','actions':[{'name':'Read','actionTypeId':{'category':'Source','owner':'AWS','provider':'S3','version':'1'},
            'configuration':{'S3Bucket':'selected-artifacts','S3ObjectKey':'source.zip','testCredential':value},'outputArtifacts':[{'name':'SourceArtifact'}],'runOrder':1}]}]}}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def block(*a,**kw):raise AssertionError('network forbidden')
    monkeypatch.setattr(socket,'create_connection',block);monkeypatch.setattr(socket.socket,'connect',block)
    secret_scanning._RESULTS.clear()
    def detector(payload,path,timeout):return [(TOKEN,'github-pat',1)] if TOKEN.encode() in payload else []
    monkeypatch.setattr(secret_scanning,'_scan_kingfisher',detector)
    monkeypatch.setattr(secret_scanning,'_scan_trufflehog',detector)
    yield
    secret_scanning._RESULTS.clear()


def capture(surface,positive=False,mutate=None,denied=False,disabled=False,cancel=False):
    selected=target(surface)
    opts={'content_secret_scans':not disabled,'_content_secret_scan_kinds':[source.KIND],source.OPTION:[selected]}
    req=SimpleNamespace(_lock=RLock(),content_secret_scans=not disabled,content_secret_scan_kinds={source.KIND},check_deadline=lambda:None)
    source.initialize(req,opts,[SCOPE])
    service,operation,args=source.route(selected)
    raw=response(surface,positive)
    if mutate:mutate(raw)
    client=boto3.client(service,region_name=REGION,aws_access_key_id='inert',aws_secret_access_key='inert')
    session=object();calls=[]
    def dispatch(session_arg,service_arg,region_arg,operation_arg,*,_metadata_profile,**arguments):
        assert session_arg is session and (service_arg,region_arg,operation_arg)==(service,REGION,operation)
        assert _metadata_profile==source.PROFILE
        source.validate_request(service,operation,arguments,request_context=(req,session),region=REGION)
        source.before_request(req);source.validate_native_client(client,service,REGION)
        calls.append((service,operation,deepcopy(arguments)))
        native=getattr(client,operation)(**arguments)
        return source.project_response(native,service,operation,arguments,request_context=(req,session),region=REGION)
    req.call=dispatch
    with Stubber(client) as stub:
        if denied:stub.add_client_error(operation,service_error_code='AccessDeniedException',expected_params=args)
        else:
            raw['ResponseMetadata']={'HTTPStatusCode':200,'RequestId':'11111111-1111-4111-8111-111111111111'}
            stub.add_response(operation,raw,args)
        if cancel:req.check_deadline=lambda:(_ for _ in ()).throw(ValueError('cancelled'))
        result=source.collect_selected(req,session,REGION,CALLER,opts,[SCOPE])
        if not disabled and not cancel:stub.assert_no_pending_responses()
    client.close()
    if not result.items:return None,None,calls
    for item in result.items:item.update(AccountId=ACCOUNT,Region=REGION)
    idx={'context':{'provider':'aws','scope':SCOPE,'metadata':{**req.configuration_content_metadata,'caller_identities':[CALLER]}},
        'collections':{source.KIND:[{'scope':SCOPE,'account_id':ACCOUNT,'status':'collected','items':result.items}],
            'aws_account':[{'scope':ACCOUNT+'/global','account_id':ACCOUNT,'global':True,'status':'collected','items':[CALLER]}]}}
    item=result.items[0]
    status,evidence=consumer.evaluate(item,idx)
    assert TOKEN not in json.dumps({'item':item,'index':idx,'evidence':evidence})
    return status,evidence,calls


@pytest.mark.parametrize('surface',['cloudformation_template','codepipeline_configuration'])
@pytest.mark.parametrize('positive',[False,True])
def test_sdk_selected_content_to_evaluator(surface,positive):
    status,evidence,calls=capture(surface,positive)
    assert status==('FAIL' if positive else 'PASS'),evidence
    assert len(calls)==1 and evidence['surface']==surface
    if positive:
        assert len(evidence['secret_leaks'])==1
        assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}


@pytest.mark.parametrize('surface',['cloudformation_template','codepipeline_configuration'])
def test_denied_cancel_and_disabled(surface):
    assert capture(surface,denied=True)[0]=='UNKNOWN'
    assert capture(surface,cancel=True)[0]=='UNKNOWN'
    result,_,calls=capture(surface,disabled=True)
    assert result is None and calls==[]


@pytest.mark.parametrize('field,value',[('name','Other'),('version',8)])
def test_foreign_pipeline_or_revision_unknown(field,value):
    assert capture('codepipeline_configuration',mutate=lambda r:r['pipeline'].update({field:value}))[0]=='UNKNOWN'


def test_foreign_pipeline_arn_unknown():
    assert capture('codepipeline_configuration',mutate=lambda r:r['metadata'].update(pipelineArn=target('codepipeline_configuration')['resource_id'].replace(ACCOUNT,'999999999999')))[0]=='UNKNOWN'


def test_wrong_template_stage_unknown():
    assert capture('cloudformation_template',mutate=lambda r:r.update(StagesAvailable=['Processed']))[0]=='UNKNOWN'


def test_json_and_native_document_multiline_literals():
    body={'Resources':{'Example':{'Properties':{'Value':TOKEN,'Key':'line1\nline2'}}}}
    info={'surface':'cloudformation_template','account':ACCOUNT,'region':REGION,'partition':'aws'}
    args={'StackName':target('cloudformation_template')['resource_id'],'TemplateStage':'Original'}
    for value in [body,json.dumps(body)]:
        raw,_=source.extract({'TemplateBody':value,'StagesAvailable':['Original']},'cloudformation','get_template',args,info)
        assert TOKEN.encode() in raw and b'line1\nline2' in raw


def test_selector_account_version_and_endpoint_preflight():
    for update in [{'resource_id':target('codepipeline_configuration')['resource_id'].replace(ACCOUNT,'999999999999')}, {'version':0}, {'version':True}]:
        with pytest.raises(ValueError):source.parse({**target('codepipeline_configuration'),**update})
    poison=SimpleNamespace(meta=SimpleNamespace(endpoint_url='https://codepipeline.other.invalid'))
    with pytest.raises(Exception):source.validate_native_client(poison,'codepipeline',REGION)


def test_document_depth_bound():
    nested={};cursor=nested
    for _ in range(35):cursor['next']={};cursor=cursor['next']
    with pytest.raises(ValueError):source._document_literals(nested)
