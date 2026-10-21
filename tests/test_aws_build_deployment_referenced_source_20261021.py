"""Normal package imports, exact native Stubber DTOs, and bounded S3 SDK path."""
from contextlib import ExitStack
from datetime import datetime,timezone
from pathlib import Path
import importlib,io,json,re,socket,sys,zipfile
from types import SimpleNamespace
import boto3
from botocore.stub import Stubber
from botocore.response import StreamingBody
import botocore.response
import pytest

from peaso import secret_scanning as scanning
from peaso.collectors import aws
from peaso.collectors import aws_s3_selected_source_secret_indicators as s3
from peaso.collectors import aws_build_deployment_referenced_source_indicators as build
from peaso.checks import aws_build_deployment_referenced_source_review as check
ACCOUNT='123456789012';REGION='eu-west-1';SCOPE=ACCOUNT+'/'+REGION
NOW=datetime(2026,10,21,tzinfo=timezone.utc)
TOKEN='ghp_abcdefghijklmnopqrstuvwxyz0123456789'
META={'HTTPStatusCode':200,'RequestId':'native-request-123'}
# These DTOs cover project/version and completed artifact declarations.
# CodeCommit has its separate native GetFile test matrix.
PROFILES=['codebuild_s3_source','codebuild_s3_buildspec','elasticbeanstalk_source_bundle','amplify_s3_zip_deployment','codebuild_build_output','codepipeline_action_output']

def target(profile):
    t={'profile':profile,'scope':SCOPE,'source_s3_uri':'s3://selected-source-bucket/jobs/source.zip'}
    if profile=='codebuild_build_output':t['build_arn']=f'arn:aws:codebuild:{REGION}:{ACCOUNT}:build/AuditProject:11111111-1111-4111-8111-111111111111'
    elif profile=='codepipeline_action_output':t.update(pipeline_arn=f'arn:aws:codepipeline:{REGION}:{ACCOUNT}:AuditPipeline',pipeline_name='AuditPipeline',pipeline_execution_id='11111111-1111-4111-8111-111111111111',action_execution_id='22222222-2222-4222-8222-222222222222',artifact_name='Output')
    elif profile=='codebuild_s3_source':t['project_arn']=f'arn:aws:codebuild:{REGION}:{ACCOUNT}:project/AuditProject'
    elif profile=='codebuild_s3_buildspec':t.update(project_arn=f'arn:aws:codebuild:{REGION}:{ACCOUNT}:project/AuditProject',source_s3_uri='s3://selected-source-bucket/jobs/buildspec.yml')
    elif profile=='elasticbeanstalk_source_bundle':t.update(application_name='AuditApp',version_label='v1',version_arn=f'arn:aws:elasticbeanstalk:{REGION}:{ACCOUNT}:applicationversion/AuditApp/v1')
    else:t.update(app_id='d123abc',branch_name='main',job_id='7',job_arn=f'arn:aws:amplify:{REGION}:{ACCOUNT}:apps/d123abc/branches/main/jobs/7')
    return t

def native(t):
    profile=t['profile'];source=build.source_target(t);uri=t['source_s3_uri']
    if profile=='codebuild_build_output':
        return {'builds':[{'arn':t['build_arn'],'id':t['build_arn'].split(':build/',1)[1],'projectName':'AuditProject','buildStatus':'SUCCEEDED','buildComplete':True,'endTime':NOW,'artifacts':{'location':'arn:aws:s3:::'+source['bucket']+'/'+source['key']}}],'ResponseMetadata':dict(META)}
    if profile=='codepipeline_action_output':
        return {'actionExecutionDetails':[{'pipelineExecutionId':t['pipeline_execution_id'],'actionExecutionId':t['action_execution_id'],'pipelineVersion':1,'stageName':'Build','actionName':'Build','status':'Succeeded','output':{'outputArtifacts':[{'name':'Output','s3location':{'bucket':source['bucket'],'key':source['key']}}]}}],'ResponseMetadata':dict(META)}
    if profile.startswith('codebuild_'):
        row={'name':'AuditProject','arn':t['project_arn'],'lastModified':NOW,
            'source':{'type':'S3' if profile=='codebuild_s3_source' else 'GITHUB',
                      'location':source['bucket']+'/'+source['key'] if profile=='codebuild_s3_source' else 'https://github.com/example/audit',
                      'buildspec':'arn:aws:s3:::'+source['bucket']+'/'+source['key'] if profile=='codebuild_s3_buildspec' else 'buildspec.yml'}}
        if 'version_id' in t:row['sourceVersion']=t['version_id']
        return {'projects':[row],'ResponseMetadata':dict(META)}
    if profile=='elasticbeanstalk_source_bundle':
        return {'ApplicationVersions':[{'ApplicationVersionArn':t['version_arn'],'ApplicationName':t['application_name'],
            'VersionLabel':t['version_label'],'DateUpdated':NOW,'SourceBundle':{'S3Bucket':source['bucket'],'S3Key':source['key']}}],
            'ResponseMetadata':dict(META)}
    return {'job':{'summary':{'jobArn':t['job_arn'],'jobId':t['job_id'],'commitId':'manual-commit',
        'commitMessage':'offline','commitTime':NOW,'startTime':NOW,'jobType':'MANUAL','status':'SUCCEED',
        'sourceUrl':uri,'sourceUrlType':'ZIP'},'steps':[]},'ResponseMetadata':dict(META)}

def zipdata(data):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as archive:archive.writestr('source.py',data)
    return stream.getvalue()

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):raise AssertionError('network forbidden')
    monkeypatch.setattr(socket.socket,'connect',blocked)
    monkeypatch.setattr(socket,'getaddrinfo',blocked)
    monkeypatch.setattr(botocore.response,'set_socket_timeout',lambda raw,seconds:None)
    def detector(data,path,timeout):return [(TOKEN,'github-pat',1)] if TOKEN.encode() in data else []
    monkeypatch.setattr(scanning,'_scan_kingfisher',detector)
    monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()

def execute(t,content,*,fault=None,disabled=False,capture=False):
    options={'content_secret_scans':not disabled,'_content_secret_scan_kinds':[build.KIND],
        build.OPTION:[t],s3.OPTION:[build.source_target(t)]}
    requests=aws.Requests(options)
    s3.initialize(requests,options,[SCOPE]);build.initialize(requests,options,[SCOPE])
    requests.content_secret_scan_kinds=frozenset([build.KIND])
    session=boto3.Session(aws_access_key_id='offline',aws_secret_access_key='offline',region_name=REGION)
    if disabled:
        read=build.collect_selected(requests,session,REGION,{'Account':ACCOUNT},options,[SCOPE])
        assert not requests._clients and requests.calls==0
        return read.status,None,None,requests
    service,operation,args=build.route(t)
    native_client=requests.client(session,service,REGION,_metadata_profile='aws-selected-configuration-content-v1')
    sts=requests.client(session,'sts',REGION,_metadata_profile=s3.PROFILE)
    s3client=requests.client(session,'s3',REGION,_metadata_profile=s3.PROFILE)
    before=native(t);after=native(t)
    if t['profile'] in ('codebuild_build_output','codepipeline_action_output') and fault in ('foreign_bucket','revision_drift','missing','unsupported'):
        if t['profile']=='codebuild_build_output':
            if fault=='foreign_bucket':before['builds'][0]['artifacts']['location']='arn:aws:s3:::foreign-bucket/jobs/source.zip'
            elif fault=='revision_drift':after['builds'][0]['endTime']=datetime(2026,10,22,tzinfo=timezone.utc)
            elif fault=='missing':before['builds']=[]
            else:before['builds'][0]['buildStatus']='IN_PROGRESS'
        else:
            if fault=='foreign_bucket':before['actionExecutionDetails'][0]['output']['outputArtifacts'][0]['s3location']['bucket']='foreign-bucket'
            elif fault=='revision_drift':after['actionExecutionDetails'][0]['pipelineVersion']=2
            elif fault=='missing':before['actionExecutionDetails']=[]
            else:before['actionExecutionDetails'][0]['status']='InProgress'
    elif fault=='foreign_bucket':
        if t['profile']=='elasticbeanstalk_source_bundle':before['ApplicationVersions'][0]['SourceBundle']['S3Bucket']='foreign-bucket'
        elif t['profile']=='amplify_s3_zip_deployment':before['job']['summary']['sourceUrl']='s3://foreign-bucket/jobs/source.zip'
        elif t['profile']=='codebuild_s3_source':before['projects'][0]['source']['location']='foreign-bucket/jobs/source.zip'
        else:before['projects'][0]['source']['buildspec']='arn:aws:s3:::foreign-bucket/jobs/buildspec.yml'
    if fault=='revision_drift' and t['profile'] not in ('codebuild_build_output','codepipeline_action_output'):
        if t['profile'].startswith('codebuild_'):after['projects'][0]['lastModified']=datetime(2026,10,22,tzinfo=timezone.utc)
        elif t['profile']=='elasticbeanstalk_source_bundle':after['ApplicationVersions'][0]['DateUpdated']=datetime(2026,10,22,tzinfo=timezone.utc)
        else:after['job']['summary']['commitId']='other-commit'
    if fault=='missing' and t['profile'] not in ('codebuild_build_output','codepipeline_action_output'):
        if t['profile'].startswith('codebuild_'):before.pop('projects');before['projectsNotFound']=['AuditProject']
        elif t['profile']=='elasticbeanstalk_source_bundle':before['ApplicationVersions']=[]
        else:before['job']['summary'].pop('sourceUrl')
    if fault=='unsupported' and t['profile'] not in ('codebuild_build_output','codepipeline_action_output'):
        if t['profile']=='codebuild_s3_source':before['projects'][0]['source']['type']='GITHUB'
        elif t['profile']=='codebuild_s3_buildspec':before['projects'][0]['source']['buildspec']='buildspec.yml'
        elif t['profile']=='elasticbeanstalk_source_bundle':before['ApplicationVersions'][0].pop('SourceBundle')
        else:before['job']['summary']['sourceUrlType']='BUCKET_PREFIX'
    source=build.source_target(t);bucket=source['bucket'];key=source['key'];etag='"etag-1"';version='v1'
    head={'ETag':etag,'ContentLength':len(content),'VersionId':version,'ResponseMetadata':dict(META)}
    get={**head,'Body':StreamingBody(io.BytesIO(content),len(content))}
    if fault=='truncated':get['ContentLength']=len(content)+1
    if fault=='etag_drift':after_head={**head,'ETag':'"etag-2"'}
    else:after_head=head
    with ExitStack() as stack:
        n=stack.enter_context(Stubber(native_client));ss=stack.enter_context(Stubber(sts));ob=stack.enter_context(Stubber(s3client))
        if fault=='denied':n.add_client_error(operation,service_error_code='AccessDeniedException',http_status_code=403,expected_params=args)
        else:n.add_response(operation,before,args)
        if fault not in ('foreign_bucket','missing','unsupported','denied','cancelled'):
            n.add_response(operation,after,args)
        if fault not in ('foreign_bucket','missing','unsupported','denied','cancelled'):
            ss.add_response('get_caller_identity',{'UserId':'offline','Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/offline','ResponseMetadata':dict(META)},{})
            ob.add_response('get_bucket_location',{'LocationConstraint':REGION,'ResponseMetadata':dict(META)},{'Bucket':bucket,'ExpectedBucketOwner':ACCOUNT})
            head_args={'Bucket':bucket,'Key':key,'ExpectedBucketOwner':ACCOUNT,**({'VersionId':version} if 'version_id' in source else {})}
            if fault=='owner_changed':
                ob.add_client_error('head_object',service_error_code='AccessDenied',http_status_code=403,expected_params=head_args)
            else:
                ob.add_response('head_object',head,head_args)
                ob.add_response('get_object',get,{**head_args,'IfMatch':etag})
                ob.add_response('head_object',after_head,{**head_args,'IfMatch':etag})
        if fault=='cancelled':requests.cancel_event=SimpleNamespace(is_set=lambda:requests.calls>0)
        read=build.collect_selected(requests,session,REGION,{'Account':ACCOUNT},options,[SCOPE])
    item=read.items[0]
    metadata={**requests.s3_source_metadata,**requests.build_deployment_metadata}
    index={'context':{'provider':'aws','scope':SCOPE,'metadata':metadata},'collections':{
        build.KIND:[{'scope':SCOPE,'service':service,'status':'collected','items':[item]}]}}
    status,evidence=check.evaluate(item,index)
    assert TOKEN not in json.dumps((item,evidence,metadata),default=str)
    return (status,evidence,item,requests,index) if capture else (status,evidence,item,requests)

@pytest.mark.parametrize('profile',PROFILES)
def test_positive_clean(profile):
    t=target(profile)
    for value,expect in ((TOKEN,'FAIL'),('mode=ready','PASS')):
        content=value.encode() if profile=='codebuild_s3_buildspec' else zipdata(value)
        status,evidence,item,requests=execute(t,content)
        assert status==expect,(profile,status,evidence,item[build.MARKER],requests.s3_source_metadata.get(s3.KIND+'_receipts'))
        assert requests.build_deployment_calls[build.identity(t)]==2
        if expect=='FAIL':assert len(evidence['secret_leaks'])==1 and len(evidence['secret_leaks'][0]['detectors'])==2

@pytest.mark.parametrize('profile',PROFILES)
def test_foreign_drift_denied(profile):
    t=target(profile);content=b'mode=ready' if profile=='codebuild_s3_buildspec' else zipdata('mode=ready')
    for fault in ('foreign_bucket','revision_drift','denied'):
        status,evidence,item,_=execute(t,content,fault=fault)
        assert status=='UNKNOWN',(profile,fault,status,evidence)
        if fault=='foreign_bucket':assert item[build.MARKER]['s3_item'] is None

def test_missing_owner_etag_truncated_cancel():
    t=target('codebuild_s3_source');content=zipdata('mode=ready')
    for fault in ('missing','owner_changed','etag_drift','truncated'):
        status,evidence,item,_=execute(t,content,fault=fault)
        assert status=='UNKNOWN',(fault,status,evidence)
    with pytest.raises(aws.ReadFailure) as cancelled:
        execute(t,content,fault='cancelled')
    assert cancelled.value.code=='collection_cancelled'

@pytest.mark.parametrize('profile',PROFILES)
def test_positive_survives_native_revision_drift(profile):
    t=target(profile);content=TOKEN.encode() if profile=='codebuild_s3_buildspec' else zipdata(TOKEN)
    status,evidence,item,_=execute(t,content,fault='revision_drift')
    assert status=='FAIL' and evidence['complete'] is False
    assert item[build.MARKER]['association_coherent'] is False

def test_versioned_source_and_unsupported_amplify_url():
    t=target('codebuild_s3_source');t['version_id']='v1'
    status,evidence,item,_=execute(t,zipdata(TOKEN))
    assert status=='FAIL' and item[build.MARKER]['s3_item'][s3.MARKER]['object']['explicit_version'] is True
    a=target('amplify_s3_zip_deployment')
    a['source_s3_uri']='https://example.invalid/signed.zip'
    with pytest.raises(ValueError):build.selected_targets({'content_secret_scans':True,
        '_content_secret_scan_kinds':[build.KIND],build.OPTION:[a],s3.OPTION:[{'scope':SCOPE,'bucket':'selected-source-bucket','key':'jobs/source.zip','format':'zip'}]},[SCOPE])

@pytest.mark.parametrize('profile',PROFILES)
def test_unsupported_native_reference_is_unknown_without_s3(profile):
    t=target(profile);payload=b'mode=ready' if profile=='codebuild_s3_buildspec' else zipdata('mode=ready')
    status,evidence,item,_=execute(t,payload,fault='unsupported')
    assert status=='UNKNOWN' and item[build.MARKER]['s3_item'] is None

def test_default_off_zero_io_and_extra_s3():
    t=target('codebuild_s3_source')
    assert execute(t,zipdata('mode=ready'),disabled=True)[0]=='not_collected'
    options={'content_secret_scans':True,'_content_secret_scan_kinds':[build.KIND],build.OPTION:[t],
        s3.OPTION:[build.source_target(t),{'scope':SCOPE,'bucket':'extra-bucket','key':'other.zip','format':'zip'}]}
    with pytest.raises(ValueError,match='extra_s3'):build.selected_targets(options,[SCOPE])
