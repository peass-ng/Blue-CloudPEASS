"""Normal package imports: native SageMaker DTO to selected S3 TAR to consumer."""
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import io,json,socket,tarfile
import boto3
from botocore.stub import Stubber
from botocore.response import StreamingBody
import botocore.response
import pytest
from peaso import secret_scanning as scanning
from peaso.collectors import aws
from peaso.collectors import aws_s3_selected_source_secret_indicators as s3
from peaso.collectors import aws_workload_referenced_source_indicators as work
from peaso.checks import aws_workload_referenced_source_review as check
from peaso.server import content_selection_preflight_20261021 as preflight

ACCOUNT='123456789012';REGION='eu-west-1';SCOPE=ACCOUNT+'/'+REGION
NAME='ScriptTraining';ARN=f'arn:aws:sagemaker:{REGION}:{ACCOUNT}:training-job/{NAME}'
URI='s3://sagemaker-selected-source-bucket/code/source.tar.gz';PROGRAM='entry_point/train.py'
NOW=datetime(2026,10,21,tzinfo=timezone.utc)
TOKEN='ghp_abcdefghijklmnopqrstuvwxyz0123456789'
META={'HTTPStatusCode':200,'RequestId':'native-request-123'}

def target():return {'profile':'sagemaker_training_script','scope':SCOPE,'training_job_arn':ARN,'source_s3_uri':URI,'program':PROGRAM}

def native(*,quoted=False):
    t=target();param=lambda x:json.dumps(x) if quoted else x
    return {'TrainingJobName':NAME,'TrainingJobArn':ARN,'TrainingJobStatus':'Completed','SecondaryStatus':'Completed',
        'ModelArtifacts':{'S3ModelArtifacts':'s3://sagemaker-selected-source-bucket/models/model.tar.gz'},
        'StoppingCondition':{'MaxRuntimeInSeconds':3600},'CreationTime':NOW,
        'HyperParameters':{'sagemaker_submit_directory':param(t['source_s3_uri']),'sagemaker_program':param(t['program'])},
        'ResponseMetadata':dict(META)}

def archive(value,*,program=PROGRAM,binary=False):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w:gz') as tar:
        data=value.encode();row=tarfile.TarInfo(program);row.size=len(data);tar.addfile(row,io.BytesIO(data))
        if binary:
            raw=b'\x00\x01';row=tarfile.TarInfo('weights.bin');row.size=len(raw);tar.addfile(row,io.BytesIO(raw))
    return stream.getvalue()

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):raise AssertionError('network forbidden')
    monkeypatch.setattr(socket.socket,'connect',blocked)
    monkeypatch.setattr(socket,'getaddrinfo',blocked)
    monkeypatch.setattr(botocore.response,'set_socket_timeout',lambda raw,seconds:None)
    def detector(data,path,timeout):return [(TOKEN,'github-pat',1)] if TOKEN.encode() in data else []
    monkeypatch.setattr(scanning,'_scan_kingfisher',detector)
    monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    scanning._RESULTS.clear();yield;scanning._RESULTS.clear()

def execute(content,*,fault=None,quoted=False,disabled=False,capture=False):
    t=target();source=work.source_target(t)
    options={'content_secret_scans':not disabled,'_content_secret_scan_kinds':[work.KIND],
        work.OPTION:[t],s3.OPTION:[source]}
    requests=aws.Requests(options);s3.initialize(requests,options,[SCOPE]);work.initialize(requests,options,[SCOPE])
    requests.content_secret_scan_kinds=frozenset([work.KIND])
    session=boto3.Session(aws_access_key_id='offline',aws_secret_access_key='offline',region_name=REGION)
    if disabled:
        read=work.collect_selected(requests,session,REGION,{'Account':ACCOUNT},options,[SCOPE])
        assert read.status=='not_collected' and requests.calls==0 and not requests._clients
        return read.status,None,None,requests,None
    service,operation,args=work.route(t)
    native_client=requests.client(session,service,REGION,_metadata_profile='aws-selected-configuration-content-v1')
    sts=requests.client(session,'sts',REGION,_metadata_profile=s3.PROFILE)
    s3client=requests.client(session,'s3',REGION,_metadata_profile=s3.PROFILE)
    before=native(quoted=quoted);after=deepcopy(before)
    if fault=='foreign':before['TrainingJobArn']=before['TrainingJobArn'].replace(ACCOUNT,'999999999999')
    if fault=='source_foreign':before['HyperParameters']['sagemaker_submit_directory']='s3://foreign-bucket/code/source.tar.gz'
    if fault=='drift':after['HyperParameters']['sagemaker_program']='other.py'
    if fault=='missing':before['HyperParameters'].pop('sagemaker_program')
    if fault=='data_only':before['HyperParameters']={};before['InputDataConfig']=[{'ChannelName':'train','DataSource':{'S3DataSource':{'S3Uri':URI,'S3DataType':'S3Prefix'}}}]
    if fault=='unsupported':before['HyperParameters']['sagemaker_submit_directory']='https://example.invalid/source.tar.gz'
    bucket=source['bucket'];key=source['key'];etag='"etag-1"';version='v1'
    head={'ETag':etag,'ContentLength':len(content),'VersionId':version,'ResponseMetadata':dict(META)}
    get={**head,'Body':StreamingBody(io.BytesIO(content),len(content))}
    if fault=='truncated':get['ContentLength']=len(content)+1
    after_head={**head,'ETag':'"etag-2"'} if fault=='etag_drift' else head
    with ExitStack() as stack:
        n=stack.enter_context(Stubber(native_client));st=stack.enter_context(Stubber(sts));ob=stack.enter_context(Stubber(s3client))
        if fault=='denied':n.add_client_error(operation,service_error_code='AccessDeniedException',http_status_code=403,expected_params=args)
        else:n.add_response(operation,before,args)
        if fault not in ('foreign','source_foreign','missing','data_only','unsupported','denied','cancelled'):
            n.add_response(operation,after,args)
            st.add_response('get_caller_identity',{'UserId':'offline','Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/offline','ResponseMetadata':dict(META)},{})
            ob.add_response('get_bucket_location',{'LocationConstraint':REGION,'ResponseMetadata':dict(META)},{'Bucket':bucket,'ExpectedBucketOwner':ACCOUNT})
            head_args={'Bucket':bucket,'Key':key,'ExpectedBucketOwner':ACCOUNT}
            if fault=='owner_changed':ob.add_client_error('head_object',service_error_code='AccessDenied',http_status_code=403,expected_params=head_args)
            else:
                ob.add_response('head_object',head,head_args)
                ob.add_response('get_object',get,{**head_args,'IfMatch':etag})
                ob.add_response('head_object',after_head,{**head_args,'IfMatch':etag})
        if fault=='cancelled':requests.cancel_event=SimpleNamespace(is_set=lambda:requests.calls>0)
        read=work.collect_selected(requests,session,REGION,{'Account':ACCOUNT},options,[SCOPE])
    item=read.items[0];metadata={**requests.s3_source_metadata,**requests.workload_source_metadata}
    index={'context':{'provider':'aws','scope':SCOPE,'metadata':metadata},'collections':{
        work.KIND:[{'scope':SCOPE,'service':service,'status':'collected','items':[item]}]}}
    status,evidence=check.evaluate(item,index)
    assert TOKEN not in json.dumps((item,evidence,metadata),default=str)
    return status,evidence,item,requests,index

def test_positive_clean_and_json_encoded_parameters():
    for quoted in (False,True):
        for value,expected in ((TOKEN,'FAIL'),('mode=ready','PASS')):
            status,evidence,item,requests,_=execute(archive(value),quoted=quoted)
            assert status==expected,(status,evidence,item[work.MARKER])
            assert requests.workload_source_calls[work.identity(target())]==2
            if expected=='FAIL':assert len(evidence['secret_leaks'])==1 and len(evidence['secret_leaks'][0]['detectors'])==2

def test_negative_native_and_s3_faults():
    for fault in ('foreign','source_foreign','drift','missing','data_only','unsupported','denied','owner_changed','etag_drift','truncated','cancelled'):
        status,evidence,item,_,_=execute(archive('mode=ready'),fault=fault)
        assert status=='UNKNOWN',(fault,status,evidence,item[work.MARKER])

def test_partial_positive_and_missing_program():
    status,evidence,_,_,_=execute(archive(TOKEN),fault='drift')
    assert status=='FAIL' and evidence['complete'] is False
    status,evidence,_,_,_=execute(archive('mode=ready',program='other.py'))
    assert status=='UNKNOWN' and evidence['complete'] is False
    status,evidence,_,_,_=execute(archive(TOKEN,binary=True))
    assert status=='FAIL' and evidence['complete'] is False
    status,evidence,_,_,_=execute(archive('mode=ready',binary=True))
    assert status=='UNKNOWN' and evidence['complete'] is False

def test_selection_and_default_off_zero_io():
    t=target();source=work.source_target(t)
    assert execute(archive('mode=ready'),disabled=True)[0]=='not_collected'
    options={'content_secret_scans':True,'_content_secret_scan_kinds':[work.KIND],work.OPTION:[t],
        s3.OPTION:[source,{'scope':SCOPE,'bucket':'other-bucket','key':'other.tar.gz','format':'tar.gz'}]}
    with pytest.raises(ValueError,match='workload_extra_s3_selection'):work.selected_targets(options,[SCOPE])
    with pytest.raises(ValueError,match='workload_extra_s3_selection'):preflight.workload_ref.selected_targets(options,[SCOPE])
    exact={**options,s3.OPTION:[source]}
    assert preflight.workload_ref.selected_targets(exact,[SCOPE])==work.selected_targets(exact,[SCOPE])
    foreign=deepcopy(t);foreign['training_job_arn']=ARN.replace(ACCOUNT,'999999999999')
    with pytest.raises(ValueError):work.selected_targets({**options,work.OPTION:[foreign],s3.OPTION:[source]},[SCOPE])
    with pytest.raises(ValueError):preflight.workload_ref.selected_targets({**options,work.OPTION:[foreign],s3.OPTION:[source]},[SCOPE])
    requests=aws.Requests({**options,s3.OPTION:[source]});s3.initialize(requests,{**options,s3.OPTION:[source]},[SCOPE]);work.initialize(requests,{**options,s3.OPTION:[source]},[SCOPE])
    session=boto3.Session(aws_access_key_id='offline',aws_secret_access_key='offline',region_name=REGION)
    result=work.collect_selected(requests,session,REGION,{'Account':'999999999999'},{**options,s3.OPTION:[source]},[SCOPE])
    assert result.status=='not_collected' and requests.calls==0 and not requests._clients

def native_cases():
    cases=[]
    for name,value,fault,expected in (
        ('pass_clean','mode=ready',None,'PASS'),('fail_secret',TOKEN,None,'FAIL'),
        ('unknown_missing','mode=ready','missing','UNKNOWN'),('unknown_drift','mode=ready','drift','UNKNOWN'),
        ('fail_partial_positive',TOKEN,'drift','FAIL')):
        status,_,item,_,index=execute(archive(value),fault=fault,capture=True)
        assert status==expected
        cases.append({'name':name,'item':item,'index':index,'expected':expected})
    document={'schema_version':1,'check_id':work.CHECK,'cases':cases}
    encoded=json.dumps(document,sort_keys=True,indent=2)
    assert TOKEN not in encoded and len(encoded)<500000
    return document

def test_native_cases_capture():
    document=native_cases()
    assert [c['expected'] for c in document['cases']]==['PASS','FAIL','UNKNOWN','UNKNOWN','FAIL']

def test_native_cases_replay():
    path=Path(__file__).resolve().parent/'fixtures/aws_sagemaker_training_native_20261021.json'
    document=json.loads(path.read_text())
    assert document['check_id']==work.CHECK and len(document['cases'])==5
    for case in document['cases']:
        assert check.evaluate(case['item'],case['index'])[0]==case['expected']
