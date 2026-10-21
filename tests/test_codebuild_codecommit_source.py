"""Offline native SDK route through the selected producer and normal consumer."""
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
import json
import socket
import sys

HERE=Path(__file__).resolve().parents[1]
from peaso import secret_scanning as scanning
from peaso.collectors import aws_build_deployment_referenced_source_indicators as build
from peaso.collectors import aws_s3_selected_source_secret_indicators as s3
from peaso.collectors.aws import ReadFailure
from peaso.checks import aws_build_deployment_referenced_source_review as check
import boto3
from botocore.stub import Stubber
import pytest

assert Path(build.__file__).resolve()==HERE/'peaso/collectors/aws_build_deployment_referenced_source_indicators.py'
assert Path(check.__file__).resolve()==HERE/'peaso/checks/aws_build_deployment_referenced_source_review.py'
ACCOUNT='123456789012';REGION='eu-west-1';SCOPE=ACCOUNT+'/'+REGION
BUILD=f'arn:aws:codebuild:{REGION}:{ACCOUNT}:build/AuditProject:11111111-2222-3333-4444-555555555555'
REPO=f'arn:aws:codecommit:{REGION}:{ACCOUNT}:AuditRepo'
COMMIT='a'*40;BLOB='b'*40
TOKEN='ghp_abcdefghijklmnopqrstuvwxyz0123456789'
NOW=datetime(2026,10,21,tzinfo=timezone.utc)
META={'HTTPStatusCode':200,'RequestId':'offline-request-1'}

def target():
    return {'profile':'codebuild_codecommit_source','scope':SCOPE,'build_arn':BUILD,
        'repository_arn':REPO,'commit_id':COMMIT,'file_path':'/source/config.txt'}

def build_row(*,repo='AuditRepo',commit=COMMIT):
    return {'builds':[{'arn':BUILD,'id':BUILD.split(':build/',1)[1],
        'projectName':'AuditProject','buildStatus':'SUCCEEDED','buildComplete':True,
        'endTime':NOW,'source':{'type':'CODECOMMIT',
            'location':f'https://git-codecommit.{REGION}.amazonaws.com/v1/repos/{repo}'},
        'resolvedSourceVersion':commit}],'ResponseMetadata':dict(META)}

def repository(*,arn=REPO,rid='11111111-2222-3333-4444-555555555555'):
    return {'repositoryMetadata':{'repositoryName':'AuditRepo','Arn':arn,
        'accountId':ACCOUNT,'repositoryId':rid},'ResponseMetadata':dict(META)}

def file_row(payload,*,commit=COMMIT,path='/source/config.txt',blob=BLOB):
    return {'commitId':commit,'filePath':path,'blobId':blob,'fileMode':'NORMAL',
        'fileSize':len(payload),'fileContent':payload,'ResponseMetadata':dict(META)}

class Requests:
    def __init__(self,options,session):
        self.content_secret_scans=options['content_secret_scans']
        self.content_secret_scan_kinds=frozenset(options['_content_secret_scan_kinds'])
        self.calls=0;self.max_calls=12;self._lock=RLock();self.session=session
        self.clients={}
        build.initialize(self,options,[SCOPE])
    def check_deadline(self):
        if getattr(self,'cancel_after_repository',False) and self.calls>=2:
            raise ReadFailure('not_collected','collection_cancelled')
        return None
    def client(self,session,service,region,**kw):
        assert session is self.session and region==REGION
        key=(service,region)
        if key not in self.clients:
            self.clients[key]=session.client(service,region_name=region)
        return self.clients[key]
    def call(self,session,service,region,operation,**kw):
        profile=kw.pop('_metadata_profile')
        assert profile==build.PROFILE
        return build.profile_call(self,session,service,region,operation,**kw)

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):raise AssertionError('network forbidden')
    monkeypatch.setattr(socket.socket,'connect',blocked)
    monkeypatch.setattr(socket,'getaddrinfo',blocked)
    def detector(data,path,timeout):
        return [(TOKEN,'github-pat',1)] if TOKEN.encode() in data else []
    monkeypatch.setattr(scanning,'_scan_kingfisher',detector)
    monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()

def execute(payload=b'mode=ready',fault=None,disabled=False):
    t=target()
    options={'content_secret_scans':not disabled,'_content_secret_scan_kinds':[build.KIND],build.OPTION:[t]}
    session=boto3.Session(aws_access_key_id='offline',aws_secret_access_key='offline',region_name=REGION)
    requests=Requests(options,session)
    requests.cancel_after_repository=fault=='cancelled'
    if disabled:
        read=build.collect_selected(requests,session,REGION,{'Account':ACCOUNT},options,[SCOPE])
        assert requests.calls==0 and not requests.clients
        return read.status,None,None,requests
    cb=requests.client(session,'codebuild',REGION)
    cc=requests.client(session,'codecommit',REGION)
    cb_before=build_row(repo='ForeignRepo' if fault=='foreign_repo' else 'AuditRepo',
        commit='c'*40 if fault=='foreign_commit' else COMMIT)
    cb_after=build_row(commit='d'*40 if fault=='build_drift' else COMMIT)
    cc_before=repository(arn=REPO.replace(ACCOUNT,'999999999999') if fault=='foreign_account' else REPO)
    if fault=='bad_repo_status':cc_before['ResponseMetadata']['HTTPStatusCode']=500
    cc_after=repository(rid='33333333-2222-3333-4444-555555555555' if fault=='repo_drift' else '11111111-2222-3333-4444-555555555555')
    first=file_row(payload,path='/foreign.txt' if fault=='foreign_path' else '/source/config.txt',
        commit='e'*40 if fault=='foreign_file_commit' else COMMIT)
    if fault=='missing_file_request_id':first['ResponseMetadata'].pop('RequestId')
    second=file_row(payload,blob='c'*40 if fault=='blob_drift' else BLOB)
    if fault=='missing_after_request_id':second['ResponseMetadata'].pop('RequestId')
    with Stubber(cb) as b, Stubber(cc) as c:
        args={'ids':[BUILD.split(':build/',1)[1]]}
        if fault=='denied':
            b.add_client_error('batch_get_builds',service_error_code='AccessDeniedException',http_status_code=403,expected_params=args)
        else:
            b.add_response('batch_get_builds',cb_before,args)
            if fault not in ('foreign_repo','foreign_commit'):
                repo_args={'repositoryName':'AuditRepo'}
                file_args={'repositoryName':'AuditRepo','commitSpecifier':COMMIT,'filePath':'/source/config.txt'}
                c.add_response('get_repository',cc_before,repo_args)
                if fault=='codecommit_denied':
                    c.add_client_error('get_file',service_error_code='AccessDeniedException',
                        http_status_code=403,expected_params=file_args)
                elif fault not in ('foreign_account','cancelled'):
                    c.add_response('get_file',first,file_args)
                    if fault not in ('foreign_path','foreign_file_commit'):
                        c.add_response('get_repository',cc_after,repo_args)
                        c.add_response('get_file',second,file_args)
            if fault not in ('foreign_repo','foreign_commit','denied'):
                b.add_response('batch_get_builds',cb_after,args)
        read=build.collect_selected(requests,session,REGION,{'Account':ACCOUNT},options,[SCOPE])
    item=read.items[0]
    metadata=dict(requests.build_deployment_metadata)
    index={'context':{'provider':'aws','scope':SCOPE,'metadata':metadata},'collections':{
        build.KIND:[{'scope':SCOPE,'service':'codebuild','status':'collected','items':[item]}]}}
    status,evidence=check.evaluate(item,index)
    assert TOKEN not in json.dumps((item,evidence,metadata),default=str)
    return status,evidence,item,requests

def test_positive_and_clean():
    for payload,status in ((TOKEN.encode(),'FAIL'),(b'mode=ready','PASS')):
        got,evidence,item,requests=execute(payload)
        assert got==status,(got,evidence,item)
        assert requests.build_deployment_calls[build.identity(target())]==2
        if status=='FAIL':
            assert len(evidence['secret_leaks'])==1
            assert len(evidence['secret_leaks'][0]['detectors'])==2

@pytest.mark.parametrize('fault',['foreign_repo','foreign_commit','foreign_account','foreign_path',
    'foreign_file_commit','repo_drift','blob_drift','build_drift','denied','codecommit_denied',
    'bad_repo_status','missing_file_request_id','missing_after_request_id'])
def test_foreign_drift_denied(fault):
    got,evidence,item,_=execute(fault=fault)
    assert got=='UNKNOWN',(fault,got,evidence,item)

def test_positive_retained_after_drift():
    got,evidence,item,_=execute(TOKEN.encode(),fault='build_drift')
    assert got=='FAIL' and evidence['complete'] is False
    assert item[build.MARKER]['association_coherent'] is False
    got,evidence,item,_=execute(TOKEN.encode(),fault='missing_after_request_id')
    assert got=='FAIL' and evidence['complete'] is False
    assert item[build.MARKER]['association_coherent'] is False

def test_cancelled_is_propagated():
    with pytest.raises(ReadFailure) as caught:execute(fault='cancelled')
    assert caught.value.code=='collection_cancelled'

def test_private_alias_only_after_stable_binding(monkeypatch):
    calls=[]
    monkeypatch.setattr(build,'reuse_image_layer',lambda leaks,**source:calls.append((leaks,source)))
    assert execute(TOKEN.encode())[0]=='FAIL'
    assert len(calls)==1 and calls[0][1]['resource_id']==build.identity(target())
    calls.clear()
    assert execute(TOKEN.encode(),fault='build_drift')[0]=='FAIL'
    assert calls==[]

def test_truncated_negative_is_unknown():
    got,evidence,item,_=execute(b'x'*1048577)
    assert got=='UNKNOWN' and item[build.MARKER]['codecommit_item']['complete'] is False

def test_selector_and_default_off():
    t=target()
    for change in ({'file_path':'/../foreign.txt'},{'repository_arn':REPO.replace(ACCOUNT,'999999999999')},
                   {'commit_id':'main'},{'build_arn':BUILD.replace(ACCOUNT,'999999999999')}):
        bad={**t,**change}
        with pytest.raises(ValueError):
            build.selected_targets({'content_secret_scans':True,'_content_secret_scan_kinds':[build.KIND],
                build.OPTION:[bad]},[SCOPE])
    status,_,_,_=execute(disabled=True)
    assert status=='not_collected'

def test_existing_s3_profile_selection_and_native_binding():
    t={'profile':'codebuild_s3_source','scope':SCOPE,
       'project_arn':f'arn:aws:codebuild:{REGION}:{ACCOUNT}:project/AuditProject',
       'source_s3_uri':'s3://selected-source-bucket/jobs/source.zip'}
    options={'content_secret_scans':True,'_content_secret_scan_kinds':[build.KIND],
        build.OPTION:[t],s3.OPTION:[build.source_target(t)]}
    assert build.selected_targets(options,[SCOPE])==[t]
    row={'projects':[{'arn':t['project_arn'],'name':'AuditProject','lastModified':NOW,
        'source':{'type':'S3','location':'selected-source-bucket/jobs/source.zip'}}],
        'ResponseMetadata':dict(META)}
    assert build.association(row,t)['associated'] is True
