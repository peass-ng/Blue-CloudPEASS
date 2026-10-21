import importlib
import importlib.util
import io
from copy import deepcopy
from pathlib import Path
import sys
import zipfile
import pytest

ROOT=Path(__file__).resolve().parents[1]
HERE=ROOT
from peaso import secret_evidence as evidence, secret_scanning as scanning

def helper(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module

@pytest.mark.parametrize('kind',('workload','build'))
def test_actual_reference_private_detail(kind,monkeypatch):
    import botocore.response
    def blocked(*args,**kwargs):raise AssertionError('network forbidden')
    import socket
    monkeypatch.setattr(socket.socket,'connect',blocked)
    monkeypatch.setattr(socket,'getaddrinfo',blocked)
    monkeypatch.setattr(botocore.response,'set_socket_timeout',lambda raw,seconds:None)
    source=ROOT/'tests'/('test_sagemaker_training_script_source.py' if kind=='workload' else 'test_aws_build_deployment_referenced_source_20261021.py')
    h=helper(Path(source),'reference_candidate_'+kind)
    token=h.TOKEN
    def detector(data,path,timeout):return [(token,'github-pat',1)] if token.encode() in data else []
    monkeypatch.setattr(scanning,'_scan_kingfisher',detector)
    monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    scanning._RESULTS.clear()
    if kind=='workload':
        module=importlib.import_module('peaso.collectors.aws_workload_referenced_source_indicators')
        target=h.target();content=h.archive(token)
    else:
        module=importlib.import_module('peaso.collectors.aws_build_deployment_referenced_source_indicators')
        target=h.target('codebuild_s3_source');content=h.zipdata(token)
    cipher=evidence.EphemeralCipher()
    with evidence.capture(cipher,tenant='alice',scan_id='a'*32) as sink:
        # The same value in another object must not become a reference alias.
        with evidence.source_context(resource_id='s3://foreign-bucket/foreign.txt',scope=h.SCOPE,
                layer='selected-s3-source:foreign'):
            evidence.scan_with_source(scanning.scan_content,token.encode(),'foreign-public-path',
                source={'path':'foreign-native-path'},timeout=3)
        if kind=='workload':
            status,observed,item,requests,index=h.execute(content,capture=True)
        else:
            status,observed,item,requests,index=h.execute(target,content,capture=True)
        assert status=='FAIL'
        assert observed['secret_leaks']
        finding={'resource_id':item['id'],'native_resource_id':item['id'],'scope':h.SCOPE,
                 'check_id':module.CHECK,'finding_type':'secrets','status':status,'evidence':observed}
        document=sink.document()
    assert token not in repr((item,observed,document))
    detail=evidence.details(finding,document,cipher,tenant='alice',scan_id='a'*32)
    assert detail['status']=='available',detail
    assert any(m['value']==token for m in detail['matches'])
    assert all('selected-s3-source:' in loc.get('layer','') for m in detail['matches'] for loc in m['locations'])
    assert all(loc.get('path')!='foreign-native-path' for m in detail['matches'] for loc in m['locations'])
    foreign_scope=deepcopy(finding)
    foreign_scope['scope']='999999999999/eu-west-1'
    scoped=evidence.details(foreign_scope,document,cipher,tenant='alice',scan_id='a'*32)
    assert not any(m['value']==token for m in scoped.get('matches',()))
    foreign_asset=deepcopy(finding)
    foreign_asset['native_resource_id']='foreign-reference:unselected'
    foreign=evidence.details(foreign_asset,document,cipher,tenant='alice',scan_id='a'*32)
    assert not any(m['value']==token for m in foreign.get('matches',()))
