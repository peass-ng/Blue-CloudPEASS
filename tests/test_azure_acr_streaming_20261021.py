"""Offline contract tests for the isolated ACR streaming proposal."""
import base64
import json
import os
import hashlib
import time
import pytest

@pytest.fixture
def proposal():
    from peaso.collectors import azure_acr_image_secret_indicators as source
    from peaso.checks import azure_acr_image_secret_review_20261020 as checks
    return source, checks


def test_pinned_shared_blob_redirect_has_no_bearer_or_persisted_sas(monkeypatch):
    from peaso.collectors import azure_acr_image_secret_indicators as source
    from peaso.collectors import azure_acr_image_stream_inspection_20261021 as stream
    payload=b'bounded image blob'
    digest='sha256:'+hashlib.sha256(payload).hexdigest()
    host='specificacct.blob.core.windows.net'
    signed='https://'+host+'/acr/blob/data?sig=ephemeral'
    sent=[]
    class Response:
        def __init__(self,status,body=b'',headers=None):
            self.status=status;self.body=body;self.headers=headers or {};self.cursor=0
        def getheader(self,key):return self.headers.get(key)
        def read(self,n):
            block=self.body[self.cursor:self.cursor+n];self.cursor+=len(block);return block
        def close(self):pass
    class Connection:
        sock=None
        def __init__(self,host,timeout):self.host=host
        def set_debuglevel(self,level):assert level==0
        def request(self,method,route,body=None,headers=None):
            sent.append((self.host,route,dict(headers)))
            if self.host=='reviewregistry.azurecr.io':
                self.response=Response(307,headers={'Location':signed})
            else:
                assert self.host==host and route=='/acr/blob/data?sig=ephemeral'
                assert 'Authorization' not in headers and 'Cookie' not in headers
                self.response=Response(200,payload,{'Content-Length':str(len(payload))})
        def getresponse(self):return self.response
        def close(self):pass
    monkeypatch.setattr(stream.http.client,'HTTPSConnection',Connection)
    monkeypatch.setattr(stream,'_PublicPinnedHTTPSConnection',Connection)
    class Outer:
        def check_cancelled(self):pass
        def call(self,fn,*args,**kwargs):return fn(*args,**kwargs)
    target={'registry_id':'/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/review/providers/Microsoft.ContainerRegistry/registries/reviewregistry',
            'repository':'review','digest':digest}
    receipts=[];reader=source.Reader(Outer(),None,receipts,'/subscriptions/00000000-0000-0000-0000-000000000000',target,
                                     {'deadline':time.monotonic()+20,'calls':0,'bytes':0})
    reader.host='reviewregistry.azurecr.io';reader.data_hosts=[]
    stream.enable_pinned_shared_data(reader)
    assert reader.blob('blobs',digest,len(payload), 'registry-token',len(payload))==payload
    assert [r['endpoint'] for r in receipts]==['registry','native_pinned_shared_data']
    assert [r['status'] for r in receipts]==['redirect','collected']
    assert len(sent)==2 and sent[0][2]['Authorization']=='Bearer registry-token'
    assert 'sig=ephemeral' not in repr(receipts)


def test_shared_location_and_dns_reject_nonpublic_destinations(monkeypatch):
    from peaso.collectors import azure_acr_image_secret_indicators as source
    from peaso.collectors import azure_acr_image_stream_inspection_20261021 as stream
    valid='https://specificacct.blob.core.windows.net/acr/blob/data?sig=opaque'
    assert stream._shared_location(valid)[0]=='specificacct.blob.core.windows.net'
    assert stream._shared_location('https://specificacct.blob.core.windows.net/acr//blob/data?sig=opaque')[0]=='specificacct.blob.core.windows.net'
    for bad in ('http://specificacct.blob.core.windows.net/acr/blob/data?sig=x',
                'https://169.254.169.254/latest?sig=x',
                'https://specificacct.blob.core.windows.net.evil.invalid/acr/blob/data?sig=x',
                'https://user@specificacct.blob.core.windows.net/acr/blob/data?sig=x',
                'https://specificacct.blob.core.windows.net:444/acr/blob/data?sig=x',
                'https://specificacct.blob.core.windows.net//acr/blob/data?sig=x',
                'https://specificacct.blob.core.windows.net/acr/../blob/data?sig=x'):
        with pytest.raises(source.Incomplete):stream._shared_location(bad)
    monkeypatch.setattr(stream.socket,'getaddrinfo',lambda *a,**k:[(2,1,6,'',('127.0.0.1',443))])
    connection=stream._PublicPinnedHTTPSConnection('specificacct.blob.core.windows.net',timeout=1)
    with pytest.raises(source.Incomplete):connection.connect()


def test_raw_and_gzip_layers_above_old_cap(proposal,monkeypatch):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    source,checks=proposal
    for compressed in (False,True):
        payload=existing.TOKEN.encode()+b'\n'+(base64.b64encode(os.urandom(9*1024*1024)) if compressed else b'x'*(9*1024*1024))
        img=existing.image(files=[('application/config.txt',payload)],compressed=compressed)
        assert len(img.wire)>8*1024*1024
        snapshot,_=existing.capture(monkeypatch,img=img)
        assert checks.evaluate(*existing.index_of(snapshot))[0]=='FAIL'
        exported=json.dumps(snapshot)
        assert existing.TOKEN not in exported and 'application/config.txt' not in exported


def test_later_denial_retains_verified_positive(proposal,monkeypatch):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    source,checks=proposal
    img=existing.image(positive='manifest')
    snapshot,_=existing.capture(monkeypatch,img=img,overrides={'layer_blob':existing.Response(b'',403)})
    assert checks.evaluate(*existing.index_of(snapshot))[0]=='FAIL'


def test_repeated_immutable_layer_is_inspected_in_manifest_order(proposal,monkeypatch):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    source,checks=proposal
    img=existing.image()
    img.manifest['layers'].append(dict(img.manifest['layers'][0]))
    img.config['rootfs']['diff_ids'].append(source._sha(img.layer))
    img.config_raw=existing.packed(img.config)
    img.manifest['config']['digest']=source._sha(img.config_raw)
    img.manifest['config']['size']=len(img.config_raw)
    img.manifest_raw=existing.packed(img.manifest)
    img.target['digest']=source._sha(img.manifest_raw)
    snapshot,_=existing.capture(monkeypatch,img=img)
    item=next(c for c in snapshot['collections'] if c['type']==source.KIND)['items'][0]
    marker=item[source.MARKER]
    assert marker['complete'] is True
    assert len(marker['layers_scanned'])==2
    assert checks.evaluate(*existing.index_of(snapshot))[0]=='PASS'


def test_repeated_digest_with_conflicting_descriptor_is_rejected():
    from peaso.collectors.azure_acr_image_stream_inspection_20261021 import consistent_descriptors,complete_blob_receipts
    first={'digest':'sha256:'+'a'*64,'size':128,'mediaType':'application/vnd.oci.image.layer.v1.tar'}
    assert consistent_descriptors([first,dict(first)]) is True
    assert consistent_descriptors([first,{**first,'size':129}]) is False
    assert consistent_descriptors([first,{**first,'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip'}]) is False
    receipt={'operation':'blob','status':'collected','http_status':200,'verified':True,'bound':True,
        'digest':first['digest'],'bytes':first['size']}
    assert complete_blob_receipts([receipt],[[first,dict(first)]]) is False
    assert complete_blob_receipts([receipt,dict(receipt)],[[first,dict(first)]]) is True
    assert complete_blob_receipts([receipt,{**receipt,'status':'unavailable'}],[[first,dict(first)]]) is False

@pytest.mark.parametrize('failure',['wrong_digest','truncated','rootfs','denied','disk'])
def test_incomplete_layer_is_unknown_and_cleans_scratch(proposal,monkeypatch,tmp_path,failure):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    import peaso.collectors.azure_acr_image_stream_inspection_20261021 as inspection
    source,checks=proposal
    img=existing.image()
    overrides={}
    if failure=='wrong_digest':
        overrides['layer_blob']=existing.Response(img.wire[:-1]+b'X')
    elif failure=='truncated':
        overrides['layer_blob']=existing.Response(img.wire[:-1])
    elif failure=='rootfs':
        img.config['rootfs']['diff_ids']=[source._sha(b'wrong')]
        img.config_raw=existing.packed(img.config)
        img.manifest['config']['digest']=source._sha(img.config_raw)
        img.manifest['config']['size']=len(img.config_raw)
        img.manifest_raw=existing.packed(img.manifest)
        img.target['digest']=source._sha(img.manifest_raw)
    elif failure=='denied':
        overrides['layer_blob']=existing.Response(b'',403)
    elif failure=='disk':
        monkeypatch.setattr(source.shutil,'disk_usage',lambda path: type('Usage',(),{'free':0})())
    original=inspection.tempfile.TemporaryDirectory
    def owned(*args,**kwargs):
        return original(*args,dir=tmp_path,**kwargs)
    monkeypatch.setattr(inspection.tempfile,'TemporaryDirectory',owned)
    snapshot,_=existing.capture(monkeypatch,img=img,overrides=overrides)
    assert checks.evaluate(*existing.index_of(snapshot))[0]=='UNKNOWN'
    assert list(tmp_path.iterdir())==[]


def test_installed_offline_engines_detect_verified_layer(proposal,monkeypatch):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    source,checks=proposal
    snapshot,_=existing.capture(monkeypatch,img=existing.image(positive='layer'),real=True)
    status,evidence=checks.evaluate(*existing.index_of(snapshot))
    assert status=='FAIL'
    assert {detector['engine'] for detector in evidence['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}

def test_first_verified_layer_positive_survives_second_unavailable(proposal,monkeypatch):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    source,checks=proposal
    img=existing.image(positive='layer')
    second=existing.image(files=[('another.txt',b'ordinary second layer')])
    img.manifest['layers'].append(second.manifest['layers'][0])
    img.config['rootfs']['diff_ids'].append(source._sha(second.layer))
    img.config_raw=existing.packed(img.config)
    img.manifest['config']['digest']=source._sha(img.config_raw)
    img.manifest['config']['size']=len(img.config_raw)
    img.manifest_raw=existing.packed(img.manifest)
    img.target['digest']=source._sha(img.manifest_raw)
    calls=0
    def layer_response():
        nonlocal calls
        calls+=1
        return existing.Response(img.wire if calls==1 else b'',200 if calls==1 else 403)
    snapshot,_=existing.capture(monkeypatch,img=img,overrides={'layer_blob':layer_response})
    status,evidence=checks.evaluate(*existing.index_of(snapshot))
    assert status=='FAIL' and evidence['complete'] is False
    assert calls==1

@pytest.mark.parametrize('positive,expected',[(None,'UNKNOWN'),('manifest','FAIL')])
def test_nested_archive_cannot_produce_clean_result(proposal,monkeypatch,positive,expected):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    import gzip
    source,checks=proposal
    img=existing.image(positive=positive,files=[('bundled.gz',gzip.compress(b'ordinary nested bytes'))])
    snapshot,_=existing.capture(monkeypatch,img=img)
    assert checks.evaluate(*existing.index_of(snapshot))[0]==expected
