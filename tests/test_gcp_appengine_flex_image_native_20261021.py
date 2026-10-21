"""Offline Version FULL GET -> OCI bytes -> normal consumer tests."""
import hashlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import threading
from types import SimpleNamespace, ModuleType
from copy import deepcopy
import pytest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT
from peaso import gcp_appengine_flex_image_selection_20261021 as selection
from peaso.collectors import gcp_appengine_flex_image_native_20261021 as source
from peaso.collectors import gcp_appengine_flex_image_runtime_20261021 as runtime
from peaso.checks import gcp_appengine_flex_image_review_20261021 as review
from peaso import secret_scanning

SCOPE='projects/example-project'
VERSION='apps/example-project/services/default/versions/v1'
REPO=SCOPE+'/locations/europe-west1/repositories/example-repo'

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def denied(*args,**kwargs):raise AssertionError('network forbidden in native fixture')
    monkeypatch.setattr(socket,'create_connection',denied)
    monkeypatch.setattr(socket.socket,'connect',denied)

def sha(raw): return 'sha256:'+hashlib.sha256(raw).hexdigest()


def fixture(secret=False, extra=False, config_secret=False):
    payload=b'TESTSECRET' if secret else b'ordinary harmless bytes'
    def layer(data,name):
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w') as archive:
            item=tarfile.TarInfo(name);item.size=len(data);archive.addfile(item,io.BytesIO(data))
        return buffer.getvalue()
    layers=[layer(payload,'app/config.txt')]
    if extra:layers.append(layer(b'other','app/other.txt'))
    config=json.dumps({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':[sha(x) for x in layers]},
        **({'config':{'Env':['KEY=TESTSECRET']}} if config_secret else {})},separators=(',',':')).encode()
    manifest=json.dumps({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json',
        'config':{'mediaType':'application/vnd.oci.image.config.v1+json','size':len(config),'digest':sha(config)},
        'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar','size':len(x),'digest':sha(x)} for x in layers]},separators=(',',':')).encode()
    reference='europe-west1-docker.pkg.dev/example-project/example-repo/example-image@'+sha(manifest)
    target={'version_name':VERSION,'immutable_reference':reference}
    uri,_,_,image_name=source.image.parse_image_uri(reference)
    bodies=[{'name':'projects/123456789','projectId':'example-project','state':'ACTIVE'},
        {'name':REPO,'format':'DOCKER','mode':'STANDARD_REPOSITORY'},
        {'name':REPO+'/dockerImages/'+image_name,'uri':reference,'mediaType':'application/vnd.oci.image.manifest.v1+json'}]
    version={'name':VERSION,'id':'v1','env':'flex','createTime':'2026-10-21T10:00:00Z',
             'deployment':{'container':{'image':reference}}}
    blobs={sha(manifest):manifest,sha(config):config,**{sha(x):x for x in layers}}
    return target,version,bodies,blobs


class Response:
    def __init__(self,url,payload,status=200,foreign=False,truncated=False):
        self.url='https://foreign.invalid/steal' if foreign else url
        self.status_code=status;self.history=[];self.payload=payload;self.closed=False
        self.headers={'Content-Length':str(len(payload)+(1 if truncated else 0))}
    def iter_content(self,chunk_size):
        for start in range(0,len(self.payload),chunk_size):yield self.payload[start:start+chunk_size]
    def close(self):self.closed=True


class Session:
    def __init__(self,target,bodies,blobs,*,denied=None,foreign=None,truncated=None,drift=None):
        self.routes={url:json.dumps(body,separators=(',',':')).encode()
                     for (url,_),body in zip(source.requests_for(target,SCOPE),bodies)}
        self.blobs=blobs;self.calls=[];self.responses=[];self.closed=False
        self.denied=denied;self.foreign=foreign;self.truncated=truncated;self.drift=drift
        self.cookies=SimpleNamespace(clear=lambda:None)
    def request(self,method,url,**kwargs):
        assert method=='GET' and kwargs['allow_redirects'] is False and kwargs['stream'] is True
        assert kwargs['headers']['Authorization'].startswith(('Bearer ','Basic '))
        self.calls.append(url)
        if 'params' in kwargs:
            import requests
            expected=requests.Request('GET',url,params=kwargs['params']).prepare().url
            payload=self.routes[url]
            if self.drift and len(self.calls)>3 and self.drift in url:
                changed=json.loads(payload);changed['updateTime']='2026-10-21T15:00:00Z';payload=json.dumps(changed).encode()
        else:
            expected=url;payload=self.blobs[url.rsplit('/',1)[-1]]
        r=Response(expected,payload,403 if self.denied and self.denied in url else 200,
                   bool(self.foreign and self.foreign in url),bool(self.truncated and self.truncated in url))
        self.responses.append(r);return r
    def close(self):self.closed=True


class Transport:
    def __init__(self,cancel=False):
        self.lock=threading.RLock();self.calls=0;self.max_calls=64;self.timeout=10;self.evidence=[]
        self.credentials=SimpleNamespace(headers=lambda:{'Authorization':'Bearer synthetic-offline-token'})
        self.cancel=cancel
    def check_cancelled(self):
        if self.cancel:raise RuntimeError('cancelled')


def fake_engine(payload,path,timeout):
    return [('TESTSECRET','offline',1)] if b'TESTSECRET' in payload else []


def collect_case(monkeypatch,secret=False,*,version_change=None,owner_change=None,version_denied=False,extra=False,config_secret=False,**faults):
    monkeypatch.setattr(secret_scanning,'_scan_kingfisher',fake_engine)
    monkeypatch.setattr(secret_scanning,'_scan_trufflehog',fake_engine)
    target,version,bodies,blobs=fixture(secret,extra,config_secret)
    if owner_change:owner_change(bodies)
    meta=Session(target,bodies,blobs,**faults);oci=Session(target,bodies,blobs,**faults)
    transport=Transport();version_calls=[]
    def version_get(_):
        transport.check_cancelled();version_calls.append(1)
        if version_denied:
            raise ValueError('version denied')
        raw=deepcopy(version)
        if version_change and len(version_calls)==2:version_change(raw)
        rid='request-'+str(len(transport.evidence)+1)
        transport.evidence.append({'id':rid,'method':'GET','scope':SCOPE,
            'url':'https://appengine.googleapis.com/v1/'+VERSION,
            'query':{'view':'FULL','fields':source.VERSION_FIELDS},
            'operation':'appengine_flex_selected_version_get','status':'collected','http_status':200})
        return raw,rid
    result=source.collect_native(transport,scope=SCOPE,selectors=[target],enabled=True,
        version_get=version_get,metadata_session=meta,image_session=oci)
    assert meta.closed and oci.closed and all(r.closed for r in meta.responses+oci.responses)
    assert 'synthetic-offline-token' not in repr(result) and 'TESTSECRET' not in repr(result)
    return result,transport,meta,oci


def item_index(result,transport,kind=selection.SECRET_KIND):
    row=result['rows'][0];target=row['selection'];rid=source.identity(target)
    item={'name':rid,'native_id':rid,'_resource_id':rid,
          runtime.MARKER:{'scope':SCOPE,'row':row,'runtime_image_proven':False},
          '_provenance':{'scope':SCOPE,'source_requests':row['source_requests']}}
    collection={'scope':SCOPE,'status':'collected','coverage_status':'collected' if row['complete'] else 'partial',
                'items':[item],'source_requests':row['source_requests']}
    index={'context':{'provider':'gcp','scope':SCOPE,'metadata':{
        selection.OPTION:[target],kind+'_authorized':True,'source_requests':transport.evidence}},
        'collections':{kind:[collection]}}
    return item,index


def test_native_secret_hit_and_clean(monkeypatch):
    for hit,expected in ((True,'FAIL'),(False,'PASS')):
        result,transport,meta,oci=collect_case(monkeypatch,secret=hit)
        assert result['status']==expected
        item,index=item_index(result,transport)
        status,evidence=review.evaluate(item,index,selection.SECRET_KIND)
        assert status==expected,evidence
        assert len(meta.calls)==6 and len(oci.calls)==3
        if hit:
            leaks=evidence['secret_leaks'];assert len(leaks)==1
            assert {d['engine'] for d in leaks[0]['detectors']}=={'kingfisher','trufflehog'}
            assert len(leaks[0]['fingerprint'])==64


def test_binding_drift_denied_redirect_truncated(monkeypatch):
    cases=[{'version_change':lambda v:v['deployment']['container'].update(image='other@sha256:'+'a'*64)},
        {'version_change':lambda v:v.update(createTime='2026-10-21T11:00:00Z')},
        {'owner_change':lambda b:b[0].update(projectId='foreign-project')},
        {'owner_change':lambda b:b[1].update(name='projects/foreign/locations/europe-west1/repositories/other')},
        {'owner_change':lambda b:b[2].update(uri='foreign@sha256:'+'a'*64)},
        {'drift':'/dockerImages/'},{'denied':'/repositories/'},{'foreign':'/dockerImages/'},
        {'truncated':'/blobs/'},{'version_denied':True}]
    for changes in cases:
        result,transport,meta,oci=collect_case(monkeypatch,**changes)
        assert review.evaluate(*item_index(result,transport),selection.SECRET_KIND)[0]=='UNKNOWN',changes


def test_partial_secret_positive_survives_later_layer_truncation(monkeypatch):
    target,version,bodies,blobs=fixture(True,True,True)
    manifest=json.loads(blobs[target['immutable_reference'].rsplit('@',1)[1]])
    second=manifest['layers'][1]['digest']
    result,transport,_,_=collect_case(monkeypatch,secret=True,extra=True,config_secret=True,truncated='/blobs/'+second)
    assert result['status']=='FAIL' and not result['complete']
    status,evidence=review.evaluate(*item_index(result,transport),selection.SECRET_KIND)
    assert status=='FAIL',evidence


def test_preflight_defaultoff_cancel(monkeypatch):
    target,version,bodies,blobs=fixture()
    transport=Transport()
    assert source.collect_native(transport,scope=SCOPE,selectors=[target],enabled=False,
        version_get=lambda _: (_ for _ in ()).throw(AssertionError('I/O')))['status']=='UNKNOWN'
    assert transport.calls==0 and transport.evidence==[]
    for changed in ({**target,'version_name':'apps/foreign-project/services/default/versions/v1'},
                    {**target,'immutable_reference':target['immutable_reference'].replace('example-project','foreign-project')},
                    {**target,'immutable_reference':target['immutable_reference'].split('@')[0]+':latest'}):
        try:selection.selected({selection.OPTION:[changed]},[SCOPE])
        except ValueError:pass
        else:raise AssertionError(changed)
    meta=Session(target,bodies,blobs);oci=Session(target,bodies,blobs)
    cancelled=Transport(cancel=True)
    result=source.collect_native(cancelled,scope=SCOPE,selectors=[target],enabled=True,
        version_get=lambda _:cancelled.check_cancelled(),metadata_session=meta,image_session=oci)
    assert result['status']=='UNKNOWN' and not meta.calls and not oci.calls


def collect_vuln_case(mode):
    from peaso.collectors import gcp_registry_trivy_20261021 as trivy_source
    from peaso.checks import gcp_registry_trivy_review_20261021 as trivy_review
    target,version,bodies,blobs=fixture()
    transport=Transport();meta=Session(target,bodies,blobs);oci=Session(target,bodies,blobs)
    def version_get(_):
        rid='request-'+str(len(transport.evidence)+1)
        transport.evidence.append({'id':rid,'method':'GET','scope':SCOPE,
            'url':'https://appengine.googleapis.com/v1/'+VERSION,
            'query':{'view':'FULL','fields':source.VERSION_FIELDS},
            'operation':'appengine_flex_selected_version_get','status':'collected','http_status':200})
        return deepcopy(version),rid
    def runner(identity,manifest,config,layers,**kwargs):
        assert kwargs['native_verifier']()==identity
        findings=[] if mode=='clean' else [{
            'vulnerability_id':'CVE-2026-12345','severity':'HIGH','package_types':['alpine'],
            'package':'fixture-package','version':'1.0','fixed_in':['1.1'],'fix_status':'fixed',
            'classes':['os-pkgs'],'image_digest':identity['manifest_digest']}]
        return {'image':identity,'status':'PASS' if not findings else 'FAIL',
            'complete':not findings,'scan_complete':not findings,
            'coverage_status':'COMPLETE' if not findings else 'UNKNOWN',
            'database':{'fresh':not findings},'findings':findings}
    def trivy_collect(reference,scope):
        trivy_meta=Session(target,bodies,blobs);trivy_image=Session(target,bodies,blobs)
        result=trivy_source.collect_native(transport,scope=scope,selectors=[reference],enabled=True,
            metadata_session=trivy_meta,image_session=trivy_image,runner=runner)
        assert trivy_meta.closed and trivy_image.closed
        row=result['rows'][0]
        record=trivy_review.project(reference,scope,row['scan']) if type(row['scan']) is dict else None
        status,_=trivy_review.evaluate(record,{'scope':scope,'selections':[reference],
            'source_requests':result['source_requests']}) if record else ('UNKNOWN',{})
        return {'status':status,'complete':row['complete'] is True and status!='UNKNOWN',
            'record':record,'source_requests':row['source_requests'],
            'source_ledger':result['source_requests']}
    result=source.collect_native(transport,scope=SCOPE,selectors=[target],enabled=True,
        version_get=version_get,secret_enabled=False,vuln_enabled=True,
        metadata_session=meta,image_session=oci,trivy_collect=trivy_collect)
    assert meta.closed and oci.closed
    return result,transport


def test_optional_trivy_typed_clean_and_partial_high():
    for mode,expected in (('clean','PASS'),('positive','FAIL')):
        result,transport=collect_vuln_case(mode)
        assert result['status']==expected,result
        item,index=item_index(result,transport,selection.VULN_KIND)
        status,evidence=review.evaluate(item,index,selection.VULN_KIND)
        assert status==expected,evidence
        if mode=='positive':assert not result['complete'] and evidence['vulnerabilities'][0]['severity']=='HIGH'


def test_production_collector_route_to_consumer(monkeypatch):
    monkeypatch.setattr(secret_scanning,'_scan_kingfisher',fake_engine)
    monkeypatch.setattr(secret_scanning,'_scan_trufflehog',fake_engine)
    target,version,bodies,blobs=fixture(True)
    meta=Session(target,bodies,blobs);oci=Session(target,bodies,blobs)
    queue=iter((meta,oci))
    monkeypatch.setattr(source,'_session',lambda:next(queue))
    transport=Transport()
    from peaso.collectors.gcp import GCPCollector
    class Collector:
        remember_selected_image_matches = GCPCollector.remember_selected_image_matches
        options={selection.OPTION:[target],selection.ENABLE_SECRET:True,
                 '_appengine_flex_image_named_checks':[selection.SECRET_CHECK]}
        requested_scopes=[SCOPE];needed={selection.SECRET_KIND}
        max_items=4;total_items=0;collections={};read_time='2026-10-21T10:00:00Z'
        def __init__(self):self.transport=transport
        def read(self,url,scope,params,operation):
            assert url=='https://appengine.googleapis.com/v1/'+VERSION and scope==SCOPE
            assert params=={'view':'FULL','fields':source.VERSION_FIELDS}
            rid='request-'+str(len(self.transport.evidence)+1)
            self.transport.evidence.append({'id':rid,'method':'GET','scope':scope,'url':url,
                'query':params,'operation':operation,'status':'collected','http_status':200})
            return deepcopy(version),rid
    collector=Collector()
    runtime.collect(collector)
    collection=collector.collections[(selection.SECRET_KIND,SCOPE)]
    assert collection['coverage_status']=='collected' and collector.total_items==1
    item=collection['items'][0]
    index={'context':{'provider':'gcp','scope':SCOPE,'metadata':{
        **collector.appengine_flex_image_metadata,'source_requests':transport.evidence}},
        'collections':{selection.SECRET_KIND:[collection]}}
    assert review.evaluate(item,index,selection.SECRET_KIND)[0]=='FAIL'
    assert meta.closed and oci.closed


def test_module_origins():
    assert Path(source.__file__).resolve()==(HERE/'peaso/collectors/gcp_appengine_flex_image_native_20261021.py').resolve()
    from peaso.collectors import gcp_image_stream_reader_20261021 as reader
    assert Path(reader.__file__).resolve()==(ROOT/'peaso/collectors/gcp_image_stream_reader_20261021.py').resolve()


def test_pure_api_selector_import_has_no_collector_dependency():
    selector=HERE/'peaso/gcp_appengine_flex_image_selection_20261021.py'
    code=f'''import importlib.abc,importlib.util,sys
class Block(importlib.abc.MetaPathFinder):
 def find_spec(self,name,*args):
  if name.startswith('peaso.collectors') or name.startswith('peaso.checks'):
   raise RuntimeError('forbidden API import:'+name)
sys.meta_path.insert(0,Block())
s=importlib.util.spec_from_file_location('selected_flex',{str(selector)!r})
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
assert m.selected({{}},['projects/example-project'],[])==[]
assert not any(k.startswith('peaso.collectors') or k.startswith('peaso.checks') for k in sys.modules)
'''
    run=subprocess.run([sys.executable,'-I','-c',code],capture_output=True,text=True,timeout=10)
    assert run.returncode==0,run.stderr
