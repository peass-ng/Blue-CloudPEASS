"""Offline native ARM + Blob HTTP through bounded ZIP and dual detector adapters."""
import base64
from copy import deepcopy
import io,json,socket,time,zipfile
from pathlib import Path
from types import SimpleNamespace
from xml.sax.saxutils import escape
import pytest
from peaso import secret_scanning
from peaso.collectors import azure
from peaso.collectors import azure_flex_deployment_archives_20261021 as flex
from peaso.collectors import azure_selected_storage_secret_indicators as storage
from peaso.checks import azure_flex_deployment_archives_review_20261021 as check
from peaso.server import content_selection_preflight_20261021 as preflight

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222';PRINCIPAL='44444444-4444-4444-4444-444444444444'
SITE=SCOPE+'/resourceGroups/review/providers/Microsoft.Web/sites/selected-function'
ACCOUNT=SCOPE+'/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/sourceaccount'
HOST='sourceaccount.blob.core.windows.net';CONTAINER='packages';BLOB='release.zip'
TOKEN='ghp_abcdefghijklmnopqrstuvwxyz0123456789'

def target():return {'site_resource_id':SITE,'storage_account_resource_id':ACCOUNT,'container':CONTAINER}
def options(on=True):return {'content_secret_scans':on,'_content_secret_scan_kinds':[flex.KIND] if on else [],
    '_azure_flex_named_checks':[flex.CHECK] if on else [],flex.OPTION:[target()]}
def jwt(audience):
    claims={'aud':audience,'tid':TENANT,'oid':PRINCIPAL,'exp':time.time()+3600}
    return 'eyJhbGciOiJub25lIn0.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.b2ZmbGluZQ'
def zipdata(value,*,binary=False):
    raw=io.BytesIO()
    with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('main.py',value)
        if binary:z.writestr('image.png',b'\x00\x01\x02')
    return raw.getvalue()

def listing(entries,*,truncated=False):
    rows=''.join('<Blob><Name>'+escape(name)+'</Name><Properties><Etag>&quot;0x123ABC&quot;</Etag><Content-Length>'+str(len(data))+'</Content-Length><BlobType>BlockBlob</BlobType></Properties></Blob>' for name,data in entries)
    return ('<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://'+HOST+'/" ContainerName="'+CONTAINER+'"><Blobs>'+rows+'</Blobs><NextMarker>'+('more' if truncated else '')+'</NextMarker></EnumerationResults>').encode()

class Response:
    def __init__(self,payload,*,head=False,headers=None,status=200):
        raw=json.dumps(payload).encode() if isinstance(payload,dict) else payload
        self.status=status;self.stream=io.BytesIO(b'' if head else raw);self.closed=False
        self.headers={'Content-Type':'application/json','Content-Length':str(len(raw)),
            'x-ms-request-id':'11111111-1111-4111-8111-111111111111',**(headers or {})}
    def getheader(self,key):return self.headers.get(key)
    def read(self,size):return self.stream.read(size)
    def close(self):self.closed=True

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):raise AssertionError('network forbidden')
    monkeypatch.setattr(socket.socket,'connect',blocked)
    monkeypatch.setattr(socket,'getaddrinfo',blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)
    def detector(data,path,timeout):return [(TOKEN,'github-pat',1)] if TOKEN.encode() in data else []
    monkeypatch.setattr(secret_scanning,'_scan_kingfisher',detector)
    monkeypatch.setattr(secret_scanning,'_scan_trufflehog',detector)
    secret_scanning._RESULTS.clear();yield;secret_scanning._RESULTS.clear()

def run(monkeypatch,contents=None,*,fault=None,on=True,capture=False):
    if contents is None:contents=[(BLOB,zipdata('mode=ready'))]
    trace=SimpleNamespace(calls=[],responses=[],connections=[],audiences=[])
    class Transport:
        tenant=TENANT;verified_tenant=TENANT
        def token(self,audience):trace.audiences.append(audience);return jwt(audience)
        def request(self,*args,**kwargs):raise AssertionError('generic transport forbidden')
    class Connection:
        sock=None
        def __init__(self,origin,timeout):
            assert origin in ('management.azure.com',HOST) and 0<timeout<=10
            self.origin=origin;self.closed=False;trace.connections.append(self)
        def set_debuglevel(self,level):assert level==0
        def request(self,method,path,body=None,headers=None):
            assert method=='GET' or method=='HEAD'
            assert body is None and headers['Authorization'].startswith('Bearer ey')
            assert 'sig' not in path.lower() and TOKEN not in str(headers)
            if self.origin=='management.azure.com':
                if path==SCOPE+'?api-version='+storage.SUB_VERSION:
                    op='subscription';data={'id':SCOPE,'subscriptionId':SCOPE.rsplit('/',1)[1],'tenantId':TENANT,'state':'Enabled'}
                elif path==ACCOUNT+'?api-version='+storage.ARM_VERSION:
                    op='account';data={'id':ACCOUNT,'name':'sourceaccount','type':'Microsoft.Storage/storageAccounts',
                        'properties':{'provisioningState':'Succeeded','primaryEndpoints':{'blob':'https://'+HOST+'/'}}}
                    if fault=='account_drift' and sum(c[0]=='account' for c in trace.calls)>=2:data['properties']['provisioningState']='Updating'
                elif path==SITE+'?api-version='+flex.SITE_VERSION:
                    op='site';uri='https://'+HOST+'/'+CONTAINER
                    if fault=='foreign_container':uri='https://foreign.blob.core.windows.net/'+CONTAINER
                    if fault=='site_drift' and any(c[0]=='site' for c in trace.calls):uri='https://'+HOST+'/other'
                    data={'id':SITE,'type':'Microsoft.Web/sites','name':'selected-function','kind':'functionapp,linux',
                        'properties':{'reserved':True,'functionAppConfig':{'deployment':{'storage':{'type':'blobContainer','value':uri}}}}}
                else:raise AssertionError('unexpected ARM path: '+path)
                response=Response(data)
            else:
                if path=='/'+CONTAINER+'?restype=container&comp=list&maxresults=5':
                    op='list';rows=contents
                    if fault=='list_drift' and any(c[0]=='list' for c in trace.calls):rows=[('other.zip',zipdata('mode=ready'))]
                    response=Response(listing(rows,truncated=fault=='list_truncated'),headers={'Content-Type':'application/xml','x-ms-version':storage.DATA_VERSION})
                    if fault=='malformed':response=Response(b'<bad',headers={'Content-Type':'application/xml','x-ms-version':storage.DATA_VERSION})
                else:
                    name=path.split('/')[2].split('?',1)[0]
                    match=[data for key,data in contents if key==name]
                    assert len(match)==1,(name,path)
                    payload=match[0]
                    props={'Content-Type':'application/zip','ETag':'"0x123ABC"','x-ms-version':storage.DATA_VERSION,'x-ms-blob-type':'BlockBlob'}
                    op='head' if method=='HEAD' else 'content'
                    if fault=='etag_drift' and op=='head' and sum(c[0]=='head' for c in trace.calls)%2==1:props['ETag']='"0x999ABC"'
                    if method=='GET':assert headers['If-Match']=='"0x123ABC"'
                    response=Response(payload,head=method=='HEAD',headers=props)
                    if fault=='truncated' and op=='content':response.headers['Content-Length']=str(len(payload)+1)
            if fault=='denied' and op=='list':response.status=403
            if fault=='second_denied' and op=='head' and path.startswith('/'+CONTAINER+'/other.zip'):
                response.status=403
            trace.calls.append((op,self.origin,method,path));trace.responses.append(response);self.response=response
        def getresponse(self):return self.response
        def close(self):self.closed=True
    monkeypatch.setattr(flex.http.client,'HTTPSConnection',Connection)
    monkeypatch.setattr(storage.http.client,'HTTPSConnection',Connection)
    reader=azure._Reader({'retries':0})
    opts=options(on)
    if not on:
        flex.collect(reader,Transport(),[SCOPE],{flex.KIND},opts)
        assert not trace.calls and not trace.audiences
        return 'not_collected',None,None,trace,None
    flex.collect(reader,Transport(),[SCOPE],{flex.KIND},opts)
    row=reader.collections[0]['items'][0]
    meta={**reader.flex_archive_metadata,'tenant_id':TENANT,'tenant_verified':True}
    index={'context':{'provider':'azure','scope':SCOPE,'metadata':meta},'collections':{flex.KIND:[reader.collections[0]]}}
    status,evidence=check.evaluate(row,index)
    assert TOKEN not in json.dumps((row,evidence,meta),default=str)
    assert all(r.closed for r in trace.responses) and all(c.closed for c in trace.connections)
    return status,evidence,row,trace,index

def test_positive_and_clean(monkeypatch):
    for value,expected in ((TOKEN,'FAIL'),('mode=ready','PASS')):
        status,evidence,row,trace,_=run(monkeypatch,[(BLOB,zipdata(value))])
        assert status==expected,(status,evidence,row[flex.MARKER])
        assert len([c for c in trace.calls if c[0]=='head'])==2
        assert len([c for c in trace.calls if c[0]=='content'])==1
        assert len([c for c in trace.calls if c[0]=='site'])==2
        assert len([c for c in trace.calls if c[0]=='list'])==2
        assert len([c for c in trace.calls if c[0]=='account'])==3
        if expected=='FAIL':assert len(evidence['secret_leaks'])==1 and len(evidence['secret_leaks'][0]['detectors'])==2

def test_negative_native_and_blob(monkeypatch):
    for fault in ('foreign_container','site_drift','account_drift','list_drift','list_truncated','malformed','denied','etag_drift','truncated'):
        status,evidence,row,trace,_=run(monkeypatch,fault=fault)
        assert status=='UNKNOWN',(fault,status,evidence,row[flex.MARKER])

def test_listing_bound_and_partial_positive(monkeypatch):
    many=[(str(n)+'.zip',zipdata('mode=ready')) for n in range(5)]
    assert run(monkeypatch,many)[0]=='UNKNOWN'
    contents=[('positive.zip',zipdata(TOKEN)),('other.zip',zipdata('mode=ready'))]
    status,evidence,row,trace,_=run(monkeypatch,contents,fault='site_drift')
    assert status=='FAIL' and evidence['complete'] is False
    status,evidence,row,trace,_=run(monkeypatch,contents,fault='second_denied')
    assert status=='FAIL' and evidence['complete'] is False
    status,evidence,row,trace,_=run(monkeypatch,[(BLOB,zipdata('mode=ready',binary=True))])
    assert status=='UNKNOWN'
    status,evidence,row,trace,_=run(monkeypatch,[(BLOB,zipdata(TOKEN,binary=True))])
    assert status=='FAIL'

def test_preflight_and_default_off(monkeypatch):
    opts=options(True)
    assert flex.selected_targets(opts,[SCOPE])==preflight.azure_flex_archives.selected_targets(opts,[SCOPE])
    assert run(monkeypatch,on=False)[0]=='not_collected'
    foreign=deepcopy(target());foreign['storage_account_resource_id']=ACCOUNT.replace(SCOPE,'/subscriptions/33333333-3333-3333-3333-333333333333')
    with pytest.raises(ValueError):flex.selected_targets({**opts,flex.OPTION:[foreign]},[SCOPE])
    with pytest.raises(ValueError):preflight.azure_flex_archives.selected_targets({**opts,flex.OPTION:[foreign]},[SCOPE])

def native_cases(monkeypatch):
    cases=[]
    for name,value,fault,expected in (
        ('pass_clean','mode=ready',None,'PASS'),('fail_secret',TOKEN,None,'FAIL'),
        ('unknown_missing','mode=ready','foreign_container','UNKNOWN'),('unknown_drift','mode=ready','site_drift','UNKNOWN'),
        ('fail_partial_positive',TOKEN,'site_drift','FAIL')):
        status,_,item,_,index=run(monkeypatch,[(BLOB,zipdata(value))],fault=fault,capture=True)
        assert status==expected
        cases.append({'name':name,'item':item,'index':index,'expected':expected})
    encoded=json.dumps(cases,sort_keys=True)
    assert TOKEN not in encoded and len(encoded)<500000
    return {'schema_version':1,'check_id':flex.CHECK,'cases':cases}

def test_native_case_replay():
    document=json.loads((Path(__file__).resolve().parent/'fixtures/azure_flex_archive_native_extended_20261021.json').read_text())
    assert document['check_id']==flex.CHECK and len(document['cases'])==5
    for case in document['cases']:assert check.evaluate(case['item'],case['index'])[0]==case['expected']
