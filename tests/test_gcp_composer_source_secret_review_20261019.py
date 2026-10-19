"""Native metadata producers plus uncached GCS streams; sockets always fail closed."""
import base64
from copy import deepcopy
import gzip
import io
import json
from pathlib import Path
import socket
from types import SimpleNamespace

import pytest
from peaso.collectors import gcp
from peaso.collectors import gcp_composer_source_secret_indicators as adapter
from peaso.checks import gcp_composer_source_secret_review_20261019 as check
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings

SCOPE = 'projects/review'
OWNER = SCOPE + '/locations/us-central1/environments/review'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
NAME = 'dags/' + 'ghp_' + '2Yt9Ec5Zp0Ru6Wq1Aa8Kd3Vx7Mn4Bs5Hj9Lf' + '.py'
BUCKET = 'review-bucket'


class Response:
    def __init__(self, value=None, *, raw=None, status=200, headers=None):
        self.payload = json.dumps(value).encode() if raw is None else raw
        self.raw = self
        self.stream = io.BytesIO(self.payload)
        self.status_code = status
        self.headers = {'Content-Length': str(len(self.payload)), 'Content-Type': 'application/json', **(headers or {})}
        self.closed = False
    def read(self, n, *, decode_content):
        assert decode_content is False and 0 < n <= 16384
        return self.stream.read(n)
    def close(self): self.closed = True
    def json(self): return json.loads(self.payload)


def metadata(payload=b'print("hello")\n', name=NAME):
    return {'bucket': BUCKET, 'name': name, 'generation': '12345', 'size': str(len(payload)), 'contentType': 'text/x-python'}


@pytest.fixture(autouse=True)
def isolation(monkeypatch):
    scanning._RESULTS.clear()
    monkeypatch.setattr(socket.socket, 'connect', lambda *a, **k: pytest.fail('unmocked socket', pytrace=False))
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])


def fixture(monkeypatch, payload=b'print("hello")\n', replies=None, options=None, source=None, collector_class=None):
    options = {'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND],
        'regions': ['us-central1'], 'metrics_scopes': False, 'include_inherited': False,
        'concurrency': 1, 'retries': 0, **(options or {})}
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {'Authorization':'Bearer auth-canary'}, close=lambda:None), options)
    collector = (collector_class or gcp.GCPCollector)({'provider':'gcp','scopes':[SCOPE],'options':options},
        requirements=['project','bucket','composer_environment'] + ([adapter.KIND] if collector_class else []), transport=transport)
    source = source or {'name': OWNER, 'config': {'dagGcsPrefix': 'gs://' + BUCKET + '/dags'}}
    calls, responses = [], []
    m = metadata(payload)
    pending = list(replies if replies is not None else [Response({'items':[m]}), Response(m),
        Response(raw=payload, headers={'Content-Type':'text/x-python','x-goog-generation':'12345'})])
    def request(method, url, **kw):
        calls.append((method,url,kw))
        assert method == 'GET'
        if kw.get('stream'):
            assert kw['allow_redirects'] is False and kw['headers']['Accept-Encoding'] == 'identity'
            assert kw['headers']['Authorization'] == 'Bearer auth-canary'
            assert 0 < kw['timeout'] <= transport.timeout
            assert pending, 'unexpected content call'
            r = pending.pop(0)
            # Dedicated content/list calls may not enter response.json or the generic cache.
            r.json = lambda: pytest.fail('content/list parsed through cache transport')
        elif url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            r = Response({'name':'projects/123456789','projectId':'review','state':'ACTIVE'})
        elif url == 'https://compute.googleapis.com/compute/v1/' + SCOPE:
            r = Response({'name':'review','id':'123456789','commonInstanceMetadata':{'items':[]}})
        elif url == 'https://storage.googleapis.com/storage/v1/b':
            r = Response({'items':[{'name':BUCKET,'projectNumber':'123456789'}]})
        elif url == 'https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/iam':
            r = Response({'version':1,'bindings':[]})
        elif url == 'https://composer.googleapis.com/v1/' + SCOPE + '/' + OWNER.split('/',2)[2].rsplit('/',1)[0]:
            r = Response({'environments':[source]})
        else:
            pytest.fail('unexpected native endpoint', pytrace=False)
        responses.append(r)
        return r
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request,auth=None))
    # Actual production scope jobs and envelope bind native API receipts, not fixture-only invented marker fields.
    for kind, scope, service, fetch in collector.scope_jobs(SCOPE):
        if kind in ('project','bucket','composer_environment'):
            collector.collections[(kind,scope)] = collector.envelope(kind,scope,service,fetch)
    return collector,calls,responses,pending


def produce(collector):
    env = collector.envelope(adapter.KIND,SCOPE,'storage',lambda:adapter.collection_pages(collector,SCOPE))
    row, = env['items']
    ix = {'context':{'provider':'gcp','scope':SCOPE},'collections':{adapter.KIND:[env], 'project':[collector.collections[('project',SCOPE)]], 'bucket':[collector.collections[('bucket',SCOPE)]], 'composer_environment':[collector.collections[('composer_environment',SCOPE)]]}}
    return row,ix,env


@pytest.mark.parametrize('options', [{'content_secret_scans':False}, {'_content_secret_scan_kinds':[]}, {'_content_secret_scan_kinds':['composer_environment']}])
def test_default_unselected_zero_content_calls(monkeypatch,options):
    c,calls,_,pending = fixture(monkeypatch,options=options)
    before = len(calls)
    monkeypatch.setattr(adapter,'scan_content',lambda *a,**k:pytest.fail('unexpected scanner'))
    assert adapter.collect_sources(c,SCOPE) == [] and len(calls) == before and len(pending) == 3
    assert check.evaluate({}, {})[0] == 'UNKNOWN'


def test_native_negative_generation_prefix_receipts_privacy(monkeypatch,clean):
    c,calls,responses,_ = fixture(monkeypatch)
    row,ix,env = produce(c)
    status,evidence = check.evaluate(row,ix)
    assert status == 'PASS' and evidence['coverage'] == 'observed_prefix_generations_only'
    assert 'concurrent changes' in evidence['observed']
    content = [kw for _,_,kw in calls if kw.get('stream')]
    assert len(content) == 3 and content[0]['params']['prefix'] == 'dags/'
    assert 'delimiter' not in content[0]['params'] and 'matchGlob' not in content[0]['params']
    assert all(k['params']['generation'] == k['params']['ifGenerationMatch'] == '12345' for k in content[1:])
    refs = row[adapter.MARKER]['source_requests']
    assert len(refs) == 6 and set(refs) <= set(row['_provenance']['source_requests'])
    assert all(r.closed for r in responses if r in responses[-3:])
    output = json.dumps([row,ix,env,c.transport.evidence]) + repr(c.transport.cache) + repr(scanning._RESULTS)
    for forbidden in [NAME, TOKEN, base64.b64encode(TOKEN.encode()).decode(), 'auth-canary','print("hello")']:
        if forbidden in output: pytest.fail('private source material persisted',pytrace=False)


@pytest.mark.parametrize('mutation', ['scope','prefix','bucket_owner','source_receipt','coverage','generation','foreign','unsupported','duplicate','list_fields','truncated','denied','redirect','gzip','binary','metadata_change','media_generation','missing_tools','file_limit','page_limit','cancel','call_limit','deadline','list_bytes'])
def test_incomplete_sources_never_clean(monkeypatch,clean,mutation):
    payload = b'print("hello")\n'
    m = metadata(payload)
    replies = [Response({'items':[m]}),Response(m),Response(raw=payload,headers={'Content-Type':'text/x-python','x-goog-generation':'12345'})]
    if mutation == 'generation': del m['generation']; replies[0] = Response({'items':[m]})
    if mutation == 'foreign': m['name']='other/secret.py'; replies[0]=Response({'items':[m]})
    if mutation == 'unsupported': m['name']='dags/file.zip'; replies[0]=Response({'items':[m]})
    if mutation == 'duplicate': replies[0]=Response({'items':[m,m]})
    if mutation == 'list_fields': replies[0]=Response({'items':[m],'unexpected':'provider secret'})
    if mutation == 'truncated': replies[0].headers['Content-Length']='999'
    if mutation in ('denied','redirect'): replies[0].status_code = 403 if mutation == 'denied' else 302
    if mutation in ('gzip','binary'):
        payload = gzip.compress(b'text') if mutation == 'gzip' else b'\xff\x00'
        m=metadata(payload)
        replies=[Response({'items':[m]}),Response(m),Response(raw=payload,headers={'Content-Type':'text/x-python','x-goog-generation':'12345'})]
    if mutation == 'metadata_change': replies[1]=Response({**m,'size':'100'})
    if mutation == 'media_generation': replies[2].headers['x-goog-generation']='999'
    if mutation == 'file_limit': replies[0]=Response({'items':[metadata(name='dags/file'+str(n)+'.py') for n in range(adapter.MAX_FILES+1)]})
    if mutation == 'page_limit': replies=[Response({'nextPageToken':str(n)}) for n in range(adapter.MAX_PAGES)]
    if mutation == 'list_bytes': replies[0]=Response(raw=b' '*(adapter.MAX_LIST_BYTES+1))
    c,calls,responses,_ = fixture(monkeypatch,replies=replies)
    if mutation == 'scope': c.collections[('composer_environment',SCOPE)]['items'][0]['name'] = OWNER.replace('/review/','/other/',1)
    if mutation == 'prefix': c.collections[('composer_environment',SCOPE)]['items'][0]['config']['dagGcsPrefix']='https://external.example/dags'
    if mutation == 'bucket_owner': c.collections[('bucket',SCOPE)]['items'][0]['projectNumber']='99999'
    if mutation == 'source_receipt': c.transport.evidence[0]['status']='unavailable'
    if mutation == 'coverage': c.collections[('composer_environment',SCOPE)]['coverage_status']='partial'
    if mutation == 'missing_tools': monkeypatch.setattr(scanning,'_scan_trufflehog',lambda *a: (_ for _ in ()).throw(RuntimeError('hidden provider snippet')))
    if mutation == 'cancel': monkeypatch.setattr(c.transport,'check_cancelled',lambda: (_ for _ in ()).throw(RuntimeError('cancelled canary')))
    if mutation == 'call_limit': c.transport.max_calls=c.transport.calls
    if mutation == 'deadline': c.transport.deadline=1
    row,ix,_ = produce(c)
    assert check.evaluate(row,ix)[0] == 'UNKNOWN'
    assert row[adapter.MARKER]['complete'] is False
    assert all(r.closed for r in responses if r in replies)
    output=json.dumps([row,ix,c.transport.evidence])+repr(c.transport.cache)
    for value in [NAME,'hidden provider snippet','cancelled canary','provider secret']:
        if value in output: pytest.fail('sensitive data persisted',pytrace=False)


def test_two_real_offline_tools_positive_negative_dedup_across_owners(monkeypatch,capsys):
    payload=('token="'+TOKEN+'"\n').encode()
    c,_,_,_ = fixture(monkeypatch,payload=payload)
    row,ix,_=produce(c)
    status,evidence=check.evaluate(row,ix)
    assert status == 'FAIL'
    leak,=evidence['secret_leaks']
    assert {d['engine'] for d in leak['detectors']} == {'kingfisher','trufflehog'}
    # Separate owner reads of the exact generation use the same keyed value fingerprint.
    second=deepcopy(c.collections[('composer_environment',SCOPE)]['items'][0])
    second['name']=OWNER+'2'
    c.collections[('composer_environment',SCOPE)]['items']=[second]
    m=metadata(payload)
    replies=[Response({'items':[m]}),Response(m),Response(raw=payload,headers={'Content-Type':'text/x-python','x-goog-generation':'12345'})]
    old_session=c.transport._session
    def request(*a,**kw): return replies.pop(0)
    monkeypatch.setattr(c.transport,'_session',lambda:SimpleNamespace(request=request,auth=None))
    row2,ix2,_=produce(c)
    status2,evidence2=check.evaluate(row2,ix2)
    assert status2 == 'FAIL'
    findings=[{'provider':'gcp','scope':SCOPE,'resource_id':r['name'],'native_resource_id':r['name'],
        'resource_type':adapter.KIND,'status':'FAIL','check_id':check.CHECK_ID,'finding_type':'secrets',
        'frameworks':[],'evidence':ev} for r,ev in [(row,evidence),(row2,evidence2)]]
    assert len(deduplicate_secret_findings(findings)) == 1
    output=json.dumps([findings,c.transport.evidence])+repr(c.transport.cache)+repr(scanning._RESULTS)+str(capsys.readouterr())
    if TOKEN in output or NAME in output: pytest.fail('private material persisted',pytrace=False)
    # Actual dual-tool clean verdict as well, with sockets blocked in this process.
    monkeypatch.setattr(c.transport,'_session',old_session)
    clean_c,_,_,_=fixture(monkeypatch,payload=b'print("no credential here")\n')
    clean_row,clean_ix,_=produce(clean_c)
    assert check.evaluate(clean_row,clean_ix)[0]=='PASS'


@pytest.mark.parametrize('case', ['two_pages','repeated_token','empty','duplicate_json','list_unknown_generation','environment_duplicate','over_environments','list_encoding','metadata_fields','stream_cancel','byte_budget','unselected_boolean'])
def test_additional_bounds_and_selection(monkeypatch,clean,case):
    m=metadata()
    replies=None
    if case=='two_pages': replies=[Response({'nextPageToken':'private-cursor-canary'}),Response({'items':[m]}),Response(m),Response(raw=b'print("hello")\n',headers={'Content-Type':'text/x-python','x-goog-generation':'12345'})]
    if case=='repeated_token': replies=[Response({'nextPageToken':'private-cursor-canary'}) for _ in range(2)]
    if case=='empty': replies=[Response({})]
    if case=='duplicate_json': replies=[Response(raw=b'{"items":[],"items":[]}')]
    if case=='list_unknown_generation': replies=[Response({'items':[{**m,'generation':'0'}]})]
    if case=='list_encoding': replies=[Response({'items':[m]},headers={'Content-Encoding':'gzip'})]
    if case=='metadata_fields': replies=[Response({'items':[m]}),Response({**m,'metadata':{'secret':TOKEN}})]
    c,calls,responses,_=fixture(monkeypatch,replies=replies)
    if case=='environment_duplicate':
        c.collections[('composer_environment',SCOPE)]['items'] *= 2
        rows=adapter.collect_sources(c,SCOPE)
        assert len(rows)==2 and all(r[adapter.MARKER]['complete'] is False for r in rows)
        return
    if case=='over_environments': c.collections[('composer_environment',SCOPE)]['items'] *= adapter.MAX_ENVIRONMENTS+1
    if case=='stream_cancel':
        count=[0]
        def cancel():
            count[0]+=1
            if count[0] >= 4: raise RuntimeError('cancelled')
        monkeypatch.setattr(c.transport,'check_cancelled',cancel)
    if case=='byte_budget':
        import threading,time
        c.transport._selected_object_secret_state={'started':time.monotonic(),'bytes':adapter.objects.MAX_TOTAL_BYTES,'calls':0,'lock':threading.Lock(),'items':{}}
    if case=='unselected_boolean':
        c.options['content_secret_scans']=1
        assert adapter.collect_sources(c,SCOPE)==[]
        return
    row,ix,_=produce(c)
    assert check.evaluate(row,ix)[0] == ('PASS' if case=='two_pages' else 'UNKNOWN')
    output=json.dumps([row,ix,c.transport.evidence])+repr(c.transport.cache)
    if 'private-cursor-canary' in output or TOKEN in output or NAME in output:
        pytest.fail('private data persisted',pytrace=False)
    assert all(r.closed for r in responses if r in (replies or []))


@pytest.mark.parametrize('mutation', ['source_refs','tool_version','scope','owner','file','path','bytes','complete'])
def test_check_rejects_tampered_producer_binding(monkeypatch,clean,mutation):
    c,_,_,_=fixture(monkeypatch)
    row,ix,_=produce(c)
    m=row[adapter.MARKER]
    if mutation=='source_refs': m['source_requests']=['request-999']
    if mutation=='tool_version': m['engines'][0]['version']='0'
    if mutation=='scope': m['scope']='projects/other'
    if mutation=='owner': m['owner']=OWNER+'2'
    if mutation=='file': m['files']=['raw/file.py']
    if mutation=='path':
        m['leaks']=[{'fingerprint':'a'*64,'detectors':[{'engine':'kingfisher','rule':'test'}], 'locations':[{'path':'raw/name.py','line':1}]}]
    if mutation=='bytes': m['bytes']=True
    if mutation=='complete': m['complete']=1
    assert check.evaluate(row,ix)[0]=='UNKNOWN'


def proposed_collector():
    """Root admitted the actual production collector hook during this dispatch."""
    return gcp.GCPCollector


def native_case(monkeypatch,mode):
    payload=('token="'+TOKEN+'"\n').encode() if mode=='FAIL' else b'print("hello")\n'
    replies=None
    if mode=='UNKNOWN': replies=[Response(raw=('provider secret '+TOKEN).encode(),status=403)]
    c,calls,responses,_=fixture(monkeypatch,payload=payload,replies=replies,collector_class=proposed_collector())
    c.collections.clear()
    snapshot=c.collect()
    env,=[e for e in snapshot['collections'] if e['type']==adapter.KIND]
    row,=env['items']
    ix={'context':{'provider':'gcp','scope':SCOPE},'collections':{
        k:[e for e in snapshot['collections'] if e['type']==k]
        for k in ['project','bucket','composer_environment',adapter.KIND]}}
    return row,ix,snapshot,c,calls,responses


@pytest.mark.parametrize('mode',['PASS','FAIL','UNKNOWN'])
def test_native_full_collector_proposed_hook_presanitize_and_snapshot(monkeypatch,mode,capsys):
    original=gcp.sanitize
    observed=[]
    def sanitize(value):
        text=json.dumps(value)
        if TOKEN in text or NAME in text or base64.b64encode(TOKEN.encode()).decode() in text:
            pytest.fail('raw source reached sanitize/cache boundary',pytrace=False)
        observed.append(True)
        return original(value)
    monkeypatch.setattr(gcp,'sanitize',sanitize)
    row,ix,snapshot,c,calls,responses=native_case(monkeypatch,mode)
    assert check.evaluate(row,ix)[0]==mode and observed
    refs=set(row[adapter.MARKER]['source_requests'])
    assert refs<=set(row['_provenance']['source_requests'])
    assert refs<={r['id'] for r in snapshot['metadata']['source_requests']}
    output=json.dumps(snapshot)+repr(c.transport.cache)+repr(scanning._RESULTS)+str(capsys.readouterr())
    for forbidden in [TOKEN,NAME,'auth-canary','provider secret',base64.b64encode(('token="'+TOKEN+'"\n').encode()).decode()]:
        if forbidden in output: pytest.fail('private source escaped native collector',pytrace=False)
    assert all(r.closed for r in responses if r in responses[-(1 if mode=='UNKNOWN' else 3):])


def test_native_project_id_number_alias(monkeypatch,clean):
    monkeypatch.setattr(__import__(__name__,fromlist=['SCOPE']),'SCOPE','projects/123456789')
    c,_,_,_=fixture(monkeypatch)
    row,ix,_=produce(c)
    assert check.evaluate(row,ix)[0]=='PASS'


def test_duplicate_leak_in_two_files_preserves_opaque_positions(monkeypatch):
    payload=('token="'+TOKEN+'"\n').encode()
    entries=[metadata(payload,NAME),metadata(payload,'dags/other.py')]
    replies=[Response({'items':entries})]
    for m in entries:
        replies.extend([Response(m),Response(raw=payload,headers={'Content-Type':'text/x-python','x-goog-generation':'12345'})])
    c,_,_,_=fixture(monkeypatch,payload=payload,replies=replies)
    row,ix,_=produce(c)
    status,evidence=check.evaluate(row,ix)
    assert status=='FAIL'
    leak,=evidence['secret_leaks']
    assert len(leak['locations'])==2 and len({x['path'] for x in leak['locations']})==2
    assert all(x['path'].startswith('composer.dag.content/') for x in leak['locations'])


@pytest.mark.parametrize('mode',['debug_logging','http_debug'])
def test_refuse_unsafe_http_diagnostics_before_content_calls(monkeypatch,mode):
    c,calls,_,_=fixture(monkeypatch)
    before=len(calls)
    if mode=='debug_logging':
        monkeypatch.setattr(adapter.logging.getLogger('urllib3.connectionpool'),'isEnabledFor',lambda level:True)
    else:
        monkeypatch.setattr(adapter.http.client.HTTPSConnection,'debuglevel',1)
    row,ix,_=produce(c)
    assert check.evaluate(row,ix)[0]=='UNKNOWN'
    assert row[adapter.MARKER]['reason']=='unsafe_http_diagnostics' and len(calls)==before


@pytest.mark.parametrize('case',['missing_prefix','masked_prefix','masked_config','project_partial','bucket_partial','project_alias_mismatch','bucket_receipt','environment_receipt','outside_scope','traversal','oversize','encrypted'])
def test_native_authority_and_object_constraints(monkeypatch,clean,case):
    m=metadata()
    if case=='traversal': m['name']='dags/../other.py'
    if case=='oversize': m['size']=str(adapter.objects.MAX_OBJECT_BYTES+1)
    if case=='encrypted': m['customerEncryption']={'encryptionAlgorithm':'AES256'}
    c,calls,_,_=fixture(monkeypatch,replies=[Response({'items':[m]})])
    env=c.collections[('composer_environment',SCOPE)]['items'][0]
    if case=='missing_prefix': env['config'].pop('dagGcsPrefix')
    if case=='masked_prefix': env['config']['_coverage']={'dagGcsPrefix':{'status':'unavailable'}}
    if case=='masked_config': env['_coverage']={'config':{'status':'unavailable'}}
    if case=='project_partial': c.collections[('project',SCOPE)]['coverage_status']='partial'
    if case=='bucket_partial': c.collections[('bucket',SCOPE)]['coverage_status']='partial'
    if case=='project_alias_mismatch': c.collections[('project',SCOPE)]['items'][0]['projectId']='other'
    if case=='bucket_receipt': c.collections[('bucket',SCOPE)]['items'][0]['_provenance']['source_requests']=[]
    if case=='environment_receipt': env['_provenance']['source_requests']=[]
    if case=='outside_scope': c.scopes=['projects/other']
    row,ix,_=produce(c)
    assert check.evaluate(row,ix)[0]=='UNKNOWN'
    assert len([kw for _,_,kw in calls if kw.get('stream')]) == (1 if case in ('traversal','oversize','encrypted') else 0)


def test_source_produced_gzip_cases_and_normal_install_idempotence(monkeypatch):
    import peaso.checks as registry
    import peaso.checks.fixtures as fixture_registry
    path=Path(check.__file__).with_name('gcp_composer_source_secret_fixtures.json.gz')
    cases=json.loads(gzip.decompress(path.read_bytes()))
    for mode in ['pass','fail','unknown']:
        assert check.evaluate(cases[mode],cases[mode+'_index'])[0]==mode.upper()
    assert check.evaluate(cases['missing'],cases['pass_index'])[0]=='UNKNOWN'
    assert check.evaluate(cases['malformed'],cases['pass_index'])[0]=='UNKNOWN'
    monkeypatch.setattr(registry,'CHECKS',[])
    monkeypatch.setattr(fixture_registry,'CASES',{})
    check.install();check.install()
    registered,=registry.CHECKS
    assert registered.id==check.CHECK_ID and registered.severity=='high' and registered.kind==adapter.KIND
    assert set(registered.dependencies)==set(check.DECLARATION['dependencies'])
    assert fixture_registry.CASES[check.CHECK_ID]==cases


def test_interleaved_foreign_transport_receipts_never_attributed(monkeypatch,clean):
    c,_,_,_=fixture(monkeypatch)
    original=adapter._list
    foreign=[]
    def interleave(*args,**kwargs):
        result=original(*args,**kwargs)
        for scope,resource,operation in [
            ('projects/other',adapter.identity(OWNER),'storage.objects.list.composer_dags'),
            (SCOPE,adapter.identity(OWNER+'2'),'storage.objects.list.composer_dags'),
            (SCOPE,'gcs-selected-object:'+'f'*64,'storage.objects.get.metadata'),
            (SCOPE,'gcs-selected-object:'+'e'*64,'storage.objects.get.media')]:
            with c.transport.lock:
                receipt={'id':'request-'+str(len(c.transport.evidence)+1),'scope':scope,
                         'resource_id':resource,'operation':operation,'method':'GET','status':'collected'}
                c.transport.evidence.append(receipt)
                foreign.append(receipt['id'])
        return result
    monkeypatch.setattr(adapter,'_list',interleave)
    row,ix,_=produce(c)
    assert check.evaluate(row,ix)[0]=='PASS'
    assert not set(foreign)&set(row[adapter.MARKER]['source_requests'])
    assert not set(foreign)&set(row['_provenance']['source_requests'])
    assert len(row[adapter.MARKER]['read_receipts'])==3


@pytest.mark.parametrize('field',['scope','resource_id','id','operation','unexplained_ref'])
def test_consumer_rejects_foreign_receipts_even_when_envelope_lists_them(monkeypatch,clean,field):
    c,_,_,_=fixture(monkeypatch)
    row,ix,env=produce(c)
    m=row[adapter.MARKER]
    if field=='scope': m['read_receipts'][0]['scope']='projects/other'
    if field=='resource_id': m['read_receipts'][0]['resource_id']=adapter.identity(OWNER+'2')
    if field=='id': m['read_receipts'][0]['id']=m['native_requests'][0]
    if field=='operation': m['read_receipts'][0]['operation']='unrelated.get'
    if field=='unexplained_ref':
        m['source_requests'].append('request-999')
        env['source_requests'].append('request-999')
    assert check.evaluate(row,ix)[0]=='UNKNOWN'
