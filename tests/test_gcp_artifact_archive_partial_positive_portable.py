import base64, hashlib, io, json, tarfile, threading, time, zipfile
import pytest
from types import SimpleNamespace
MODE = "proposal"
from peaso import secret_scanning as scan
from peaso.collectors import gcp_artifact_file_secret_indicators as art
from peaso.collectors import gcp_selected_archive_secret_indicators as arc
from peaso.collectors import gcp_selected_object_secret_indicators as obj
from peaso.checks import gcp_artifact_file_secret_review_20261019 as ac
from peaso.checks import gcp_selected_archive_secret_review_20261019 as cc

SCOPE='projects/review'; BUCKET='review-bucket'; SECRET='offline-secret-value-123'
results=[]
def record(surface, case, expected, actual, marker=None):
    assert actual == expected, (surface,case,expected,actual,marker)
    assert SECRET not in json.dumps(marker), (surface, case, "raw secret in marker")
    results.append({'surface':surface,'case':case,'result':actual,'leaks':len(marker.get('leaks',[])) if marker else None,
                    'complete':marker.get('complete') if marker else None,
                    'digest_verified':marker.get('digest_verified') if marker else None})

def scanners(kind):
    scan._RESULTS.clear()
    def king(payload,path,timeout):
        return [(SECRET,'rule',1)] if SECRET.encode() in payload and kind != 'negative' else []
    def truffle(payload,path,timeout):
        if kind == 'unavailable': raise OSError('offline engine unavailable')
        return []
    scan._scan_kingfisher=king; scan._scan_trufflehog=truffle

def tar_of(files):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT) as f:
        for name,payload in files:
            info=tarfile.TarInfo(name);info.size=len(payload);f.addfile(info,io.BytesIO(payload))
    return output.getvalue()

def zip_of(files):
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_STORED) as f:
        for name,payload in files:f.writestr(name,payload)
    return output.getvalue()

class Transport:
    def __init__(self):
        self.lock=threading.Lock();self.evidence=[];self.calls=0;self.max_calls=None
        self.started=time.monotonic();self.deadline=None;self.deadline_seconds=None;self.timeout=10
        self.credentials=SimpleNamespace(headers=lambda:{'Authorization':'Bearer fake'})
        self.options={}
    def check_cancelled(self):pass

def make_art(raw,format_name,metadata_case=None,media_case=None):
    target={'project_scope':SCOPE,'name':SCOPE+'/locations/us-central1/repositories/source/files/settings.env',
            'sha256':hashlib.sha256(raw).hexdigest(),'format':format_name}
    meta={'name':target['name'],'sizeBytes':str(len(raw)),'hashes':[{'type':'SHA256','value':base64.b64encode(hashlib.sha256(raw).digest()).decode()}]}
    if metadata_case=='foreign':meta['name']=meta['name'].replace('projects/review','projects/foreign')
    if metadata_case=='digest':meta['hashes'][0]['value']=base64.b64encode(bytes(32)).decode()
    collector=SimpleNamespace(options={'content_secret_scans':True,'_content_secret_scan_kinds':[art.KIND],art.OPTION:[target]},
        scopes=[SCOPE],transport=Transport(),collections={
        ('project',SCOPE):{'coverage_status':'collected','items':[{'name':'projects/10001','projectId':'review'}]},
        ('artifact_repository',SCOPE):{'coverage_status':'collected','items':[{'name':SCOPE+'/locations/us-central1/repositories/source','mode':'STANDARD_REPOSITORY','format':'GENERIC'}]}})
    import requests
    class Response:
        def __init__(self,url,params,data,content_type):
            self.url=requests.Request('GET',url,params=params).prepare().url
            self.status_code=200;self.history=[]
            self.headers={'Content-Length':str(len(data)),'Content-Type':content_type}
            self.raw=SimpleNamespace(read=lambda n,decode_content: self.body.read(n))
            self.body=io.BytesIO(data)
        def close(self):pass
    class Session:
        def __init__(self):self.cookies={};self.headers={};self.proxies={}
        def request(self,method,url,*,params,**kwargs):
            assert method=='GET' and url.startswith('https://artifactregistry.googleapis.com/')
            media='/download/v1/' in url
            op='artifactregistry.files.download' if media else 'artifactregistry.files.get'
            assert url==('https://artifactregistry.googleapis.com/download/v1/'+target['name']+':download' if media
                         else 'https://artifactregistry.googleapis.com/v1/'+target['name'])
            assert params==({'alt':'media'} if media else {'fields':art.FIELDS})
            data=(b'X'*len(raw) if media_case=='digest' else raw) if media else json.dumps(meta).encode()
            return Response(url,params,data,'application/octet-stream' if media else 'application/json')
        def close(self):pass
    previous=requests.Session;requests.Session=Session
    try:
        rows=art.collect_selected_files(collector,SCOPE)
    finally:requests.Session=previous
    row=rows[0];m=row[art.MARKER]
    refs=[e['id'] for e in collector.transport.evidence]
    row['_coverage']={art.MARKER:{'status':'collected' if m['complete'] else 'incomplete','source_requests':refs}}
    row['_provenance']={'source_requests':refs}
    idx={'context':{'provider':'gcp','scope':SCOPE},'collections':{art.KIND:[{'scope':SCOPE,'status':'collected','items':[row],'source_requests':refs}]}}
    return m,ac.evaluate(row,idx)[0]

def make_arc(raw,format_name,metadata_case=None,media_case=None):
    target={'project_scope':SCOPE,'bucket':BUCKET,'object':'source.'+format_name,'generation':'1234','format':format_name}
    meta={'bucket':BUCKET,'name':target['object'],'generation':'1234','size':str(len(raw)),
          'contentType':{'zip':'application/zip','tar':'application/x-tar','tar.gz':'application/gzip'}[format_name]}
    if metadata_case=='foreign':meta['generation']='1235'
    if metadata_case=='wrong_size':meta['size']=str(len(raw)+1)
    if metadata_case=='foreign_name':meta['name']='foreign.zip'
    collector=SimpleNamespace(options={'content_secret_scans':True,'_content_secret_scan_kinds':[arc.KIND],arc.OPTION:[target]},
        scopes=[SCOPE],transport=Transport(),collections={('project',SCOPE):{'coverage_status':'collected','items':[{'name':'projects/10001','projectId':'review'}]},
        ('bucket',SCOPE):{'coverage_status':'collected','items':[{'name':BUCKET,'projectNumber':'10001'}]}})
    from urllib.parse import quote
    class Response:
        def __init__(self,data,media):
            self.status_code=200
            self.headers={'Content-Length':str(len(data))}
            if media:self.headers.update({'X-Goog-Generation':'1235' if media_case=='wrong_generation' else target['generation'],'Content-Type':meta['contentType']})
            self.raw=SimpleNamespace(read=lambda n,decode_content: self.body.read(n))
            self.body=io.BytesIO(data)
        def close(self):pass
    class Session:
        def request(self,method,url,*,params,**kwargs):
            assert method=='GET' and url=='https://storage.googleapis.com/storage/v1/b/'+BUCKET+'/o/'+quote(target['object'],safe='')
            media=params.get('alt')=='media'
            assert kwargs['stream'] is True and kwargs['allow_redirects'] is False
            assert params['generation']==params['ifGenerationMatch']==target['generation']
            data=(b'X'*len(raw) if media_case=='digest' else raw[:-1] if media_case=='truncated' else raw) if media else json.dumps(meta).encode()
            response=Response(data,media)
            if media_case=='truncated' and media:response.headers['Content-Length']=str(len(raw))
            if media_case=='redirect' and media:response.status_code=302
            return response
    collector.transport._session=lambda: Session()
    pages=list(arc.collection_pages(collector,SCOPE))
    row=pages[-1][0][0];m=row[arc.MARKER]
    if m['complete'] or m['status']=='partial':
        assert len(collector.transport.evidence)==2
        assert [e['operation'] for e in collector.transport.evidence]==['storage.objects.get.metadata','storage.objects.get.media']
        assert all(e['status']=='collected' and e['resource_id']==obj.identity({k:v for k,v in target.items() if k!='format'}) for e in collector.transport.evidence)
    refs=[e['id'] for e in collector.transport.evidence]
    row['_provenance']={'source_requests':refs}
    idx={'context':{'provider':'gcp','scope':SCOPE},'collections':{arc.KIND:[{'scope':SCOPE,'status':'collected','items':[row],'source_requests':refs}]}}
    return m,cc.evaluate(row,idx)[0]

@pytest.fixture(autouse=True)
def restore_scanners():
    original = (scan._scan_kingfisher, scan._scan_trufflehog)
    scan._RESULTS.clear()
    yield
    scan._scan_kingfisher, scan._scan_trufflehog = original
    scan._RESULTS.clear()

def test_artifact_archive_matrix():
    results.clear()
    positive=('API_TOKEN='+SECRET+'\n').encode();negative=b'STAGE=production\n'
    for case,kind,raw in [('full_positive','positive',positive),('full_clean','negative',negative),('partial_positive','unavailable',positive),('partial_negative','unavailable',negative)]:
        scanners(kind)
        m,status=make_art(raw,'utf8')
        record('artifact-utf8',case,{'full_positive':'FAIL','full_clean':'PASS','partial_positive':'FAIL' if MODE=='proposal' else 'UNKNOWN','partial_negative':'UNKNOWN'}[case],status,m)
    for case,kind,raw,meta,media in [('foreign_metadata','positive',positive,'foreign',None),('changed_metadata_digest','positive',positive,'digest',None),('changed_media_digest','positive',positive,None,'digest')]:
        scanners(kind);m,status=make_art(raw,'utf8',meta,media);record('artifact-utf8',case,'UNKNOWN',status,m)
    for fmt in ('zip','tar','tar.gz'):
        raw=zip_of([('one.env',positive),('two.env',negative)]) if fmt=='zip' else tar_of([('one.env',positive),('two.env',negative)])
        if fmt=='tar.gz':import gzip;raw=gzip.compress(raw,mtime=0)
        for case,kind in [('full_positive','positive'),('partial_positive','unavailable')]:
            scanners(kind);m,status=make_art(raw,fmt);record('artifact-'+fmt,case,'FAIL' if case=='full_positive' or MODE=='proposal' else 'UNKNOWN',status,m)
        # Later malformed member after one successful positive.
        bad=zip_of([('one.env',positive),('two.bin',b'\0')]) if fmt=='zip' else tar_of([('one.env',positive),('two.bin',b'\0')])
        if fmt=='tar.gz':bad=gzip.compress(bad,mtime=0)
        scanners('positive');m,status=make_art(bad,fmt)
        record('artifact-'+fmt,'later_unsupported','FAIL' if MODE=='proposal' else 'UNKNOWN',status,m)
        for case,kind,raw_case,meta,media in [('full_positive','positive',raw,None,None),('partial_positive','unavailable',raw,None,None),
                                              ('later_unsupported','positive',bad,None,None),('foreign_metadata','positive',raw,'foreign',None),
                                              ('changed_media','positive',raw,None,'digest')]:
            scanners(kind)
            m,status=make_arc(raw_case,fmt,meta,media)
            expected='FAIL' if case=='full_positive' or MODE=='proposal' and case in ('partial_positive','later_unsupported') else 'UNKNOWN'
            record('selected-archive-'+fmt,case,expected,status,m)
    if MODE=='proposal':
        for fmt in ('zip','tar','tar.gz'):
            maker=zip_of if fmt=='zip' else tar_of
            pos=maker([('one.env',positive)])
            neg=maker([('one.env',negative)])
            dup=maker([('one.env',positive),('two.env',positive)])
            bad=maker([('one.bin',b'\0')])
            if fmt=='tar.gz':
                import gzip
                pos,neg,dup,bad=(gzip.compress(x,mtime=0) for x in (pos,neg,dup,bad))
            for case,kind,data,meta,media,expect in [
                ('full_clean','negative',neg,None,None,'PASS'),
                ('partial_negative','unavailable',neg,None,None,'UNKNOWN'),
                ('native_generation_bound_partial_positive','unavailable',pos,None,None,'FAIL'),
                ('wrong_generation','unavailable',pos,None,'wrong_generation','UNKNOWN'),
                ('foreign_name','unavailable',pos,'foreign_name',None,'UNKNOWN'),
                ('wrong_size','unavailable',pos,'wrong_size',None,'UNKNOWN'),
                ('truncated_media','unavailable',pos,None,'truncated','UNKNOWN'),
                ('redirect_media','unavailable',pos,None,'redirect','UNKNOWN'),
                ('unsupported_first','positive',bad,None,None,'UNKNOWN'),
                ('dedup_two_members','positive',dup,None,None,'FAIL')]:
                scanners(kind)
                m,status=make_arc(data,fmt,meta,media)
                record('selected-archive-'+fmt,case,expect,status,m)
                if case=='dedup_two_members':assert len(m['leaks'])==1
            scanners('negative');m,status=make_art(neg,fmt)
            record('artifact-'+fmt,'full_clean','PASS',status,m)
            scanners('unavailable');m,status=make_art(neg,fmt)
            record('artifact-'+fmt,'partial_negative','UNKNOWN',status,m)
            scanners('positive');m,status=make_art(bad,fmt)
            record('artifact-'+fmt,'unsupported_first','UNKNOWN',status,m)
        scanners('unavailable');m,status=make_art(positive,'utf8')
        assert status=='FAIL'
        target={'project_scope':SCOPE,'name':SCOPE+'/locations/us-central1/repositories/source/files/settings.env',
                'sha256':hashlib.sha256(positive).hexdigest(),'format':'utf8'}
        row={'name':art.identity(target),art.MARKER:m,'_coverage':{art.MARKER:{'status':'incomplete','source_requests':['request-1','request-2']}},
             '_provenance':{'source_requests':['request-1','request-2']}}
        idx={'context':{'provider':'gcp','scope':SCOPE},'collections':{art.KIND:[{'scope':SCOPE,'status':'collected','items':[row],
             'source_requests':['request-1','request-2']}]}}
        for case,mutate in [('unbound_receipt',lambda:row['_coverage'][art.MARKER].update(source_requests=['request-1'])),
                            ('foreign_identity',lambda:row.update(name='artifact-selected-file:'+'0'*64)),
                            ('unverified_digest',lambda:m.update(digest_verified=False))]:
            import copy
            rr=copy.deepcopy(row);mm=rr[art.MARKER]
            ii={'context':idx['context'],'collections':{art.KIND:[{'scope':SCOPE,'status':'collected','items':[rr],
                'source_requests':['request-1','request-2']}]}}
            if case=='unbound_receipt':rr['_coverage'][art.MARKER]['source_requests']=['request-1']
            if case=='foreign_identity':rr['name']='artifact-selected-file:'+'0'*64
            if case=='unverified_digest':mm['digest_verified']=False
            record('artifact-utf8',case,'UNKNOWN',ac.evaluate(rr,ii)[0],mm)
    if MODE=='proposal':
        import copy
        raw=zip_of([('one.env',positive)])
        scanners('unavailable')
        target={'project_scope':SCOPE,'bucket':BUCKET,'object':'source.zip','generation':'1234','format':'zip'}
        m,status=make_arc(raw,'zip')
        assert status=='FAIL'
        for case in ('foreign_identity','foreign_scope','unavailable_detector_claim','missing_receipt','foreign_receipt'):
            mm=copy.deepcopy(m)
            name=arc.identity(target)
            if case=='foreign_identity':name='gcs-selected-archive:'+'0'*64
            if case=='foreign_scope':mm['scope']='projects/foreign'
            if case=='unavailable_detector_claim':mm['leaks'][0]['detectors'][0]['engine']='trufflehog'
            row={'name':name,arc.MARKER:mm,'_coverage':{arc.MARKER:{'status':'collected','source_requests':['request-1','request-2']}},
                 '_provenance':{'source_requests':['request-1','request-2']}}
            if case=='missing_receipt':row['_coverage'][arc.MARKER]['source_requests']=['request-1']
            if case=='foreign_receipt':row['_coverage'][arc.MARKER]['source_requests']=['request-1','request-3']
            idx={'context':{'provider':'gcp','scope':SCOPE},'collections':{arc.KIND:[{'scope':SCOPE,'status':'collected','items':[row],
                 'source_requests':['request-1','request-2']}]}}
            record('selected-archive-zip',case,'UNKNOWN',cc.evaluate(row,idx)[0],mm)
        for malformed in ({'project_scope':SCOPE,'bucket':BUCKET,'object':'source.zip','generation':'1234'},
                          {'project_scope':SCOPE,'bucket':BUCKET,'object':'source.zip','generation':'1234','format':'zip','sha256':'0'*64}):
            try:arc.normalize_selection({'content_secret_scans':True,'_content_secret_scan_kinds':[arc.KIND],arc.OPTION:[malformed]},[SCOPE])
            except obj.Incomplete:pass
            else:raise AssertionError('malformed archive selection accepted')
    print(json.dumps({'mode':MODE,'cases':results},indent=2))
    assert len(results) == 78
