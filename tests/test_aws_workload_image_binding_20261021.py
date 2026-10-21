"""Normal-import native workload metadata -> bounded ECR image -> Trivy -> check proof."""
from contextlib import contextmanager,ExitStack
from copy import deepcopy
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib,importlib,io,json,sys,tarfile,threading
import boto3
from botocore.stub import Stubber
import pytest

HERE=Path(__file__).resolve().parents[1]
from peaso import aws_image_selection_20261021 as selection
from peaso.collectors import aws_image_vulnerability_native_20261021 as native
from peaso.collectors import aws_image_vulnerability_runtime_20261021 as runtime
from peaso.checks import aws_image_vulnerabilities_20261021 as check
from peaso import container_image_archive_20261020 as archive
from peaso import trivy_container_runner_20261020 as trivy
from peaso.collectors import aws_package_content_indicators as download
ACCOUNT='123456789012';REGION='eu-west-1';SCOPE=ACCOUNT+'/'+REGION
TASK=f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/audit:7'
JOB=f'arn:aws:batch:{REGION}:{ACCOUNT}:job-definition/audit:7'
LAMBDA=f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:audit'
META={'HTTPStatusCode':200,'RequestId':'native-request-123'}
PROFILES=('lambda','ecs','container','ecs_container','eks_container','eks_init_container','node_container')
NATIVE_SECRET_CASES={}

@pytest.fixture
def image():
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as tar:
        payload=b'ID=alpine\nVERSION_ID=3.22.0\n';entry=tarfile.TarInfo('etc/os-release');entry.size=len(payload)
        tar.addfile(entry,io.BytesIO(payload))
    layer=buf.getvalue()
    config=json.dumps({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':[archive.sha(layer)]},
        'config':{'Env':['PRIVATE_FIXTURE=never-report-this-value']},
        'history':[{'created_by':'RUN echo fixture'}]},separators=(',',':')).encode()
    manifest=json.dumps({'schemaVersion':2,'mediaType':archive.OCI,
        'config':{'mediaType':next(x for x in archive.CONFIGS if 'oci' in x),'size':len(config),'digest':archive.sha(config)},
        'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar','size':len(layer),'digest':archive.sha(layer)}]},separators=(',',':')).encode()
    digest=archive.sha(manifest)
    reference=f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/fixture/image@{digest}'
    return SimpleNamespace(layer=layer,config=config,manifest=manifest,digest=digest,reference=reference)

def target(profile,image):
    row={'scope':SCOPE,'repository_name':'fixture/image','image_digest':image.digest}
    if profile=='lambda':return {'scope':SCOPE,'function_arn':LAMBDA}
    if profile=='ecs':row.update(task_definition_arn=TASK,container_name='worker')
    else:
        row.update(job_definition_arn=JOB,batch_profile=profile)
        if profile in ('ecs_container','eks_container','eks_init_container'):row['container_name']='worker'
        if profile=='node_container':row['node_range']='0:'
    return row

def workload_response(profile,image,*,revision=7,foreign=False):
    reference=image.reference if not foreign else image.reference.replace(ACCOUNT,'000000000000')
    if profile=='lambda':
        return {'Configuration':{'FunctionArn':LAMBDA,'PackageType':'Image','Version':'$LATEST',
                'RevisionId':'rev-'+str(revision)},'Code':{'ResolvedImageUri':reference},
                'ResponseMetadata':dict(META)}
    if profile=='ecs':
        return {'taskDefinition':{'taskDefinitionArn':TASK,'family':'audit','revision':revision,
            'status':'ACTIVE','containerDefinitions':[{'name':'worker','image':reference}]},'ResponseMetadata':dict(META)}
    row={'jobDefinitionArn':JOB,'jobDefinitionName':'audit','revision':revision,'status':'ACTIVE','type':'container',
        'containerOrchestrationType':'EKS' if profile.startswith('eks_') else 'ECS'}
    if profile=='container':row['containerProperties']={'image':reference,'vcpus':1,'memory':128}
    elif profile=='ecs_container':row['ecsProperties']={'taskProperties':[{'containers':[{'name':'worker','image':reference}]}]}
    elif profile in ('eks_container','eks_init_container'):
        field='initContainers' if profile=='eks_init_container' else 'containers'
        row['eksProperties']={'podProperties':{field:[{'name':'worker','image':reference}]}}
    else:row['nodeProperties']={'numNodes':1,'mainNode':0,'nodeRangeProperties':[{'targetNodes':'0:','container':{'image':reference,'vcpus':1,'memory':128}}]}
    return {'jobDefinitions':[row],'ResponseMetadata':dict(META)}

def runner(positive=True,fresh=True):
    def scan(identity,manifest,config,layers,**kw):
        assert kw['native_verifier']()==identity
        archive.validate(identity,manifest,config,layers)
        diff=archive.sha(layers[0].read_bytes() if isinstance(layers[0],Path) else layers[0])
        vuln={'VulnerabilityID':'CVE-2026-12345','PkgName':'fixture-package','InstalledVersion':'1.0',
            'FixedVersion':'1.1','Status':'fixed','Severity':'HIGH'}
        result={'SchemaVersion':2,'ArtifactType':'container_image','Metadata':{'ImageID':identity['config_digest'],
            'DiffIDs':[diff],'RepoDigests':[identity['immutable_reference']]},
            'Results':[{'Target':'fixture-image','Class':'os-pkgs','Type':'alpine','Packages':[{'Name':'fixture-package'}],
                'Vulnerabilities':[vuln] if positive else []}]}
        scan=trivy.parse_report(json.dumps(result,separators=(',',':')).encode(),0,identity,
            diff_ids=[diff],database={'fresh':fresh})
        assert kw['native_verifier']()==identity
        return scan
    return scan

def request_budget(cancel=False):
    return SimpleNamespace(check_deadline=(lambda:(_ for _ in ()).throw(RuntimeError('cancelled')) if cancel else lambda:None),
        _lock=threading.RLock(),max_calls=None,calls=0,deadline=None,timeout=3,content_secret_scans=False)

@contextmanager
def lease(**kw):yield '/synthetic/lease'

def execute(profile,image,monkeypatch,*,positive=True,fresh=True,mutation=None,disabled=False):
    selected=target(profile,image)
    if disabled:
        class NoIO:
            def __getattr__(self,name):raise AssertionError('disabled touched IO')
        assert native.collect_native(NoIO(),NoIO(),None,None,None)['observations']==[]
        assert runtime.authorize_collector({},[])==[]
        return 'not_collected',None,None
    requests=request_budget()
    clients={service:boto3.client(service,region_name=REGION,aws_access_key_id='offline',aws_secret_access_key='offline')
        for service in ('sts','ecr','ecs','batch','lambda')}
    if mutation=='cleanup':
        def failed_close():raise RuntimeError('PRIVATE-cleanup-error')
        monkeypatch.setattr(clients['ecr'],'close',failed_close)
    payloads={archive.sha(image.config):image.config,archive.sha(image.layer):image.layer}
    with ExitStack() as stack:
        stub={service:stack.enter_context(Stubber(client)) for service,client in clients.items()}
        def caller():stub['sts'].add_response('get_caller_identity',{'Account':ACCOUNT,
            'Arn':f'arn:aws:sts::{ACCOUNT}:assumed-role/offline/session','UserId':'offline','ResponseMetadata':dict(META)},{})
        def work(changed=False):
            service='lambda' if profile=='lambda' else 'ecs' if profile=='ecs' else 'batch'
            operation='get_function' if profile=='lambda' else 'describe_task_definition' if profile=='ecs' else 'describe_job_definitions'
            args={'FunctionName':LAMBDA} if profile=='lambda' else {'taskDefinition':TASK} if profile=='ecs' else {'jobDefinitions':[JOB]}
            if mutation=='denied':stub[service].add_client_error(operation,service_error_code='AccessDeniedException',http_status_code=403,expected_params=args);return
            dto=workload_response(profile,image,revision=8 if changed and mutation=='revision' else 7,
                foreign=changed and mutation=='foreign')
            stub[service].add_response(operation,dto,args)
        def manifest(*, initial=False):
            stub['ecr'].add_response('batch_get_image',{'images':[{'registryId':ACCOUNT,'repositoryName':'fixture/image',
                'imageId':{'imageDigest':image.digest},'imageManifest':image.manifest.decode(),
                'imageManifestMediaType':archive.OCI}],'failures':[],'ResponseMetadata':dict(META)},
                {'registryId':ACCOUNT,'repositoryName':'fixture/image','imageIds':[{'imageDigest':image.digest}],
                 **({'acceptedMediaTypes':[archive.OCI,archive.DOCKER]} if profile=='lambda' or not initial else {})})
        caller();work()
        if mutation!='denied':
            manifest(initial=True)
            for blob in (image.config,image.layer):
                digest=archive.sha(blob)
                stub['ecr'].add_response('get_download_url_for_layer',{'layerDigest':digest,
                    'downloadUrl':f'https://fixture.s3.{REGION}.amazonaws.com/blob/{digest}?PRIVATE=signed',
                    'ResponseMetadata':dict(META)},
                    {'registryId':ACCOUNT,'repositoryName':'fixture/image','layerDigest':digest})
            for turn in range(4):
                caller();work(changed=turn==0 and mutation in ('revision','foreign'))
                if turn==0 and mutation in ('revision','foreign'):break
                manifest()
        class Response:
            status=200
            def __init__(self,url):
                self.url=url;self.stream=io.BytesIO(payloads[url.split('/blob/')[1].split('?')[0]])
                self.headers={'Content-Length':str(len(self.stream.getvalue()))}
            def geturl(self):return self.url
            def read(self,count):return self.stream.read(count)
            def __enter__(self):return self
            def __exit__(self,*a):pass
        monkeypatch.setattr(download,'build_opener',lambda *args:SimpleNamespace(open=lambda url,**kw:Response(url)))
        def client(service,**kwargs):
            config=kwargs['config'];assert kwargs['region_name']==REGION and config.ignore_configured_endpoint_urls
            return clients[service]
        session=SimpleNamespace(client=client)
        if mutation in ('revision','foreign'):
            def forbidden(*a,**kw):raise AssertionError('drift reached scanner')
            run=forbidden
        else:run=runner(positive,fresh)
        result=runtime.collect_scope(requests,session,{'Account':ACCOUNT},REGION,[selected],lease=lease,
            runner=run,scratch_parent=None)
    metadata={};runtime.attach_metadata(metadata,[{'type':selection.KIND,'items':result.items}],[selected])
    item=result.items[0]
    index={'context':{'provider':'aws','scope':SCOPE,'metadata':metadata},
        'collections':{selection.KIND:[{'scope':SCOPE,'status':result.status,'items':[item]}]}}
    status,evidence=check.evaluate(item,index)
    assert 'PRIVATE' not in json.dumps((item,evidence,metadata),default=str)
    return status,evidence,item

@pytest.mark.parametrize('profile',PROFILES)
def test_positive_and_clean_native_to_consumer(profile,image,monkeypatch):
    assert execute(profile,image,monkeypatch)[0]=='FAIL'
    assert execute(profile,image,monkeypatch,positive=False)[0]=='PASS'

@pytest.mark.parametrize('profile',PROFILES)
def test_foreign_revision_denied_unknown(profile,image,monkeypatch):
    for mutation in ('foreign','revision','denied'):
        assert execute(profile,image,monkeypatch,mutation=mutation)[0]=='UNKNOWN'

def test_disabled_no_io_and_closed_selection(image,monkeypatch):
    assert execute('ecs',image,monkeypatch,disabled=True)[0]=='not_collected'
    selected=target('ecs',image)
    assert selection.selections({selection.ENABLE:True,selection.OPTION:[selected]},[SCOPE])==[selected]
    controls={selection.ENABLE:True,selection.OPTION:[selected]}
    runtime.issue_engine_grant(controls,[SCOPE],[])
    with pytest.raises(ValueError):runtime.authorize_collector(controls,[SCOPE])
    runtime.issue_engine_grant(controls,[SCOPE],[selection.CHECK])
    assert runtime.authorize_collector(controls,[SCOPE])==[selected]
    for bad in (dict(selected,image_digest='latest'),dict(selected,container_name='other',extra='x'),
                dict(selected,scope='000000000000/'+REGION),dict(selected,task_definition_arn=TASK.rsplit(':',1)[0])):
        with pytest.raises(ValueError):selection.selections({selection.ENABLE:True,selection.OPTION:[bad]},[SCOPE])

def test_clean_incomplete_unknown_and_missing(image,monkeypatch):
    assert execute('ecs',image,monkeypatch,positive=False,fresh=False)[0]=='UNKNOWN'
    selected=target('ecs',image)
    metadata={};runtime.attach_metadata(metadata,[],[selected])
    assert metadata['image_vulnerability_scan']['observations']==[None]

@pytest.mark.parametrize('profile',['ecs','container'])
def test_partial_positive_fail_and_partial_clean_unknown(profile,image,monkeypatch):
    assert execute(profile,image,monkeypatch,mutation='cleanup')[0]=='FAIL'
    assert execute(profile,image,monkeypatch,mutation='cleanup',positive=False)[0]=='UNKNOWN'

def test_secret_path_requires_its_named_check_and_exact_workload(image):
    from peaso.collectors import aws_workload_image_secret_native_20261021 as secret
    t=target('ecs',image)
    options={secret.ENABLE:True,secret.OPTION:[t]}
    assert secret.selected(options,[SCOPE],[])==[]
    assert secret.selected(options,[SCOPE],[secret.CHECK])==[t]
    with pytest.raises(ValueError):
        secret.selected({secret.ENABLE:True,secret.OPTION:[{'scope':SCOPE,
            'repository_name':'fixture/image','image_digest':image.digest}]},[SCOPE],[secret.CHECK])
    assert secret.selected({secret.ENABLE:False,secret.OPTION:[t]},[SCOPE],[secret.CHECK])==[]
    secret.issue_engine_grant(options,[SCOPE],[])
    assert secret.authorize_collector(options,[SCOPE])==[]
    secret.issue_engine_grant(options,[SCOPE],[secret.CHECK])
    assert secret.authorize_collector(options,[SCOPE])==[t]
    secret.issue_engine_grant(options,[SCOPE],[secret.CHECK])
    options[secret.OPTION]=[dict(t,container_name='changed')]
    with pytest.raises(ValueError):secret.authorize_collector(options,[SCOPE])

def test_secret_consumer_conserves_partial_positive(image):
    from peaso.checks import aws_workload_image_secret_review_20261021 as secret_check
    from peaso.collectors.aws_package_content_indicators import marker
    t=target('ecs',image)
    binding={'asset_arn':TASK,'revision':7,'container':'worker','profile':'ecs_container','image_uri':image.reference}
    identity=f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/fixture/image@{image.digest}'
    reference={'File':'image-config','Categories':['secret'],'LayerDigest':archive.sha(image.config)}
    source={'collection_status':'collected','ImageDigest':image.digest,
        'PackageSecretIndicators':marker(identity,ACCOUNT,REGION,'ecr:batch_get_image',[reference],complete=False,
            code='image_content_incomplete')}
    row={'selection':t,'binding_before':binding,'binding_after':None,'source':source,'complete':False,
         'image':{'repository_name':'fixture/image','image_digest':image.digest}}
    assert secret_check.evaluate(row)[0]=='FAIL'
    source['PackageSecretIndicators']=marker(identity,ACCOUNT,REGION,'ecr:batch_get_image',[])
    assert secret_check.evaluate(row)[0]=='UNKNOWN'
    row['binding_after']=binding;row['complete']=True
    assert secret_check.evaluate(row)[0]=='PASS'

@pytest.mark.parametrize('positive,mutation',[(False,None),(True,None),(False,'drift'),(True,'drift')])
@pytest.mark.parametrize('profile',['ecs','lambda','container'])
def test_secret_native_package_pipeline_clean(image,monkeypatch,positive,mutation,profile):
    from peaso.collectors import aws_workload_image_secret_native_20261021 as secret
    from peaso.checks import aws_workload_image_secret_review_20261021 as secret_check
    from peaso.collectors.aws import Requests
    if positive:
        configuration=json.loads(image.config)
        # Deliberately synthetic PAT; fixture credentials are never verified.
        configuration['config']['Env']=['GITHUB_TOKEN=ghp_SYNTHETICSYNTHETICSYNTHETICSYNTHETIC']
        image.config=json.dumps(configuration,separators=(',',':')).encode()
        manifest=json.loads(image.manifest)
        manifest['config']['size']=len(image.config)
        manifest['config']['digest']=archive.sha(image.config)
        image.manifest=json.dumps(manifest,separators=(',',':')).encode()
        image.digest=archive.sha(image.manifest)
        image.reference=f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/fixture/image@{image.digest}'
    selected=target(profile,image)
    requests=Requests({'content_secret_scans':True,'retry_attempts':1,'max_calls':32})
    clients={service:boto3.client(service,region_name=REGION,aws_access_key_id='offline',aws_secret_access_key='offline')
        for service in ('sts','ecs','ecr','lambda','batch')}
    payloads={archive.sha(image.config):image.config,archive.sha(image.layer):image.layer}
    with ExitStack() as stack:
        stub={service:stack.enter_context(Stubber(client)) for service,client in clients.items()}
        for turn in range(2):
            stub['sts'].add_response('get_caller_identity',{'Account':ACCOUNT,
                'Arn':f'arn:aws:sts::{ACCOUNT}:assumed-role/offline/session','UserId':'offline','ResponseMetadata':dict(META)},{})
            if profile=='ecs':
                stub['ecs'].add_response('describe_task_definition',workload_response('ecs',image,
                    revision=8 if mutation and turn else 7),{'taskDefinition':TASK})
            elif profile=='lambda':
                stub['lambda'].add_response('get_function',workload_response('lambda',image,
                    revision=8 if mutation and turn else 7),{'FunctionName':LAMBDA})
            else:
                stub['batch'].add_response('describe_job_definitions',workload_response(profile,image,
                    revision=8 if mutation and turn else 7),{'jobDefinitions':[JOB]})
        stub['ecr'].add_response('batch_get_image',{'images':[{'registryId':ACCOUNT,'repositoryName':'fixture/image',
            'imageId':{'imageDigest':image.digest},'imageManifest':image.manifest.decode(),
            'imageManifestMediaType':archive.OCI}],'failures':[],'ResponseMetadata':dict(META)},
            {'registryId':ACCOUNT,'repositoryName':'fixture/image','imageIds':[{'imageDigest':image.digest}],
             **({'acceptedMediaTypes':[download.OCI,download.DOCKER]} if profile=='lambda' else {})})
        for blob in (image.config,image.layer):
            digest=archive.sha(blob)
            stub['ecr'].add_response('get_download_url_for_layer',{'layerDigest':digest,
                'downloadUrl':f'https://fixture.s3.{REGION}.amazonaws.com/blob/{digest}?PRIVATE=signed',
                'ResponseMetadata':dict(META)},
                {'registryId':ACCOUNT,'repositoryName':'fixture/image','layerDigest':digest})
        class Response:
            status=200
            def __init__(self,url):
                self.url=url;self.stream=io.BytesIO(payloads[url.split('/blob/')[1].split('?')[0]])
                self.headers={'Content-Length':str(len(self.stream.getvalue()))}
            def geturl(self):return self.url
            def read(self,count):return self.stream.read(count)
            def __enter__(self):return self
            def __exit__(self,*a):pass
        monkeypatch.setattr(download,'build_opener',lambda *args:SimpleNamespace(open=lambda url,**kw:Response(url)))
        def client(service,**kw):
            assert kw['region_name']==REGION and kw['config'].ignore_configured_endpoint_urls
            return clients[service]
        session=SimpleNamespace(client=client)
        result=secret.collect_collection(requests,session,{'Account':ACCOUNT},REGION,[selected])
        rows=[result.items[0]['WorkloadImageSecretReview']]
    assert len(rows)==1
    status,evidence=secret_check.evaluate(rows[0])
    assert status==('FAIL' if positive else 'UNKNOWN' if mutation else 'PASS'),rows[0]
    if profile=='ecs':
        item=result.items[0]
        index={'context':{'provider':'aws','scope':SCOPE,'metadata':{secret.OPTION:[selected]}},
            'collections':{secret.KIND:[{'scope':SCOPE,
                'status':result.status,'items':result.items}]}}
        assert secret_check.evaluate_item(item,index)[0]==status
        NATIVE_SECRET_CASES[(positive,mutation)]={'item':item,'index':index,'expected':status}
    assert 'PRIVATE' not in json.dumps(rows)

def test_secret_denied_cancel_and_default_off_zero_io(image):
    from peaso.collectors import aws_workload_image_secret_native_20261021 as secret
    from peaso.checks import aws_workload_image_secret_review_20261021 as secret_check
    from peaso.collectors.aws import Requests
    selected=target('ecs',image)
    class NoIO:
        def client(self,*a,**kw):raise AssertionError('disabled or cancelled path reached SDK')
    assert secret.collect_scope(Requests({}),NoIO(),ACCOUNT,REGION,[selected],named=[secret.CHECK])==[]
    assert secret.collect_scope(Requests({'content_secret_scans':True}),NoIO(),ACCOUNT,REGION,
        [selected],named=[])==[]
    cancelled=threading.Event();cancelled.set()
    from peaso.collectors.aws import ReadFailure
    with pytest.raises(ReadFailure) as stopped:
        secret.collect_scope(Requests({'content_secret_scans':True,'cancel_event':cancelled}),NoIO(),
            ACCOUNT,REGION,[selected],named=[secret.CHECK])
    assert stopped.value.code=='collection_cancelled'

    sts=boto3.client('sts',region_name=REGION,aws_access_key_id='offline',aws_secret_access_key='offline')
    ecs=boto3.client('ecs',region_name=REGION,aws_access_key_id='offline',aws_secret_access_key='offline')
    with Stubber(sts) as s,Stubber(ecs) as e:
        s.add_response('get_caller_identity',{'Account':ACCOUNT,
            'Arn':f'arn:aws:sts::{ACCOUNT}:assumed-role/offline/session','UserId':'offline','ResponseMetadata':dict(META)},{})
        e.add_client_error('describe_task_definition',service_error_code='AccessDeniedException',
            http_status_code=403,expected_params={'taskDefinition':TASK})
        session=SimpleNamespace(client=lambda service,**kw:{'sts':sts,'ecs':ecs}[service])
        rows=secret.collect_scope(Requests({'content_secret_scans':True,'retry_attempts':1}),
            session,ACCOUNT,REGION,[selected],named=[secret.CHECK])
    assert len(rows)==1 and secret_check.evaluate(rows[0])[0]=='UNKNOWN'


def test_secret_native_cases_replay():
    from peaso.checks import aws_workload_image_secret_review_20261021 as secret_check
    document=json.loads((HERE/'tests/fixtures/aws_workload_image_secret_native_20261021.json').read_text())
    assert document['check_id']==secret_check.CHECK and len(document['cases'])==5
    for case in document['cases']:
        assert secret_check.evaluate_item(case['item'],case['index'])[0]==case['expected']
