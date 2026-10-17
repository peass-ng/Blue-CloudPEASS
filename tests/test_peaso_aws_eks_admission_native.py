"""Offline SDK-shaped EKS metadata + actual signed admission-routing predicate."""
import base64
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import json
from urllib.parse import urlsplit,parse_qs
import boto3
from botocore.stub import Stubber
import pytest
from peaso.collectors import aws,aws_eks_admission_native as native
from peaso.engine import collect_snapshot,evaluate_snapshot
from peaso.snapshot import make_snapshot

A='123456789012';R='us-east-1';S=A+'/'+R;ARN=f'arn:aws:eks:{R}:{A}:cluster/owned'
ENDPOINT='https://ABCDEF0123456789ABCDEF0123456789.gr7.us-east-1.eks.amazonaws.com'
CHECK='aws_eks_runtime_image_integrity'

def policy():return {'status':'collected','designated_cluster_arns':[ARN],
    'approved_verifier_services':[{'namespace':'security','name':'verifier'}]}

@pytest.fixture(scope='module')
def ca():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'INERT-EKS-CA')]);now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(1).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)

def detail(ca):return {'cluster':{'name':'owned','arn':ARN,'status':'ACTIVE','endpoint':ENDPOINT,
    'certificateAuthority':{'data':base64.b64encode(ca).decode()},'resourcesVpcConfig':{'endpointPublicAccess':True}}}

def config(mode='good'):
    hook={'name':'verifier.security.example','failurePolicy':'Fail','clientConfig':{'service':{'namespace':'security','name':'verifier'}},
          'rules':[{'operations':['CREATE'],'apiGroups':[''],'apiVersions':['v1'],'resources':['pods']}]}
    if mode=='ignore':hook['failurePolicy']='Ignore'
    if mode=='url':hook['clientConfig']={'url':'https://redaction-user:NEVER-PERSIST@unrelated.invalid/webhook'}
    if mode=='scoped':hook['namespaceSelector']={'matchLabels':{'name':'somewhere'}}
    return {'metadata':{'name':mode+'.example','uid':mode+'-uid'},'webhooks':[hook]}

def page(items,continuation=''):return {'kind':'ValidatingWebhookConfigurationList','apiVersion':'admissionregistration.k8s.io/v1',
    'metadata':{'resourceVersion':'7','continue':continuation},'items':items}

class Response:
    status=200
    def __init__(self,url,data):self.url=url;self.data=json.dumps(data).encode()
    def geturl(self):return self.url
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,n):return self.data[:n]


def setup_transport(monkeypatch,mode,wire):
    pages=[page([config('good')])]
    if mode=='empty':pages=[page([])]
    if mode in('ignore','url','scoped'):pages=[page([config(mode)])]
    if mode=='unrelated-url':pages=[page([config(),config('url')])]
    if mode=='paged':pages=[page([config('url')],'next'),page([config()])]
    if mode in('repeated','page-limit'):pages=[page([config()],'next'),page([config()],'next')]
    if mode=='null-item-kind':pages[0]['items'][0]['kind']=None
    if mode=='null-item-version':pages[0]['items'][0]['apiVersion']=None
    if mode=='duplicate-hook':pages[0]['items'][0]['webhooks']*=2
    if mode=='wrong-kind':pages[0]['kind']='PodList'
    if mode=='duplicate':pages=[page([config(),config()])]
    if mode=='terminal-count':pages[0]['metadata']['remainingItemCount']=1
    if mode=='missing-version':pages[0]['metadata'].pop('resourceVersion')
    class Opener:
        def open(self,request,timeout):
            wire.append(request)
            assert request.method=='GET' and urlsplit(request.full_url).path==native.PATH
            assert urlsplit(request.full_url).netloc==urlsplit(ENDPOINT).netloc
            assert 0<timeout<=15
            if mode=='denied':
                from urllib.error import HTTPError
                raise HTTPError(request.full_url,403,'denied',{},None)
            return Response(request.full_url,pages[min(len(wire)-1,len(pages)-1)])
    def build(*handlers):
        import ssl
        from urllib.request import ProxyHandler,HTTPSHandler
        assert any(isinstance(h,ProxyHandler)and h.proxies=={}for h in handlers)
        handler=next(h for h in handlers if isinstance(h,HTTPSHandler))
        assert handler._context.check_hostname and handler._context.verify_mode==ssl.CERT_REQUIRED
        assert any(isinstance(h,native.NoRedirect)for h in handlers)
        return Opener()
    monkeypatch.setattr(native,'build_opener',build)


def capture(monkeypatch,ca,mode='good',public=False,limits=None):
    session=boto3.Session(aws_access_key_id='INERTACCESS',aws_secret_access_key='INERTSECRET',aws_session_token='INERTSESSION',region_name=R)
    wire=[];setup_transport(monkeypatch,mode,wire)
    opts={'regions':[R],'retry_attempts':1,'service_concurrency':1,'compliance_policy':{'eks_image_integrity':policy()},**(limits or{})}
    with ExitStack()as stack:
        original=session.client;clients={};stubs={}
        def client(service,**kwargs):
            if service not in clients:
                clients[service]=original(service,region_name=R);stubs[service]=stack.enter_context(Stubber(clients[service]))
            return clients[service]
        monkeypatch.setattr(session,'client',client);client('eks')
        response=detail(ca)
        if mode=='foreign-arn':response['cluster']['arn']=ARN.replace(A,'999999999999')
        if mode=='private':response['cluster']['resourcesVpcConfig']['endpointPublicAccess']=False
        if mode=='endpoint-userinfo':response['cluster']['endpoint']=ENDPOINT.replace('https://','https://user@')
        if mode=='foreign-endpoint':response['cluster']['endpoint']=ENDPOINT.replace('us-east-1','eu-west-1')
        if public:
            client('sts');stubs['sts'].add_response('get_caller_identity',{'Account':A,'Arn':f'arn:aws:iam::{A}:user/inert','UserId':'INERT'}, {})
            stubs['eks'].add_response('list_clusters',{'clusters':['owned']},{})
        stubs['eks'].add_response('describe_cluster',response,{'name':'owned'})
        monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'explicit-inert-test'))
        if public:
            opts['inventories']=['eks_cluster','k8s_admission_policy']
            snapshot=collect_snapshot({'connector':{'provider':'aws','scopes':[A],'auth':{},'options':opts},'checks':[CHECK]})
        else:
            req=aws.Requests(opts);req.eks_admission_policy=policy()
            read=native.collect(req,session,R,A)
            cluster={'name':'owned','Cluster':{**response,'collection_status':'collected'}}
            snapshot=make_snapshot('aws',[S],[{'type':'eks_cluster','scope':S,'status':'collected','items':[cluster]},
                {'type':'k8s_admission_policy','scope':S,'status':read.status,'items':read.items}],metadata={'compliance_policy':{'eks_image_integrity':policy()}})
        report=evaluate_snapshot(snapshot,checks=[CHECK],include_not_applicable=True)
        for stub in stubs.values():stub.assert_no_pending_responses()
    encoded=json.dumps(snapshot)
    assert 'INERTACCESS'not in encoded and'INERTSESSION'not in encoded and'NEVER-PERSIST'not in encoded
    assert 'k8s-aws-v1.'not in encoded and'BEGIN CERTIFICATE'not in encoded
    return snapshot,report,wire

@pytest.mark.parametrize('mode,wanted',[('good','PASS'),('empty','FAIL'),('ignore','FAIL'),('url','FAIL'),('scoped','FAIL'),('unrelated-url','PASS'),('paged','PASS')])
def test_native_complete_list_signed_routing_verdict(monkeypatch,ca,mode,wanted):
    _,report,wire=capture(monkeypatch,ca,mode)
    assert {f['status']for f in report['findings']if f['check_id']==CHECK}=={wanted}
    assert wire


def test_actual_public_collect_and_session_local_presign(monkeypatch,ca):
    _,report,wire=capture(monkeypatch,ca,public=True)
    assert {f['status']for f in report['findings']if f['check_id']==CHECK}=={'PASS'}
    token=wire[0].headers['Authorization'].split(' ',1)[1];encoded=token.split('.',1)[1]
    url=base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)).decode();query=parse_qs(urlsplit(url).query)
    assert urlsplit(url).netloc=='sts.us-east-1.amazonaws.com'
    assert query['Action']==['GetCallerIdentity'] and query['X-Amz-SignedHeaders']==['host;x-k8s-aws-id']
    assert query['X-Amz-Expires']==['60']

@pytest.mark.parametrize('mode',['denied','private','foreign-arn','endpoint-userinfo','foreign-endpoint','wrong-kind','duplicate','terminal-count','missing-version','repeated','page-limit'])
def test_native_unsupported_or_incomplete_remains_unknown(monkeypatch,ca,mode):
    _,report,_=capture(monkeypatch,ca,mode,limits={'max_pages':1}if mode=='page-limit'else None)
    assert {f['status']for f in report['findings']if f['check_id']==CHECK}=={'UNKNOWN'}


def test_missing_scope_policy_never_reads_or_gets_credentials():
    class Session:
        def __getattr__(self,name):raise AssertionError('No operation allowed without opt-in')
    result=native.collect(aws.Requests({}),Session(),R,A)
    assert result.status=='not_collected'

@pytest.mark.parametrize('scopes,regions,valid',[([A],[R],True),([S],[],True),([A],[],False),([A],['eu-west-1'],False),(['999999999999'],[R],False)])
def test_owner_scope_accounts_plus_explicit_region_or_exact_pair(scopes,regions,valid):
    opts={'compliance_policy':{'eks_image_integrity':policy()},'regions':regions}
    if valid:assert native.normalize(opts,scopes)==policy()
    else:
        with pytest.raises(ValueError):native.normalize(opts,scopes)

@pytest.mark.parametrize('mode,limits,expected_requests',[
    ('good',{'max_calls':1},0),('unrelated-url',{'max_resources':1},1)])
def test_existing_shared_call_and_resource_caps_stop_incomplete_reads(monkeypatch,ca,mode,limits,expected_requests):
    _,report,wire=capture(monkeypatch,ca,mode,limits=limits)
    assert len(wire)==expected_requests
    assert {f['status']for f in report['findings']if f['check_id']==CHECK}=={'UNKNOWN'}


def test_cancelled_shared_budget_refuses_native_http_before_call():
    from threading import Event
    event=Event();event.set();requests=aws.Requests({'cancel_event':event})
    with pytest.raises(aws.ReadFailure):native.Budget(requests).charge()
    assert requests.calls==0

@pytest.mark.parametrize('mode',['local','cognito'])
def test_actual_typed_hosted_and_local_namespace_acceptance(mode):
    from types import SimpleNamespace
    from peaso.server.validation import validate_connector
    opts={'regions':[R],'compliance_policy':{'eks_image_integrity':policy()}}
    auth={'method':'assume_role','role_arn':f'arn:aws:iam::{A}:role/inert-readonly'}
    before=deepcopy(opts);validate_connector('aws',auth,opts,SimpleNamespace(auth_mode=mode))
    assert opts==before


def test_namespace_wrong_provider_and_extra_observations_rejected():
    from types import SimpleNamespace
    from fastapi import HTTPException
    from peaso.server.validation import validate_connector
    opts={'compliance_policy':{'eks_image_integrity':policy()}}
    with pytest.raises(HTTPException)as e:validate_connector('azure',{},opts,SimpleNamespace(auth_mode='local'))
    assert e.value.status_code==422
    opts['compliance_policy']['eks_image_integrity']['observed_webhooks']=[]
    with pytest.raises(HTTPException)as e:validate_connector('aws',{},opts,SimpleNamespace(auth_mode='local'))
    assert e.value.status_code==422


def test_native_redirect_handler_never_follows_or_exports_auth():
    from urllib.request import Request
    request=Request(ENDPOINT+native.PATH,headers={'Authorization':'Bearer INERT'})
    assert native.NoRedirect().redirect_request(request,None,302,'redirect',{},'https://other.invalid/')is None


@pytest.mark.parametrize('mode',['null-item-kind','null-item-version','duplicate-hook'])
def test_native_item_metadata_null_or_duplicate_hook_is_unknown(monkeypatch,ca,mode):
    _,report,_=capture(monkeypatch,ca,mode)
    assert {f['status']for f in report['findings']if f['check_id']==CHECK}=={'UNKNOWN'}
