"""Independent native ARM HTTP -> existing collector -> proposed SAS predicate."""
from copy import deepcopy
import socket
import base64,json,time
import pytest
from peaso.collectors import azure
from peaso import engine
from peaso.checks import azure_sas_expiry_policy_declaration_proposal_20261020 as candidate
from tests.test_azure_storage_native_review_20261020 import NativeHTTP,SUB,SCOPE,ACCOUNT

MISSING=object()

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):raise AssertionError('No actual network/auth in SAS native proof')
    monkeypatch.setattr(socket,'create_connection',blocked)
    monkeypatch.setattr(socket,'getaddrinfo',blocked)
    monkeypatch.setattr(socket.socket,'connect',blocked)
    monkeypatch.setattr(socket.socket,'connect_ex',blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)


def capture(monkeypatch,policy=MISSING,mode='positive'):
    def mutate(http):
        if policy is not MISSING:http.a['properties']['sasPolicy']=deepcopy(policy)
    http=NativeHTTP('azure.storage.https_only',mode,mutate)
    monkeypatch.setattr(azure,'build_opener',lambda *args:http)
    claims={'tid':'22222222-2222-2222-2222-222222222222','aud':azure.ARM,'exp':int(time.time())+3600}
    token='eyJhbGciOiJub25lIn0.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.inert'
    connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':token,'storage_token':'fixture-inert','tenant_id':claims['tid']},'options':{'concurrency':1,'retries':0}}
    snapshot=azure.collect(connector,['storage_account'])
    http.snapshot=snapshot
    index=engine._index(snapshot,list(engine.resources(snapshot)))
    index['context']={'provider':'azure','scope':SCOPE,'created_at':snapshot['created_at'],'metadata':snapshot['metadata']}
    rows=[r for collection in snapshot['collections']if collection['type']=='storage_account'for r in collection['items']if r.get('id')==ACCOUNT]
    assert not http.unexpected,http.unexpected
    assert all(r['method']=='GET' or r['path']=='/providers/Microsoft.ResourceGraph/resources'for r in http.calls)
    return rows[0]if rows else {},index,http


@pytest.mark.parametrize('policy,status',[
    ({'sasExpirationPeriod':'0.01:00:00','expirationAction':'Block'},'PASS'),
    ({'sasExpirationPeriod':'3.00:00:00','expirationAction':'Block'},'PASS'),
    ({'sasExpirationPeriod':'7.00:00:00','expirationAction':'Block'},'PASS'),
    ({'sasExpirationPeriod':'0.01:00:00','expirationAction':'Log'},'FAIL'),
    ({'sasExpirationPeriod':'0.01:00:00'},'FAIL'),
    (MISSING,'FAIL'),(None,'FAIL'),
    ({'sasExpirationPeriod':'0.00:00:00','expirationAction':'Block'},'UNKNOWN'),
    ({'sasExpirationPeriod':'-1.00:00:00','expirationAction':'Block'},'UNKNOWN'),
    ({'sasExpirationPeriod':'0.24:00:00','expirationAction':'Block'},'UNKNOWN'),
    ({'sasExpirationPeriod':'0.01:60:00','expirationAction':'Block'},'UNKNOWN'),
    ({'sasExpirationPeriod':'0.01:00:60','expirationAction':'Block'},'UNKNOWN'),
    ({'sasExpirationPeriod':'10675200.00:00:00','expirationAction':'Block'},'UNKNOWN'),
    ({'sasExpirationPeriod':'10675199.23:59:59','expirationAction':'Block'},'UNKNOWN'),
    ({'sasExpirationPeriod':'10675199.02:48:05','expirationAction':'Block'},'PASS'),
    ({'sasExpirationPeriod':True,'expirationAction':'Block'},'UNKNOWN'),
    ({'sasExpirationPeriod':'0.01:00:00','expirationAction':'block'},'UNKNOWN'),
    ({'sasExpirationPeriod':'0.01:00:00','expirationAction':None},'UNKNOWN'),
    ({'sasExpirationPeriod':'01:00:00','expirationAction':'Block'},'UNKNOWN'),
    ({},'UNKNOWN'),([], 'UNKNOWN'),
])
def test_native_policy_and_supported_interval(monkeypatch,policy,status):
    item,index,http=capture(monkeypatch,policy)
    actual,evidence=candidate.evaluate(item,index)
    assert actual==status,evidence
    assert evidence['token_issuance_verified'] is False
    assert all('listKeys' not in r['path']and'listAccountSas'not in r['path']for r in http.calls)


@pytest.mark.parametrize('mode',['denied','foreign'])
def test_native_unavailable_or_foreign_parent_not_clean(monkeypatch,mode):
    item,index,_=capture(monkeypatch,{'sasExpirationPeriod':'0.01:00:00','expirationAction':'Block'},mode)
    assert candidate.evaluate(item,index)[0]=='UNKNOWN'


@pytest.mark.parametrize('fault',['representation','version','tenant','capture','scope','inventory','provisioning','policy_coverage'])
def test_authenticated_native_proof_drift_unknown(monkeypatch,fault):
    item,index,_=capture(monkeypatch,{'sasExpirationPeriod':'0.01:00:00','expirationAction':'Block'})
    if fault=='representation':item['_provenance']['representation']='metadata'
    elif fault=='version':item['_provenance']['api_version']='other'
    elif fault=='tenant':index['context']['metadata']['tenant_verified']=False
    elif fault=='capture':item['_provenance']['credential_context_id']='f'*32
    elif fault=='scope':index['context']['scope']='/subscriptions/'+'3'*36
    elif fault=='inventory':index['storage_account']=[]
    elif fault=='provisioning':item['properties']['provisioningState']='Updating'
    else:item['properties']['_coverage']={'sasPolicy':{'status':'denied'}}
    assert candidate.evaluate(item,index)[0]=='UNKNOWN'
