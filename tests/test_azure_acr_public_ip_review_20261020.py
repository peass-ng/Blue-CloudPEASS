"""Independent finite ARM responses -> actual collector -> public engine."""
from copy import deepcopy
from dataclasses import replace
import json
import socket
from urllib.parse import parse_qs, urlsplit
import pytest
from peaso.checks import CHECKS
from peaso.checks import azure_acr_public_ip_review_20261020 as review
from peaso.collectors import azure
from peaso.collectors import azure_acr_public_ip_review_20261020 as native
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import validate

SUB = '11111111-1111-1111-1111-111111111111'
TENANT = '22222222-2222-2222-2222-222222222222'
SCOPE = '/subscriptions/'+SUB
RID = SCOPE+'/resourceGroups/native-acr/providers/Microsoft.ContainerRegistry/registries/nativeregistry'
FOREIGN = RID.replace(SUB, '99999999-9999-9999-9999-999999999999')


@pytest.fixture(autouse=True)
def no_live(monkeypatch):
    attempts = []
    def blocked(*args, **kwargs):
        attempts.append('live socket/DNS/auth');raise AssertionError('ACR metadata review forbids live IO')
    for name in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex','gethostbyaddr','getnameinfo'):
        monkeypatch.setattr(socket,name,blocked)
    for name in ('connect','connect_ex','sendto'):
        monkeypatch.setattr(socket.socket,name,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure,'AzureTransport',blocked)
    yield
    assert not attempts, attempts


def registry(values=('203.0.113.0/24',), default='Deny', pna='Enabled', bypass='None', rid=RID):
    return {'id':rid,'name':rid.rsplit('/',1)[-1],'type':'Microsoft.ContainerRegistry/registries','location':'eastus',
            'sku':{'name':'Premium'},'properties':{'provisioningState':'Succeeded','publicNetworkAccess':pna,
             'networkRuleBypassOptions':bypass,'networkRuleSet':{'defaultAction':default,
              'ipRules':[{'action':'Allow','value':v} for v in values],'virtualNetworkRules':[]}}}


class NativeHTTP:
    tenant = verified_tenant = TENANT
    def __init__(self, detail=None, *, mode='normal', discovery=None):
        self.detail = registry() if detail is None else detail
        self.discovery = [registry()] if discovery is None else discovery
        self.mode, self.calls, self.errors = mode, [], []
    def request(self, url, *, body=None, audience=azure.ARM):
        p=urlsplit(url);q=parse_qs(p.query);method='POST' if body is not None else 'GET'
        self.calls.append({'method':method,'url':url,'body':deepcopy(body)})
        try:
            assert p.scheme=='https' and p.netloc=='management.azure.com' and not p.fragment and audience==azure.ARM
            if p.path=='/providers/Microsoft.ResourceGraph/resources':
                assert method=='POST' and q=={'api-version':['2022-10-01']} and body['subscriptions']==[SUB]
                return {'data':deepcopy(self.discovery)}
            assert method=='GET'
            if p.path==SCOPE+'/resources':
                assert q=={'api-version':['2021-04-01']};return {'value':deepcopy(self.discovery)}
            if p.path==SCOPE+'/providers/Microsoft.ContainerRegistry/registries':
                assert q.get('api-version')==['2023-07-01']
                if self.mode=='list-denied':raise azure.AzureReadError('forbidden',403)
                if q.get('page')==['2']:raise azure.AzureReadError('forbidden',403)
                result={'value':deepcopy(self.discovery)}
                if self.mode=='partial':result['nextLink']=azure.ARM+p.path+'?api-version=2023-07-01&page=2'
                return result
            ids={row['id'] for row in self.discovery if isinstance(row,dict) and isinstance(row.get('id'),str)}
            if p.path in ids:
                assert q=={'api-version':['2023-07-01']} or q=={'api-version':['2023-11-01-preview']}
                if self.mode=='denied':raise azure.AzureReadError('forbidden',403)
                if self.mode=='deleted':raise azure.AzureReadError('not_found',404)
                if self.mode=='malformed-get':return [42]
                if self.mode=='error-body':raise ValueError('PRIVATE_RESPONSE_BODY_DO_NOT_EXPORT')
                return deepcopy(self.detail)
            for rid in ids:
                if p.path in {rid+'/'+s for s in ('replications','tokens','scopeMaps','cacheRules')}:
                    assert q=={'api-version':['2023-07-01']};return {'value':[]}
                if p.path==rid+'/providers/Microsoft.Insights/diagnosticSettings':
                    assert q=={'api-version':['2021-05-01-preview']};return {'value':[]}
            raise AssertionError('Unexpected native route '+p.path)
        except azure.AzureReadError:raise
        except AssertionError as exc:self.errors.append(str(exc));raise


def run(record_property, detail=None, *, mode='normal', discovery=None, options=None):
    api=NativeHTTP(detail,mode=mode,discovery=discovery)
    dependencies=next(c.dependencies for c in CHECKS if c.id==review.CHECK)
    snap=azure.collect({'provider':'azure','scopes':[SUB],'options':{'concurrency':1,'retries':0,**(options or {})}},dependencies,transport=api)
    assert not api.errors,api.errors
    assert validate(snap)==snap
    before=deepcopy(snap)
    out=evaluate_snapshot(snap,checks=[review.CHECK],include_not_applicable=True)
    rows=[r for r in out['findings'] if r['check_id']==review.CHECK];assert rows
    assert before==snap
    record_property('native_receipt',json.dumps({'mode':mode,'calls':api.calls,'statuses':[r['status'] for r in rows],
                    'evidence':[r['evidence'] for r in rows],'envelopes':[{k:c[k] for k in ('type','scope','status')} for c in snap['collections']]},sort_keys=True))
    return snap,rows,api


@pytest.mark.parametrize('pna',['Enabled','Disabled'])
@pytest.mark.parametrize('bypass',['None','AzureServices'])
@pytest.mark.parametrize('default',['Allow','Deny'])
@pytest.mark.parametrize('values',[
    [],['203.0.113.1'],['203.0.113.0/24'],['0.0.0.0/0'],['203.0.113.1/0'],
    ['0.0.0.0/1','128.0.0.0/1'],['128.0.0.0/1','0.0.0.0/2','64.0.0.0/2'],
    ['0.0.0.0/1','128.0.0.0/2'],['203.0.113.0/24','203.0.113.0/24']])
def test_native_declared_ipv4_union(pna,bypass,default,values,record_property):
    _,rows,_=run(record_property,registry(values,default,pna,bypass))
    all_ips=any('/0' in v for v in values) or set(values)=={'0.0.0.0/1','128.0.0.0/1'} or len(values)==3 and '128.0.0.0/1' in values
    expected='FAIL' if pna=='Enabled' and (default=='Allow' or all_ips) else 'PASS'
    assert {r['status'] for r in rows}=={expected},rows
    assert all(r['evidence']['trusted_service_bypass']==bypass for r in rows)


@pytest.mark.parametrize('path,value',[
    ('properties.publicNetworkAccess','unknown'),('properties.publicNetworkAccess',None),
    ('properties.networkRuleBypassOptions','all'),('properties.networkRuleBypassOptions',None),
    ('properties.provisioningState','Updating'),('properties.networkRuleSet',None),
    ('properties.networkRuleSet.defaultAction','unknown'),('properties.networkRuleSet.ipRules',None),
    ('properties.networkRuleSet.ipRules',{}),('properties.networkRuleSet.ipRules',[42]),
    ('properties.networkRuleSet.ipRules',[{'action':'Deny','value':'0.0.0.0/0'}]),
    *[('properties.networkRuleSet.ipRules',[{'action':'Allow','value':v}]) for v in
      ('::/0','0:0:0:0:0:0:0:0/0','example.com','https://example.com',' 0.0.0.0/0','01.2.3.4','1.2.3.4/255.255.255.0','1.2.3.4/33',42,'')]])
def test_native_malformed_or_unsupported_never_passes(path,value,record_property):
    obj=registry();target=obj;parts=path.split('.')
    for p in parts[:-1]:target=target[p]
    target[parts[-1]]=value
    _,rows,_=run(record_property,obj)
    assert {r['status'] for r in rows}<={'UNKNOWN','DENIED'},rows


@pytest.mark.parametrize('path',['properties.publicNetworkAccess','properties.networkRuleBypassOptions','properties.provisioningState',
                                 'properties.networkRuleSet','properties.networkRuleSet.defaultAction','properties.networkRuleSet.ipRules'])
def test_native_omitted_fields_do_not_invent_defaults(path,record_property):
    obj=registry();target=obj;parts=path.split('.')
    for p in parts[:-1]:target=target[p]
    target.pop(parts[-1]);_,rows,_=run(record_property,obj)
    assert {r['status'] for r in rows}=={'UNKNOWN'},rows


@pytest.mark.parametrize('mode',['denied','deleted','list-denied','partial','malformed-get','error-body'])
def test_native_unreadable_or_partial_never_clean(mode,record_property):
    snap,rows,_=run(record_property,mode=mode)
    assert {r['status'] for r in rows}<={'UNKNOWN','DENIED'},rows
    if mode=='partial':assert any(c['status']=='partial' for c in snap['collections'])
    assert 'PRIVATE_RESPONSE_BODY_DO_NOT_EXPORT' not in json.dumps([snap,rows])


@pytest.mark.parametrize('field,value',[('id',FOREIGN),('id',RID+'/tokens/child'),('type','Microsoft.Storage/storageAccounts'),
                                        ('name','otherregistry'),('properties',None)])
def test_native_get_identity_and_representation_binding(field,value,record_property):
    obj=registry();obj[field]=value;_,rows,_=run(record_property,obj)
    assert {r['status'] for r in rows}=={'UNKNOWN'},rows


def test_native_foreign_discovery_never_gets_requested(record_property):
    _,rows,api=run(record_property,discovery=[registry(rid=FOREIGN)])
    assert {r['status'] for r in rows}<={'UNKNOWN','DENIED'},rows
    assert not any(FOREIGN in c['url'] for c in api.calls)


def test_native_wrong_parent_type_does_not_authorize_registry_get(record_property):
    obj=registry();obj['type']='Microsoft.Storage/storageAccounts'
    _,rows,api=run(record_property,discovery=[obj])
    assert {r['status'] for r in rows}=={'UNKNOWN'},rows
    assert not any(c['url']==azure.ARM+RID+'?api-version=2023-07-01' for c in api.calls)


@pytest.mark.parametrize('options',[{'max_calls':1},{'max_calls':6},{'collection_deadline_seconds':0.0000001},
                                  {'_cancel_check':lambda:True}])
def test_native_bounds_and_cancellation_never_become_compliance(options,record_property):
    _,rows,_=run(record_property,options=options)
    assert {r['status'] for r in rows}<={'UNKNOWN','DENIED'},rows


def test_native_empty_inventory_is_absence_not_compliance(record_property):
    _,rows,_=run(record_property,discovery=[])
    assert {r['status'] for r in rows}<={'EMPTY','NOT_APPLICABLE','UNKNOWN'},rows


@pytest.mark.parametrize('count',[200,201])
def test_native_ip_rule_bound(count,record_property):
    _,rows,_=run(record_property,registry(['203.0.113.1']*count))
    assert {r['status'] for r in rows}==({'PASS'} if count==200 else {'UNKNOWN'}),rows


@pytest.mark.parametrize('bypass',['None','AzureServices'])
def test_native_explicit_default_allow_fails_without_optional_rules(bypass,record_property):
    obj=registry(default='Allow',bypass=bypass);obj['properties']['networkRuleSet'].pop('ipRules')
    _,rows,_=run(record_property,obj)
    assert {r['status'] for r in rows}=={'FAIL'},rows
    assert all('declared_ip_rules' not in row['evidence'] for row in rows)


def test_dependency_selection_is_narrow(record_property):
    assert native.required_types({native.KIND})=={'container_registry'}
    assert native.required_types({'container_registry'})==set()
    assert native.KIND in plan_collection({'provider':'azure','scopes':[SUB],'checks':[review.CHECK]})
    assert native.KIND not in plan_collection({'provider':'azure','scopes':[SUB],'checks':['azure.claude.acr_network_default_deny']})
    api=NativeHTTP();snap=azure.collect({'provider':'azure','scopes':[SUB],'options':{'concurrency':1,'retries':0}},['container_registry'],transport=api)
    assert not api.errors and not any(c['type']==native.KIND for c in snap['collections'])
    assert not any(c['url']==azure.ARM+RID+'?api-version=2023-07-01' for c in api.calls)


@pytest.mark.parametrize('change',['marker','scope','request','duplicate','parent','missing-item','status','credential','customer',
                                  'numeric-complete','write-proof','operation','version'])
def test_pure_consumer_rejects_unbound_native_capture(change,record_property,monkeypatch):
    from peaso import engine
    captured=[];original=next(c for c in CHECKS if c.id==review.CHECK)
    def capture(item,index):
        captured.append({'item':deepcopy(item),'index':deepcopy(index)})
        return original.evaluate(item,index)
    monkeypatch.setattr(engine,'_registry',lambda:[replace(c,evaluate=capture) if c.id==review.CHECK else c for c in CHECKS])
    run(record_property);assert len(captured)==1
    data=captured[0];own=data['index']['collections'][native.KIND][0];row=own['items'][0]
    if change=='marker':row.pop(native.MARKER)
    elif change=='scope':row[native.MARKER]['scope']='/subscriptions/foreign'
    elif change=='request':row[native.MARKER]['request_uri']='https://evil.example/registry'
    elif change=='duplicate':own['items'].append(deepcopy(row))
    elif change=='parent':row['parent_id']=FOREIGN
    elif change=='missing-item':own['items']=[]
    elif change in ('credential','customer'):row['_provenance'][change+'_context_id']='foreign-capture'
    elif change=='numeric-complete':row[native.MARKER]['complete']=1
    elif change=='write-proof':row['_provenance']['read_only']=False
    elif change=='operation':row['_provenance']['source_operation']='Registries_Update'
    elif change=='version':row['_provenance']['api_version']='unknown'
    else:own['status']='partial'
    status,_=original.evaluate(data['item'],data['index']);assert status=='UNKNOWN'


@pytest.mark.parametrize('mode',['pass','fail','unknown'])
def test_native_fixture_capture(mode,record_property,monkeypatch):
    from peaso import engine
    original=next(c for c in CHECKS if c.id==review.CHECK);captured=[]
    def capture(item,index):
        status,evidence=original.evaluate(item,index)
        captured.append({'item':deepcopy(item),'index':deepcopy(index),'status':status,'evidence':deepcopy(evidence)})
        return status,evidence
    monkeypatch.setattr(engine,'_registry',lambda:[replace(c,evaluate=capture) if c.id==review.CHECK else c for c in CHECKS])
    obj=registry(['0.0.0.0/1','128.0.0.0/1'] if mode=='fail' else ['203.0.113.0/24'])
    if mode=='unknown':obj['properties'].pop('networkRuleBypassOptions')
    run(record_property,obj);assert len(captured)==1
    assert captured[0]['status']=={'pass':'PASS','fail':'FAIL','unknown':'UNKNOWN'}[mode]
    record_property('native_fixture',json.dumps({'mode':mode,**captured[0]},sort_keys=True))


def test_native_captured_fixture_replay_is_pure():
    from pathlib import Path
    fixtures=json.loads(Path('peaso/checks/azure_acr_public_ip_review_20261020_fixtures.json').read_text())[review.CHECK]
    fn=next(c.evaluate for c in CHECKS if c.id==review.CHECK)
    for mode,expected in [('pass','PASS'),('fail','FAIL'),('unknown','UNKNOWN')]:
        item,index=deepcopy(fixtures[mode]),deepcopy(fixtures[mode+'_index']);before=deepcopy((item,index))
        assert fn(item,index)[0]==expected
        assert before==(item,index)


def test_registered_public_metadata_and_native_dependencies():
    matches=[c for c in CHECKS if c.id==review.CHECK];assert len(matches)==1
    check=matches[0];public=check.public()
    assert check.category=='network' and check.kind=='container_registry'
    assert public['severity']=='medium' and public['finding_type']=='network'
    assert public['dependencies']==['container_registry',native.KIND]
    assert public['requirement_controls']==[]


def test_native_case_insensitive_arm_identity_is_bound(record_property):
    obj=registry();obj['id']=RID.upper();obj['type']=obj['type'].upper();obj['name']=obj['name'].upper()
    _,rows,_=run(record_property,obj)
    assert {r['status'] for r in rows}=={'PASS'},rows


@pytest.mark.parametrize('value',[FOREIGN,RID+'/tokens/child',RID.replace('native-acr','..'),
                                RID.replace('native-acr','bad\x00group'),RID.replace('native-acr','bad\x7fgroup'),
                                RID.replace('native-acr','bad%2fgroup'),'https://evil.example/registry'])
def test_native_identity_validator_rejects_non_resource_routes(value):
    with pytest.raises(ValueError):native.registry_id(value,SCOPE)
