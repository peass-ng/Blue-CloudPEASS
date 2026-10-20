"""Bounded native successors for the accepted storage and subnet regressions.

Responses use the independent reviewed provider fixtures through real urllib
AzureTransport parsing; negative provenance tests remove facts after collection.
No historical CASES or owner policy is used.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
import socket
from urllib.error import HTTPError
from urllib.parse import urlsplit

import pytest
from peaso.collectors import azure, azure_swc
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests import test_azure_storage_native_review_20261020 as storage
from tests import test_azure_compute_network_native_review_20261020 as compute

KEYS = 'azure.claude.storage_access_keys_rotated_90'
VHD = 'azure.claude.storage_vhd_accounts_cmk'
ATTACHED = 'azure.gap.compute_vm_tcp_udp_access_restricted_internet'
REMOTE = 'azure.gap.compute_vm_remote_access_restricted_all_ports'
ANCHOR = datetime(2024, 10, 20, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs): raise AssertionError('Network/DNS/auth forbidden in native fix proofs')
    for name in ('create_connection','getaddrinfo'): monkeypatch.setattr(socket,name,blocked)
    for name in ('connect','connect_ex'): monkeypatch.setattr(socket.socket,name,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)


def captured_clock(monkeypatch):
    import peaso.snapshot as module
    class Fixed(datetime):
        @classmethod
        def now(cls,tz=None): return ANCHOR if tz is not None else ANCHOR.replace(tzinfo=None)
    monkeypatch.setattr(module,'datetime',Fixed)


@pytest.mark.parametrize('age,status', [(timedelta(days=90),'PASS'),(timedelta(days=90,microseconds=1),'FAIL'),
    (timedelta(days=90)-timedelta(microseconds=1),'PASS'),(timedelta(days=89,hours=23),'PASS'),
    (timedelta(days=91),'FAIL'),(timedelta(microseconds=-1),'UNKNOWN')])
def test_native_key_age_capture_exact_boundary(monkeypatch,age,status):
    captured_clock(monkeypatch)
    def change(api): api.a['properties']['keyCreationTime']={'key1':(ANCHOR-age).isoformat(),'key2':(ANCHOR-timedelta(days=1)).isoformat()}
    fs,_,_=storage.capture(monkeypatch,KEYS,mutate=change)
    assert {f['status']for f in fs}=={status},fs
    if status!='UNKNOWN':
        ev=fs[0]['evidence'];assert ev['threshold_seconds']==90*86400
        assert ev['key_age_seconds']['key1']==age.total_seconds()
        assert datetime.fromisoformat(ev['captured_at'])==ANCHOR and ev['time_source']=='scan_capture'
        assert ev['key_creation_time']['key1']==(ANCHOR-age).isoformat()


@pytest.mark.parametrize('variant',['missing-key1','missing-key2','empty','not-a-time','naive','null','boolean','future-key2','malformed-parent'])
def test_native_incomplete_key_pair_never_clean(monkeypatch,variant):
    captured_clock(monkeypatch)
    def change(api):
        times={'key1':(ANCHOR-timedelta(days=1)).isoformat(),'key2':(ANCHOR-timedelta(days=2)).isoformat()}
        if variant.startswith('missing-'):times.pop(variant[8:])
        if variant=='empty':times={}
        if variant=='not-a-time':times['key1']='not-a-time'
        if variant=='naive':times['key1']='2024-10-19T00:00:00'
        if variant=='null':times['key2']=None
        if variant=='boolean':times['key1']=True
        if variant=='future-key2':times['key2']=(ANCHOR+timedelta(seconds=1)).isoformat()
        if variant=='malformed-parent':times=[]
        api.a['properties']['keyCreationTime']=times
    fs,_,_=storage.capture(monkeypatch,KEYS,mutate=change)
    assert {f['status']for f in fs}=={'UNKNOWN'},fs


@pytest.mark.parametrize('variant,status', [('https443','PASS'),('cmk-platform','FAIL'),('foreign-host','UNKNOWN'),
 ('userinfo','UNKNOWN'),('port','UNKNOWN'),('foreign-endpoint','UNKNOWN'),('endpoint-userinfo','UNKNOWN'),
 ('endpoint-query','UNKNOWN'),('dns-zone','UNKNOWN'),('account-name-mismatch','UNKNOWN'),
 ('foreign-vm','UNKNOWN'),('managed-and-vhd','UNKNOWN')])
def test_native_vhd_exact_account_origin(monkeypatch,variant,status):
    def change(api):
        disk=api.vm['properties']['storageProfile']['osDisk']
        if variant=='https443':disk['vhd']['uri']='https://account.blob.core.windows.net:443/vhds/os.vhd'
        if variant=='cmk-platform':api.a['properties']['encryption']['keySource']='Microsoft.Storage'
        if variant=='foreign-host':disk['vhd']['uri']='https://account.evil.invalid/vhds/os.vhd'
        if variant=='userinfo':disk['vhd']['uri']='https://user@account.blob.core.windows.net/vhds/os.vhd'
        if variant=='port':disk['vhd']['uri']='https://account.blob.core.windows.net:8443/vhds/os.vhd'
        if variant=='foreign-endpoint':api.a['properties']['primaryEndpoints']['blob']='https://foreign.blob.core.windows.net/'
        if variant=='endpoint-userinfo':api.a['properties']['primaryEndpoints']['blob']='https://user@account.blob.core.windows.net/'
        if variant=='endpoint-query':api.a['properties']['primaryEndpoints']['blob']='https://account.blob.core.windows.net/?token=opaque'
        if variant=='dns-zone':api.a['properties']['primaryEndpoints']['blob']='https://account.z99.blob.storage.azure.net/'
        if variant=='account-name-mismatch':api.a['name']='foreign'
        if variant=='foreign-vm':api.vm['id']=api.vm['id'].replace(storage.SUB,'99999999-9999-9999-9999-999999999999')
        if variant=='managed-and-vhd':disk['managedDisk']={'id':storage.RG+'/providers/Microsoft.Compute/disks/os'}
    fs,_,_=storage.capture(monkeypatch,VHD,mutate=change)
    assert {f['status']for f in fs}=={status},fs


@pytest.mark.parametrize('variant',['wrong-provider','malformed-uuid','dot-segment'])
def test_storage_service_router_rejects_nonliteral_native_parent(monkeypatch,variant):
    _,snapshot,_=storage.capture(monkeypatch,storage.CHILD_PORTS[0])
    assert azure_swc.authorized_storage_service_scopes(snapshot,storage.SCOPE)
    scope=storage.SCOPE
    old,new=('Microsoft.Storage','MicrosoftXStorage')if variant=='wrong-provider'else(storage.SUB,'1'*36)if variant=='malformed-uuid'else('/resourceGroups/rg/','/resourceGroups/../')
    data=json.loads(json.dumps(snapshot).replace(old,new));scope=scope.replace(old,new)
    assert not azure_swc.authorized_storage_service_scopes(data,scope)


class _HTTP200(io.BytesIO):
    status = 200


class ComputeHTTP:
    def __init__(self,api,variant):self.api,self.variant=api,variant
    def open(self,request,timeout):
        assert timeout==20 and request.get_method()in('GET','POST')
        assert urlsplit(request.full_url).netloc=='management.azure.com'
        path=urlsplit(request.full_url).path
        if path==compute.SUBNET and self.variant=='denied':raise HTTPError(request.full_url,403,'fixture denied',{},io.BytesIO(b'{}'))
        body=json.loads(request.data)if request.data else None
        value=self.api.request(request.full_url,body=body,audience=azure.ARM)
        if path==compute.SUBNET:
            if self.variant=='missing':value.pop('properties')
            if self.variant=='foreign-id':value['id']=value['id'].replace(compute.SUB,'99999999-9999-9999-9999-999999999999')
            if self.variant=='wrong-type':value['type']='Microsoft.Network/virtualNetworks/virtualNetworkPeerings'
        return _HTTP200(json.dumps(value).encode())


def compute_capture(monkeypatch,cid=ATTACHED,variant='good',mutate=None):
    objects,children=compute.native_case(cid,variant=='bad')
    vnet=next(r for r in objects if r['id']==compute.VNET)
    if variant=='duplicate-declaration':vnet['properties']['subnets']*=2
    if variant=='foreign-reference':vnet['properties']['subnets'][0]['id']=compute.SUBNET.replace('/native-vnet/','/sibling/')
    if mutate:mutate(objects,children)
    api=compute.NativeARM(objects,children,cid,'good')
    wire=ComputeHTTP(api,variant);monkeypatch.setattr(azure,'build_opener',lambda *a:wire)
    snapshot=azure.collect({'provider':'azure','scopes':[compute.SUB],'auth':{'method':'token','arm_token':'fixture-inert'},'options':{'concurrency':1,'retries':0}},list(compute.REGISTRY[cid].dependencies))
    assert not api.errors,api.errors
    rows=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)['findings']
    return rows,snapshot,api


@pytest.mark.parametrize('variant,status',[('good','PASS'),('denied','UNKNOWN'),('missing','UNKNOWN'),
 ('foreign-id','UNKNOWN'),('wrong-type','UNKNOWN'),('duplicate-declaration','UNKNOWN'),('foreign-reference','UNKNOWN')])
def test_native_subnet_default_scoped_join(monkeypatch,variant,status):
    rows,_,_=compute_capture(monkeypatch,variant=variant)
    assert {f['status']for f in rows}=={status},rows


@pytest.mark.parametrize('target',['vnet','subnet'])
@pytest.mark.parametrize('field',['representation','source_operation','api_version','read_only'])
def test_subnet_join_requires_actual_producer_provenance(monkeypatch,target,field):
    _,s,_=compute_capture(monkeypatch)
    assert azure_swc.authorized_subnet_scopes(s,compute.SCOPE)=={compute.VNET}
    native=next(c for c in s['collections']if c['type']==target)
    native['items'][0]['_provenance'].pop(field)
    s=make_snapshot('azure',s['scopes'],s['collections'],created_at=s['created_at'],metadata=s['metadata'])
    assert not azure_swc.authorized_subnet_scopes(s,compute.SCOPE)
    rows=evaluate_snapshot(s,checks=[ATTACHED])['findings']
    assert {f['status']for f in rows}=={'UNKNOWN'},rows


def test_sibling_subnet_collection_cannot_supply_declared_parent(monkeypatch):
    _,s,_=compute_capture(monkeypatch)
    child=next(c for c in s['collections']if c['type']=='subnet')
    child['scope']=compute.VNET+'-sibling'
    child['items'][0]['id']=compute.SUBNET.replace('/native-vnet/','/native-vnet-sibling/')
    s=make_snapshot('azure',s['scopes'],s['collections'],created_at=s['created_at'],metadata=s['metadata'])
    assert not azure_swc.authorized_subnet_scopes(s,compute.SCOPE)
    rows=evaluate_snapshot(s,checks=[ATTACHED])['findings']
    assert {f['status']for f in rows}=={'UNKNOWN'},rows

@pytest.mark.parametrize('cid',['azure.storage.https_only','azure.storage.blob_versioning',storage.CHILD_PORTS[0]])
def test_native_type_case_alias_is_not_a_contradiction(monkeypatch,cid):
    def change(api):
        api.a['type']=api.a['type'].upper()
        api.blob['type']=api.blob['type'].upper()
        api.file['type']=api.file['type'].upper()
    fs,_,_=storage.capture(monkeypatch,cid,mutate=change)
    assert {f['status']for f in fs}=={'PASS'},fs


def test_native_sibling_subscription_subnet_denial_is_isolated(monkeypatch):
    rows,first,_=compute_capture(monkeypatch)
    assert {f['status']for f in rows}=={'PASS'}
    own_scope=compute.SCOPE;own_vm=compute.VM
    old_sub=compute.SUB;second_sub='99999999-9999-9999-9999-999999999999'
    with pytest.MonkeyPatch.context()as scoped:
        for name,value in list(vars(compute).items()):
            if name.isupper()and isinstance(value,str)and old_sub in value:
                scoped.setattr(compute,name,value.replace(old_sub,second_sub))
        _,second,_=compute_capture(scoped,variant='denied')
    combined=make_snapshot('azure',[own_scope,'/subscriptions/'+second_sub],first['collections']+second['collections'])
    rows=evaluate_snapshot(combined,checks=[ATTACHED])['findings']
    own=[f for f in rows if f.get('native_resource_id')==own_vm]
    assert own and {f['status']for f in own}=={'PASS'},rows
    assert {f['status']for f in rows if f['scope']=='/subscriptions/'+second_sub}=={'UNKNOWN'},rows

@pytest.mark.parametrize('variant,status',[
 ('default-only','UNKNOWN'),('literal-allow','FAIL'),('wildcard-deny','PASS'),
 ('earlier-unknown-deny','UNKNOWN'),('earlier-unknown-allow','UNKNOWN'),
 ('later-unknown-after-deny','PASS'),('later-unknown-after-allow','FAIL'),
 ('duplicate-priority','UNKNOWN'),('malformed-priority','UNKNOWN'),('malformed-protocol','UNKNOWN'),
 ('restricted-source-deny','FAIL'),('ipv4-only-deny','UNKNOWN'),('restricted-ports','UNKNOWN'),
 ('restricted-protocol','UNKNOWN'),('restricted-destination','UNKNOWN'),
 ('ipv6-allow','FAIL'),('ipv6-wildcard-deny','PASS'),('ipv6-ipv4-only-deny','UNKNOWN'),
 ('ipv4-with-ipv6-allow','UNKNOWN'),('foreign-rule','UNKNOWN'),('unknown-direction','UNKNOWN')])
def test_native_nsg_priority_prefix_proofs(monkeypatch,variant,status):
    def change(objects,children):
        nsg=next(r for r in objects if r['id']==compute.NSG)
        deny=compute.rule('ExplicitDenyAll',priority=300,access='Deny',protocol='*',source='*',port='*')
        allow=compute.rule('ExplicitPublicAllow',priority=200,protocol='*',source='*',port='*')
        unknown=compute.rule('UnsupportedTag',priority=100,access='Deny',protocol='*',source='VirtualNetwork',port='*')
        rules=[]
        if variant in ('literal-allow','later-unknown-after-allow','foreign-rule','ipv6-allow','ipv4-with-ipv6-allow'):rules=[allow]
        elif variant!='default-only':rules=[deny]
        if variant in ('earlier-unknown-deny','earlier-unknown-allow'):
            unknown['properties']['access']='Allow'if variant.endswith('allow')else'Deny';rules=[unknown,allow,deny]
        if variant=='later-unknown-after-deny':unknown['properties']['priority']=400;rules=[deny,unknown]
        if variant=='later-unknown-after-allow':unknown['properties']['priority']=400;rules=[allow,unknown]
        if variant=='duplicate-priority':unknown['properties']['priority']=300;rules=[deny,unknown]
        if variant=='malformed-priority':unknown['properties']['priority']=True;rules=[deny,unknown]
        if variant=='malformed-protocol':unknown['properties']['protocol']='FutureProtocol';rules=[deny,unknown]
        if variant=='unknown-direction':unknown['properties']['direction']='FutureDirection';rules=[deny,unknown]
        if variant=='restricted-source-deny':deny['properties'].update(priority=100,sourceAddressPrefix='10.0.0.0/8');rules=[deny,allow]
        if variant in ('ipv4-only-deny','ipv6-ipv4-only-deny'):deny['properties']['sourceAddressPrefix']='0.0.0.0/0'
        if variant=='restricted-ports':deny['properties']['destinationPortRange']='22'
        if variant=='restricted-protocol':deny['properties']['protocol']='Tcp'
        if variant=='restricted-destination':deny['properties']['destinationAddressPrefix']='10.0.0.4/32'
        if variant in ('ipv6-allow','ipv4-with-ipv6-allow'):allow['properties']['sourceAddressPrefix']='::/0'
        if variant.startswith('ipv6-'):
            nic=next(r for r in objects if r['id']==compute.NIC);nic['properties']['ipConfigurations'][0]['properties']['privateIPAddress']='fd00::4'
            vnet=next(r for r in objects if r['id']==compute.VNET);vnet['properties']['addressSpace']['addressPrefixes']=['fd00::/64'];vnet['properties']['subnets'][0]['properties']['addressPrefix']='fd00::/64'
        if variant=='foreign-rule':allow['id']=allow['id'].replace('/native-nsg/','/foreign-nsg/')
        nsg['properties']['securityRules']=rules
    fs,_,_=compute_capture(monkeypatch,cid=REMOTE,mutate=change)
    assert {f['status']for f in fs}=={status},fs


@pytest.mark.parametrize('target',['nic','subnet'])
@pytest.mark.parametrize('variant',['missing-owner-proof','nested-fake-proof','incomplete-marker','wrong-owner-kind'])
def test_native_omitted_nsg_association_requires_owner_get(monkeypatch,target,variant):
    rows,s,_=compute_capture(monkeypatch,variant='bad')
    assert {f['status']for f in rows}=={'FAIL'},rows
    row=next(c for c in s['collections']if c['type']==target)['items'][0]
    if variant in ('missing-owner-proof','nested-fake-proof'):row.pop('_provenance')
    if variant=='nested-fake-proof':row['properties']['_provenance']={'representation':'full','source_operation':'get','read_only':True,'api_version':'2023-09-01'}
    if variant=='incomplete-marker':row['_provenance']['read_only']=False
    if variant=='wrong-owner-kind':row['type']='Microsoft.Storage/storageAccounts'
    s=make_snapshot('azure',s['scopes'],s['collections'],created_at=s['created_at'],metadata=s['metadata'])
    rows=evaluate_snapshot(s,checks=[ATTACHED])['findings']
    assert {f['status']for f in rows}=={'UNKNOWN'},rows

from pathlib import Path
CURRENT_NATIVE_OVERLAY=json.loads((Path(__file__).parent/'fixtures'/'azure_storage_native_fixes_20261020.json').read_text())['cases']


@pytest.mark.parametrize('cid,label',[(cid,label)for cid,rows in CURRENT_NATIVE_OVERLAY.items()for label in rows])
def test_separate_current_native_fixture_overlay(cid,label):
    case=deepcopy(CURRENT_NATIVE_OVERLAY[cid][label])
    before=deepcopy(case)
    from peaso.checks import CHECKS
    check=next(c for c in CHECKS if c.id==cid)
    status,evidence=check.evaluate(case['item'],case['index'])
    assert status==case['status'],(cid,label,status,evidence)
    assert case==before
    if cid==KEYS and status!='UNKNOWN':
        assert evidence['key_age_seconds']==case['evidence']['key_age_seconds']

@pytest.mark.parametrize('variant,status',[('unrelated-file','PASS'),('managed-file-only','PASS'),
 ('relevant-file-no-blob','UNKNOWN'),('denied-file-get','UNKNOWN'),('foreign-file-id','UNKNOWN'),
 ('relevant-blob-missing','UNKNOWN'),('duplicate-origin','UNKNOWN')])
def test_native_vhd_endpoint_applicability_with_filestorage(monkeypatch,variant,status):
    secondary=storage.RG+'/providers/Microsoft.Storage/storageAccounts/files'
    file_account={'id':secondary,'name':'files','type':'Microsoft.Storage/storageAccounts','kind':'FileStorage',
      'sku':{'name':'Premium_LRS','tier':'Premium'},'etag':'files-generation1','properties':{
       'provisioningState':'Succeeded','primaryEndpoints':{'file':'https://files.file.core.windows.net/'},
       'encryption':{'keySource':'Microsoft.Storage','services':{'file':{'enabled':True,'keyType':'Account'}}}}}
    native=storage.NativeHTTP(VHD,'positive')
    if variant=='managed-file-only':
        native.vm['properties']['storageProfile']['osDisk']={'managedDisk':{'id':storage.RG+'/providers/Microsoft.Compute/disks/os'}}
    if variant=='relevant-file-no-blob':native.vm['properties']['storageProfile']['osDisk']['vhd']['uri']='https://files.blob.core.windows.net/vhds/os.vhd'
    if variant=='relevant-blob-missing':native.a['properties']['primaryEndpoints'].pop('blob')
    if variant=='duplicate-origin':file_account['properties']['primaryEndpoints']['blob']='https://account.blob.core.windows.net/'
    calls=[]
    class Wire:
        def open(self,request,timeout):
            p=urlsplit(request.full_url);assert request.get_method()in('GET','POST')and p.scheme=='https'and timeout==20
            calls.append((request.get_method(),p.netloc,p.path))
            assert p.netloc in {'management.azure.com',*('account.'+s+'.core.windows.net'for s in ('blob','queue','table'))}
            if p.path==secondary:
                assert request.get_method()=='GET'
                if variant=='denied-file-get':raise HTTPError(request.full_url,403,'fixture denied',{},io.BytesIO(b'{}'))
                row=deepcopy(file_account)
                if variant=='foreign-file-id':row['id']=row['id'].replace(storage.SUB,'99999999-9999-9999-9999-999999999999')
                return _HTTP200(json.dumps(row).encode())
            if p.path.startswith(secondary+'/'):
                assert request.get_method()=='GET'
                assert p.path in {secondary+'/'+s for s in ('blobServices/default/containers','encryptionScopes','localUsers',
                    'providers/Microsoft.EventGrid/eventSubscriptions','providers/Microsoft.Authorization/locks',
                    'providers/Microsoft.Insights/diagnosticSettings',
                    'blobServices/default/providers/Microsoft.Insights/diagnosticSettings',
                    'queueServices/default/providers/Microsoft.Insights/diagnosticSettings',
                    'tableServices/default/providers/Microsoft.Insights/diagnosticSettings')}
                if p.path==secondary+'/blobServices/default/containers':raise HTTPError(request.full_url,404,'FileStorage has no Blob service',{},io.BytesIO(b'{}'))
                return _HTTP200(b'{"value":[]}')
            if p.path=='/providers/Microsoft.ResourceGraph/resources'and request.data and 'resourcecontainers'not in json.loads(request.data)['query']:
                assert request.get_method()=='POST'
                return _HTTP200(json.dumps({'data':[deepcopy(file_account),deepcopy(native.vm)] + ([]if variant=='managed-file-only'else[deepcopy(native.a)]),'resultTruncated':False}).encode())
            response=native.open(request,timeout)
            if p.path==storage.SCOPE+'/providers/Microsoft.Storage/storageAccounts':
                row=json.load(response);row['value']=[deepcopy(file_account)]if variant=='managed-file-only'else row['value']+[deepcopy(file_account)]
                return _HTTP200(json.dumps(row).encode())
            return response
    monkeypatch.setattr(azure,'build_opener',lambda *a:Wire())
    s=azure.collect({'provider':'azure','scopes':[storage.SUB],'auth':{'method':'token','arm_token':'fixture-inert','storage_token':'fixture-inert'},'options':{'retries':0,'concurrency':1}},['storage_account','vm'])
    fs=evaluate_snapshot(s,checks=[VHD],include_not_applicable=True)['findings']
    assert calls and not native.unexpected,native.unexpected
    assert {f['status']for f in fs}=={status},fs
    if variant=='managed-file-only':assert fs[0]['evidence']['unmanaged_os_vhd_count']==0
