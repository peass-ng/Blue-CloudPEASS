"""Inert native-shape metadata tests; no cloud resources, packets or live API calls."""
from copy import deepcopy
from urllib.parse import urlsplit

import pytest

from peaso.checks import CHECKS
from peaso.collectors import azure_nsg_ingress_native as native
from peaso.collectors.azure import _Reader, AzureReadError

S = '/subscriptions/11111111-2222-3333-4444-555555555555'
R = S + '/resourceGroups/rg/providers/'
N = R + 'Microsoft.Network/networkSecurityGroups/n'
NIC = R + 'Microsoft.Network/networkInterfaces/nic'
VNET = R + 'Microsoft.Network/virtualNetworks/vnet'
SUBNET = VNET + '/subnets/default'
VM = R + 'Microsoft.Compute/virtualMachines/vm'
PIP = R + 'Microsoft.Network/publicIPAddresses/pip'
CONFIG = NIC + '/ipConfigurations/config'
OPTIONS = {'compliance_parameters': {native.NAMESPACE: {'status': 'collected', 'scope': S,
    'observed_at': '2026-10-16T01:00:00Z', 'max_age_seconds': 300, 'approvedInternetPorts': [443]}}}


def rule(name, priority, direction='Inbound', access='Deny', port='*', source='*'):
    return {'name': name, 'priority': priority, 'direction': direction, 'access': access,
        'protocol': 'All', 'sourcePortRange': '*', 'destinationPortRange': port,
        'sourceAddressPrefix': source, 'destinationAddressPrefix': '*'}


def topology(port='443'):
    defaults = [rule('AllowVnetInBound',65000,access='Allow',source='10.0.0.0/16'),
        rule('AllowAzureLoadBalancerInBound',65001,access='Allow',source='AzureLoadBalancer'),
        rule('DenyAllInBound',65500),rule('AllowVnetOutBound',65000,'Outbound','Allow'),
        rule('AllowInternetOutBound',65001,'Outbound','Allow'),rule('DenyAllOutBound',65500,'Outbound')]
    custom = rule('AllowTcp',100,access='Allow',port=port);custom['protocol']='Tcp'
    effective = [custom]+defaults
    def resource(rid, kind, properties):
        return {'id':rid, 'type':native.TYPES[kind], 'etag':'"generation-1"', 'properties':properties}
    nsg = resource(N,'nsg',{'securityRules':[{'name':r['name'],'properties':{k:v for k,v in r.items()if k!='name'}} for r in [custom]],
        'defaultSecurityRules':[{'name':r['name'],'properties':{k:v for k,v in r.items()if k!='name'}} for r in defaults],
        'networkInterfaces':[{'id':NIC}], 'subnets':[]})
    objs={N:nsg,
        NIC:resource(NIC,'nic',{'networkSecurityGroup':{'id':N},'virtualMachine':{'id':VM},
            'ipConfigurations':[{'id':CONFIG,'properties':{'privateIPAddress':'10.0.0.4',
                'subnet':{'id':SUBNET},'publicIPAddress':{'id':PIP}}}]}),
        VNET:resource(VNET,'vnet',{'virtualNetworkPeerings':[],'subnets':[{'id':SUBNET}]}),
        VM:resource(VM,'vm',{'networkProfile':{'networkInterfaces':[{'id':NIC}]}}),
        PIP:resource(PIP,'public_ip',{'ipAddress':'8.8.8.8','ipConfiguration':{'id':CONFIG}}),
        SUBNET:{'id':SUBNET,'etag':'"subnet-1"','properties':{'ipConfigurations':[{'id':CONFIG}]}},}
    groups=[{'networkSecurityGroup':{'id':N},'association':{'networkInterface':{'id':NIC}},'effectiveSecurityRules':effective}]
    routes=[{'state':'Active','source':'Default','addressPrefix':['0.0.0.0/0'],'nextHopType':'Internet'},
            {'state':'Active','source':'Default','addressPrefix':['10.0.0.0/16'],'nextHopType':'VnetLocal'},
            {'state':'Active','source':'Default','addressPrefix':['100.64.0.0/10'],'nextHopType':'None'}]
    return objs,groups,routes


class InertTransport:
    def __init__(self, objects):self.objects=objects;self.calls=[]
    def token(self,*args):raise AssertionError('No actual token lookup allowed in inert tests')
    def request(self,url,**kwargs):
        self.calls.append(url)
        path=urlsplit(url).path.casefold()
        for kind,typ in native.TYPES.items():
            if path==(S+'/providers/'+typ).casefold():
                return {'value':[deepcopy(v)for v in self.objects.values()if str(v.get('type','')).casefold()==typ.casefold()]}
        for rid,row in self.objects.items():
            if rid.casefold()==path:return deepcopy(row)
        raise AssertionError('Unexpected metadata URL '+url)


def run_native(monkeypatch, *, port='443', mutate=None, response=None, reader_options=None):
    objects,groups,routes=topology(port)
    if mutate:mutate(objects,groups,routes)
    transport=InertTransport(objects);reader=_Reader({'retries':0,**(reader_options or {})})
    for kind,typ in native.TYPES.items():
        rows=[deepcopy(v)for v in objects.values()if v.get('type')==typ]
        reader.collections.append({'type':kind,'scope':S,'status':'collected'if rows else'empty','items':rows})
    def inert_response(self,url,parent,kind,nsg_ids,*,initial,body=None):
        if response:return response(self,url,parent,kind,nsg_ids,initial=initial,body=body)
        return native.ReadResponse(200,{'value':deepcopy(groups if kind=='nsg'else routes if kind=='routes'else[])},{})
    monkeypatch.setattr(native.NetworkQueries,'_response',inert_response)
    # Native join tests use decoded inert metadata; separate wire tests exercise
    # the dedicated GET's URL, token and pre-parse byte bounds.
    monkeypatch.setattr(native.NetworkQueries,'get',lambda self,url,**kwargs:transport.request(url,**kwargs))
    native.collect(reader,transport.request,transport,[S],native.NATIVE_TYPES,OPTIONS)
    return reader,transport


def status(reader, check_id=native.CHECK):
    kinds={c['type']:c for c in reader.collections}
    index={'context':{'provider':'azure','scope':S,'created_at':'2026-10-16T01:00:30Z',
            'metadata':{'compliance_policy':{'sw31':native.owner_metadata(native.normalize(OPTIONS,[S]),'2026-10-16T01:00:30Z')}}},
        'collections':{k:[v]for k,v in kinds.items()},
        **{k:[{'scope':S,'data':deepcopy(r)}for r in v['items']]for k,v in kinds.items()}}
    check=next(c for c in CHECKS if c.id==check_id)
    return check.evaluate({'scope':S},index)[0]


@pytest.mark.parametrize('port,expected',[('443','PASS'),('22','FAIL')])
def test_native_metadata_join_to_actual_signed_evaluator(monkeypatch,port,expected):
    reader,transport=run_native(monkeypatch,port=port)
    output=reader.collections[-1]
    assert output['status']=='collected',output
    assert len(output['items'])==1
    assert status(reader)==expected
    assert status(reader,'azure.other.nsg_port_protocol_assignment')=='UNKNOWN'
    assert all(url.startswith(native.ARM+S)for url in transport.calls)


@pytest.mark.parametrize('mutation',[
    lambda o,g,r:o[N]['properties']['networkInterfaces'].clear(),
    lambda o,g,r:o[NIC]['properties'].__setitem__('enableIPForwarding',True),
    lambda o,g,r:o[NIC]['properties']['ipConfigurations'][0]['properties'].__setitem__('loadBalancerBackendAddressPools',[{'id':'unknown'}]),
    lambda o,g,r:o[SUBNET]['properties'].__setitem__('routeTable',{'id':'unresolved'}),
    lambda o,g,r:o[VNET]['properties'].__setitem__('virtualNetworkPeerings',[{'id':'unresolved'}]),
    lambda o,g,r:o[VM]['properties']['networkProfile']['networkInterfaces'].append({'id':NIC+'other'}),
    lambda o,g,r:o[PIP]['properties'].__setitem__('ipConfiguration',{'id':CONFIG+'foreign'}),
    lambda o,g,r:o[VM].pop('etag'),
    lambda o,g,r:g[0].__setitem__('association',{}),
    lambda o,g,r:g.clear(),
    lambda o,g,r:g[0]['effectiveSecurityRules'].pop(3),
    lambda o,g,r:r[0].__setitem__('source','User'),
    lambda o,g,r:r[0].__setitem__('nextHopType','VirtualAppliance'),
    lambda o,g,r:r[0].__setitem__('state','Invalid'),
    lambda o,g,r:r.append({'state':'Active','source':'Default','nextHopType':'None','addressPrefix':['8.0.0.0/8']}),
])
def test_unresolved_topology_never_becomes_complete_pass(monkeypatch,mutation):
    reader,_=run_native(monkeypatch,mutate=mutation)
    assert reader.collections[-1]['status'] not in ('collected','empty')
    assert reader.collections[-1]['items']==[]
    assert status(reader)=='UNKNOWN'


def test_effective_admin_override_not_ignored(monkeypatch):
    def response(self,url,parent,kind,nsg_ids,**kwargs):
        if kind=='admin':return native.ReadResponse(200,{'value':[{'access':'AlwaysAllow'}]}, {})
        raise AssertionError('Admin override must stop before NSG projection')
    reader,_=run_native(monkeypatch,response=response)
    assert reader.collections[-1]['status'] not in ('collected','empty')
    assert status(reader)=='UNKNOWN'


def test_native_denied_all_yields_proved_empty(monkeypatch):
    def deny(o,g,r):g[0]['effectiveSecurityRules'][0]['access']='Deny'
    reader,_=run_native(monkeypatch,mutate=deny)
    assert reader.collections[-1]['status']=='empty'
    assert status(reader)=='PASS'


def test_wide_projection_budget_stays_unknown(monkeypatch):
    reader,_=run_native(monkeypatch,port='1-65535')
    assert reader.collections[-1]['status'] not in ('collected','empty')
    assert status(reader)=='UNKNOWN'


def test_call_budget_stays_unknown(monkeypatch):
    reader,_=run_native(monkeypatch,reader_options={'max_calls':2})
    assert reader.collections[-1]['status'] not in ('collected','empty')
    assert status(reader)=='UNKNOWN'


@pytest.mark.parametrize('url',[
    native.ARM+NIC+'/start?api-version='+native.VERSION,
    'https://evil.invalid'+NIC+'/effectiveRouteTable?api-version='+native.VERSION,
    native.ARM+NIC+'/effectiveRouteTable?api-version='+native.VERSION+'&api-version='+native.VERSION,
    native.ARM+NIC+'/effectiveRouteTable?api-version='+native.VERSION+'#fragment',
    native.ARM+NIC+'/../effectiveRouteTable?api-version='+native.VERSION,
])
def test_unsafe_query_rejected_before_token_or_http(url):
    q=native.NetworkQueries(_Reader({'retries':0}),InertTransport({}),S)
    with pytest.raises((AzureReadError,ValueError)):
        q._response(url,NIC,'routes',(),initial=True)
    assert q.calls==0


@pytest.mark.parametrize('direction',['Inbound','Outbound'])
def test_native_parent_accepts_direction_scoped_defaults(direction):
    objects,_,_=topology()
    rules=native._native_nsg_rules(objects[N])
    assert len([r for r in rules if r['properties']['direction']==direction]) in (3,4)


class InertHTTPResponse:
    def __init__(self,status,data=None,headers=None):
        import json
        self.status=status;self.headers=headers or {}
        self.body=b''if data is None else json.dumps(data).encode()
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def read(self,limit):return self.body[:limit]


def wire_queries(monkeypatch,responses,*,max_pages=None):
    requests=[];tokens=[]
    class Transport:
        def token(self,audience):tokens.append(audience);return 'INERT-NOT-A-CREDENTIAL'
    class Opener:
        def open(self,request,timeout):
            requests.append(request)
            assert responses,'Unexpected extra HTTP request'
            item=responses.pop(0)
            if isinstance(item,Exception):raise item
            return item
    monkeypatch.setattr(native,'build_opener',lambda *args:Opener())
    q=native.NetworkQueries(_Reader({'retries':0,'max_pages':max_pages}),Transport(),S,sleep=lambda _:None)
    return q,requests,tokens


@pytest.mark.parametrize('kind,parent',[('nsg',NIC),('routes',NIC),('admin',VNET)])
def test_wire_exact_three_semantic_reads_only(monkeypatch,kind,parent):
    q,requests,tokens=wire_queries(monkeypatch,[InertHTTPResponse(200,{'value':[]})])
    assert list(q.pages(kind,parent,nsg_ids=(N,)))==[[]]
    assert [r.method for r in requests]==['POST']
    assert requests[0].full_url==native.ARM+parent+'/'+native.SUFFIXES[kind]+'?api-version='+native.VERSION
    assert tokens==[native.ARM]
    assert q.calls==1


@pytest.mark.parametrize('kind,location_parent',[('nsg',N),('routes',NIC)])
def test_wire_bounded_lro_uses_bound_get_then_native_result(monkeypatch,kind,location_parent):
    location=native.ARM+'/'+location_parent+'/operationResults/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee?api-version=2025-07-01'
    q,requests,tokens=wire_queries(monkeypatch,[InertHTTPResponse(202,None,{'Location':location,'Retry-After':'1'}),
        InertHTTPResponse(200,{'value':[]})])
    assert list(q.pages(kind,NIC,nsg_ids=(N,)))==[[]]
    assert [r.method for r in requests]==['POST','GET']
    assert q.calls==2 and len(tokens)==2
    assert len(q.proofs)==1


@pytest.mark.parametrize('location',[
    'https://evil.invalid'+NIC+'/operationResults/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee?api-version='+native.VERSION,
    native.ARM+NIC+'-foreign/operationResults/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee?api-version='+native.VERSION,
    native.ARM+NIC+'/start?api-version='+native.VERSION,
    native.ARM+NIC+'/operationResults/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee?api-version=1900-01-01',
])
def test_wire_foreign_or_mutating_lro_cannot_acquire_second_token(monkeypatch,location):
    q,requests,tokens=wire_queries(monkeypatch,[InertHTTPResponse(202,None,{'Location':location})])
    with pytest.raises(AzureReadError):list(q.pages('routes',NIC))
    assert len(requests)==len(tokens)==1


@pytest.mark.parametrize('case',['missing_location','huge_retry','malformed_retry','poll_budget','admin_lro'])
def test_wire_incomplete_lro_stays_unknown(monkeypatch,case):
    location=native.ARM+NIC+'/operationResults/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee?api-version='+native.VERSION
    headers={'Location':location}
    if case=='missing_location':headers={}
    if case=='huge_retry':headers['Retry-After']='31'
    if case=='malformed_retry':headers['Retry-After']='tomorrow'
    responses=[InertHTTPResponse(202,None,headers)]*(13 if case=='poll_budget'else 1)
    q,requests,tokens=wire_queries(monkeypatch,responses)
    with pytest.raises(AzureReadError):list(q.pages('admin'if case=='admin_lro'else'routes',VNET if case=='admin_lro'else NIC))
    assert len(requests)<=13


def test_wire_admin_pagination_sends_exact_skip_token(monkeypatch):
    import json
    q,requests,_=wire_queries(monkeypatch,[InertHTTPResponse(200,{'value':[],'skipToken':'page2'}),InertHTTPResponse(200,{'value':[]})])
    assert list(q.pages('admin',VNET))==[[],[]]
    assert all(r.method=='POST'for r in requests)
    assert [json.loads(r.data)for r in requests]==[{}, {'skipToken':'page2'}]


@pytest.mark.parametrize('case',['repeated_token','page_budget','malformed_value','native_denied'])
def test_wire_pagination_or_denial_never_yields_complete(case,monkeypatch):
    from urllib.error import HTTPError
    if case=='native_denied':responses=[HTTPError(native.ARM,403,'denied',{},None)]
    elif case=='malformed_value':responses=[InertHTTPResponse(200,{'value':{}})]
    else:responses=[InertHTTPResponse(200,{'value':[],'skipToken':'again'})]*2
    q,requests,_=wire_queries(monkeypatch,responses,max_pages=1 if case=='page_budget'else None)
    with pytest.raises((AzureReadError,HTTPError)):list(q.pages('admin',VNET))
    assert len(requests)<=2


def test_inventory_generation_change_stays_unknown(monkeypatch):
    original=InertTransport.request;reads=[]
    def change(self,url,**kwargs):
        row=original(self,url,**kwargs)
        if urlsplit(url).path.casefold()==N.casefold():
            reads.append(url)
            if len(reads)>1:row['etag']='"changed-generation"'
        return row
    monkeypatch.setattr(InertTransport,'request',change)
    reader,_=run_native(monkeypatch)
    assert len(reads)==2
    assert reader.collections[-1]['status'] not in ('collected','empty')
    assert reader.collections[-1]['items']==[]
    assert status(reader)=='UNKNOWN'


@pytest.mark.parametrize('options',[None,[],{'compliance_parameters':None},
    {'compliance_parameters':{native.NAMESPACE:None}}])
def test_owner_bad_container_rejected(options):
    with pytest.raises(ValueError):native.normalize(options,[S])


@pytest.mark.parametrize('field,value',[
    ('scope','/subscriptions/foreign'),('status','empty'),('max_age_seconds',True),
    ('max_age_seconds',86401),('max_age_seconds',0),('observed_at','2026-10-16'),
    ('approvedInternetPorts',[True]),('approvedInternetPorts',[0]),
    ('approvedInternetPorts',[65536]),('approvedInternetPorts',[443,443]),
    ('approvedInternetPorts',[str(443)]),('approvedInternetPorts',list(range(1,4098))),
    ('nsg_effective_internet_path',[]),('observed_paths',[]),
])
def test_owner_strict_fields_reject_observations_and_bad_types(field,value):
    options=deepcopy(OPTIONS);options['compliance_parameters'][native.NAMESPACE][field]=value
    with pytest.raises(ValueError):native.normalize(options,[S])


@pytest.mark.parametrize('scopes',[[],None,{'arbitrary':'mapping'},[S+'foreign'],[True]])
def test_owner_selected_scope_validation(scopes):
    if scopes is None:
        assert native.normalize(OPTIONS,scopes)['scope']==S # Intake validates declared scope, selection follows before transport.
    else:
        with pytest.raises(ValueError):native.normalize(OPTIONS,scopes)


def test_owner_deepcopy_preserves_clock_and_stale_future_missing():
    raw=deepcopy(OPTIONS)
    policy=native.normalize(raw,[S]);policy['approvedInternetPorts'].append(8443)
    assert raw==OPTIONS
    assert native.normalize(OPTIONS,[S])['observed_at']=='2026-10-16T01:00:00Z'
    policy=native.normalize(OPTIONS,[S])
    assert native.owner_metadata(policy,'2026-10-16T01:00:30Z')=={'approvedInternetPorts':[443]}
    assert native.owner_metadata(policy,'2026-10-16T01:05:01Z')=={}
    assert native.owner_metadata(policy,'2026-10-16T00:59:59Z')=={}
    assert native.normalize({})is None
    assert native.owner_metadata(None,'2026-10-16T01:00:30Z')=={}


def test_owner_conflicting_raw_sw31_cannot_replace_policy():
    options=deepcopy(OPTIONS);options['compliance_policy']={'sw31':{'approvedInternetPorts':[22]}}
    with pytest.raises(ValueError):native.normalize(options,[S])


def test_owner_unrelated_namespace_preserved():
    options=deepcopy(OPTIONS);options['compliance_policy']={'sw33':{'custom':'criteria'}}
    before=deepcopy(options)
    assert native.normalize(options,[S])['approvedInternetPorts']==[443]
    assert options==before


@pytest.mark.parametrize('kind',['load_balancer','application_gateway'])
def test_v2_managed_ingress_without_nic_reference_is_unknown(monkeypatch,kind):
    def hidden(objects,groups,routes):
        rid=R+native.TYPES[kind]+'/hidden'
        objects[rid]={'id':rid,'type':native.TYPES[kind],'etag':'"hidden"',
            'properties':{'backendAddressPools':[{'properties':{'loadBalancerBackendAddresses':[
                {'properties':{'ipAddress':'10.0.0.4','virtualNetwork':{'id':VNET}}}]}}]}}
    reader,_=run_native(monkeypatch,mutate=hidden)
    assert reader.collections[-1]['error']['kind']=='AzureReadError'
    assert reader.collections[-1]['status'] not in ('collected','empty')
    assert status(reader)=='UNKNOWN'


def test_v2_private_nic_cannot_be_silently_omitted(monkeypatch):
    def private(objects,groups,routes):
        objects[NIC]['properties']['ipConfigurations'][0]['properties'].pop('publicIPAddress')
        objects.pop(PIP)
    reader,_=run_native(monkeypatch,mutate=private)
    assert reader.collections[-1]['error']['kind']=='AzureReadError'
    assert reader.collections[-1]['status'] not in ('collected','empty')
    assert status(reader)=='UNKNOWN'


@pytest.mark.parametrize('mutation',[
    lambda o:o[PIP]['properties'].__setitem__('ipConfiguration',{'id':R+'Microsoft.Network/loadBalancers/foreign/frontendIPConfigurations/f'}),
    lambda o:o[VNET]['properties'].pop('subnets'),
    lambda o:o[SUBNET]['properties']['ipConfigurations'].append({'id':R+'Microsoft.Network/loadBalancers/foreign/frontendIPConfigurations/f'}),
    lambda o:o[SUBNET]['properties'].__setitem__('applicationGatewayIPConfigurations',[{'id':'unknown'}]),
    lambda o:o[SUBNET]['properties'].pop('ipConfigurations'),
])
def test_v2_reverse_or_managed_vnet_universe_unknown(monkeypatch,mutation):
    reader,_=run_native(monkeypatch,mutate=lambda objects,groups,routes:mutation(objects))
    assert reader.collections[-1]['error']['kind']=='AzureReadError'
    assert reader.collections[-1]['status'] not in ('collected','empty')
    assert status(reader)=='UNKNOWN'


@pytest.mark.parametrize('path,version',[(N,native.VERSION),(S+'/providers/Microsoft.Network/loadBalancers',native.VERSION),
    (S+'/providers/Microsoft.Network/applicationGateways',native.VERSION),(SUBNET,native.VERSION),(VM,'2024-07-01')])
def test_v2_wire_inventory_get_is_exact_and_bounded(monkeypatch,path,version):
    q,requests,tokens=wire_queries(monkeypatch,[InertHTTPResponse(200,{'value':[]})])
    assert q.get(native.ARM+path+'?api-version='+version)=={'value':[]}
    assert len(requests)==len(tokens)==1 and requests[0].method=='GET'
    assert q.bytes>0 and q.calls==1


@pytest.mark.parametrize('url',[
    native.ARM+N+'/start?api-version='+native.VERSION,
    native.ARM+N+'?api-version='+native.VERSION+'&api-version='+native.VERSION,
    native.ARM+N+'?api-version='+native.VERSION+'&$skiptoken=unexpected',
    native.ARM+N+'?api-version=1900-01-01',
    'https://evil.invalid'+N+'?api-version='+native.VERSION,
    native.ARM+'/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/providers/Microsoft.Network/loadBalancers?api-version='+native.VERSION,
    native.ARM+N+'/../n?api-version='+native.VERSION,
])
def test_v2_wire_inventory_get_denies_before_token(monkeypatch,url):
    q,requests,tokens=wire_queries(monkeypatch,[])
    with pytest.raises(AzureReadError):q.get(url)
    assert requests==tokens==[] and q.calls==0


def test_v2_wire_inventory_oversize_rejected_before_json(monkeypatch):
    response=InertHTTPResponse(200);response.body=b'x'*(8*1024*1024+1)
    q,requests,tokens=wire_queries(monkeypatch,[response])
    parsed=[]
    def forbidden(*args,**kwargs):parsed.append(True);raise AssertionError('Oversized body must never be parsed')
    monkeypatch.setattr(native.json,'loads',forbidden)
    with pytest.raises(AzureReadError):q.get(native.ARM+N+'?api-version='+native.VERSION)
    assert parsed==[] and len(requests)==len(tokens)==1


@pytest.mark.parametrize('character',['\n','\t'])
def test_inventory_get_control_char_before_token(monkeypatch,character):
    q,requests,tokens=wire_queries(monkeypatch,[])
    with pytest.raises(AzureReadError):q.get(native.ARM+character+N+'?api-version='+native.VERSION)
    assert requests==tokens==[] and q.calls==0


@pytest.mark.parametrize('kind,missing',[('public_ip',PIP),('vm',VM),('vnet',VNET)])
def test_complete_list_missing_forward_reference_rejected_before_get(monkeypatch,kind,missing):
    objects,groups,routes=topology()
    reader=_Reader({'retries':0})
    for inventory,typ in native.TYPES.items():
        rows=[deepcopy(row)for rid,row in objects.items()if row.get('type')==typ and rid!=missing]
        reader.collections.append({'type':inventory,'scope':S,'status':'collected'if rows else'empty','items':rows})
    class MissingListTransport(InertTransport):
        def request(self,url,**kwargs):
            path=urlsplit(url).path.casefold()
            if path==(S+'/providers/'+native.TYPES[kind]).casefold():
                self.calls.append(url);return {'value':[]}
            return super().request(url,**kwargs)
    transport=MissingListTransport(objects)
    monkeypatch.setattr(native.NetworkQueries,'get',lambda self,url,**kwargs:transport.request(url,**kwargs))
    monkeypatch.setattr(native.NetworkQueries,'_response',lambda self,url,parent,operation,nsg_ids,**kwargs:
        native.ReadResponse(200,{'value':deepcopy(groups if operation=='nsg'else routes if operation=='routes'else[])},{}))
    seen=[];original=native.unavailable
    def record(code):seen.append(code);return original(code)
    monkeypatch.setattr(native,'unavailable',record)
    native.collect(reader,transport.request,transport,[S],native.NATIVE_TYPES,OPTIONS)
    assert seen[-1]=='nsg_native_reference_absent_from_complete_inventory'
    assert reader.collections[-1]['error']['kind']=='AzureReadError'
    assert reader.collections[-1]['status'] not in ('collected','empty')
    assert reader.collections[-1]['items']==[] and status(reader)=='UNKNOWN'
    assert missing.casefold() not in [urlsplit(url).path.casefold()for url in transport.calls]
