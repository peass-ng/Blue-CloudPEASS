"""Directed native public-edge joins through collector and unchanged SW22 predicate."""
import copy,json
import pytest
from peaso.collectors import azure
from peaso.collectors import azure_public_edge_native as edge
from peaso.engine import collect_snapshot,evaluate_snapshot
from tests.test_peaso_azure_bulk_native import Transport,SUB,SCOPE,BASE,parent,envelope
CHECK='azure_application_gateway_11_5_1_1_1_f56bdc2'
IP=BASE+'Microsoft.Network/publicIPAddresses/ip';LB=BASE+'Microsoft.Network/loadBalancers/lb';GW=BASE+'Microsoft.Network/applicationGateways/gw';FD=BASE+'Microsoft.Network/frontDoors/fd';PROFILE=BASE+'Microsoft.Cdn/profiles/profile'

def capture(mode='good',**limits):
    ip=parent(IP,edge.TYPES['public_ip'],{'ddosSettings':{'protectionMode':'Enabled'}});ip['etag']='W/"ip-v2"';ip['properties']['password']='PRIVATE_NATIVE_VALUE'
    lb=parent(LB,edge.TYPES['load_balancer'],{'frontendIPConfigurations':[{'id':LB+'/frontendIPConfigurations/public','properties':{'publicIPAddress':{'id':IP}}}]});lb['etag']='W/"lb-v3"'
    rows={'public_ip':[ip],'load_balancer':[lb],'application_gateway':[],'frontdoor':[]};profiles=[]
    if mode=='disabled':ip['properties']['ddosSettings']['protectionMode']='Disabled'
    if mode=='inherited':ip['properties']['ddosSettings']['protectionMode']='VirtualNetworkInherited'
    if mode=='missing_settings':ip['properties'].pop('ddosSettings')
    if mode=='missing_etag':ip.pop('etag')
    if mode=='missing_ip_reference':lb['properties']['frontendIPConfigurations'][0]['properties']['publicIPAddress']['id']=IP+'-foreign'
    if mode=='duplicate_ip':rows['public_ip']*=2
    if mode=='duplicate_frontend':lb['properties']['frontendIPConfigurations']*=2
    if mode=='foreign_frontend':lb['properties']['frontendIPConfigurations'][0]['id']=GW+'/frontendIPConfigurations/foreign'
    if mode=='foreign_parent':ip['id']=IP.replace(SUB,'99999999-9999-9999-9999-999999999999')
    if mode=='empty':rows={k:[]for k in rows}
    if mode=='private_lb':rows['public_ip']=[];lb['properties']['frontendIPConfigurations'][0]['properties']={'privateIPAddress':'10.0.0.4'}
    if mode=='public_gateway':
        gw=parent(GW,edge.TYPES['application_gateway'],{'frontendIPConfigurations':[{'id':GW+'/frontendIPConfigurations/public','properties':{'publicIPAddress':{'id':IP}}}],'firewallPolicy':{'id':BASE+'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf'}});gw['etag']='gw-v1';rows['application_gateway']=[gw]
    if mode=='frontdoor':
        fd=parent(FD,edge.TYPES['frontdoor'],{'frontendEndpoints':[],'routingRules':[],'backendPools':[]});fd['etag']='fd-v1';rows['frontdoor']=[fd]
    if mode=='profile':
        profile=parent(PROFILE,edge.TYPES['frontdoor_profile'],{'provisioningState':'Succeeded'});profile.update(etag='p-v1',sku={'name':'Premium_AzureFrontDoor'});profiles=[profile]
    routes={'/subscriptions':{'value':[{'id':SCOPE,'subscriptionId':SUB,'tenantId':Transport.tenant}]}}
    for kind,values in rows.items():
        routes[SCOPE+'/providers/'+edge.TYPES[kind]]={'value':copy.deepcopy(values)}
        for row in values:routes[row['id']]=copy.deepcopy(row)
    routes[SCOPE+'/providers/Microsoft.Cdn/profiles']={'value':copy.deepcopy(profiles)}
    for row in profiles:routes[row['id']]=copy.deepcopy(row)
    if mode=='denied_profiles':routes[SCOPE+'/providers/Microsoft.Cdn/profiles']=azure.AzureReadError('forbidden',403)
    if mode=='partial_profiles':routes[SCOPE+'/providers/Microsoft.Cdn/profiles']={'value':[],'nextLink':azure.ARM+SCOPE+'/providers/Microsoft.Cdn/profiles?api-version=2025-04-15&page=2'};routes[SCOPE+'/providers/Microsoft.Cdn/profiles']=lambda q: (_ for _ in ()).throw(azure.AzureReadError('forbidden',403)) if 'page'in q else {'value':[],'nextLink':azure.ARM+SCOPE+'/providers/Microsoft.Cdn/profiles?api-version=2025-04-15&page=2'}
    if mode=='get_id_changed':routes[IP]['id']=IP+'-changed'
    if mode=='get_etag_changed':routes[IP]['etag']='W/"ip-native-v3"'
    api=Transport(routes)
    snap=azure.collect({'provider':'azure','scopes':[SUB],'options':{'retries':0,**limits}},[ *edge.PARENTS,*edge.NATIVE_TYPES],transport=api)
    result=evaluate_snapshot(snap,checks=[CHECK],include_not_applicable=True)['findings'][0]['status']
    assert 'PRIVATE_NATIVE_VALUE' not in json.dumps(snap)
    return snap,result,api


@pytest.mark.parametrize('mode,expected',[
 ('good','PASS'),('disabled','FAIL'),('empty','NOT_APPLICABLE'),('private_lb','NOT_APPLICABLE'),
 ('get_etag_changed','PASS'),('inherited','UNKNOWN'),('missing_settings','UNKNOWN'),('missing_etag','UNKNOWN'),
 ('missing_ip_reference','UNKNOWN'),('duplicate_ip','UNKNOWN'),('duplicate_frontend','UNKNOWN'),
 ('foreign_frontend','UNKNOWN'),('foreign_parent','UNKNOWN'),('public_gateway','UNKNOWN'),('frontdoor','UNKNOWN'),
 ('profile','UNKNOWN'),('get_id_changed','UNKNOWN'),('denied_profiles','DENIED'),('partial_profiles','DENIED')])
def test_native_collection_signed_result(mode,expected):
    snap,status,api=capture(mode);assert status==expected
    if mode in {'good','disabled','get_etag_changed'}:
        ip=envelope(snap,'public_ip')['items'][0];binding=next(row for row in envelope(snap,'public_edge_binding')['items']if row['resource_kind']=='public_ip')
        assert binding['resource_etag']==ip['etag']
        assert ip['_provenance']['source_operation']=='Microsoft.Network/publicIPAddresses:GET'
        assert binding['_provenance']['source_operation']=='Azure.publicEdgeProtection:resolve'
        assert binding['public_frontend_ids']==[IP]
        assert all('api-version='in call for call in api.calls)


@pytest.mark.parametrize('limits',[{'max_calls':1},{'max_resources':1}])
def test_budget_cannot_publish_partial_universe(limits):
    snap,status,_=capture(**limits);assert status in {'UNKNOWN','DENIED'}
    assert envelope(snap,'public_edge_binding')['status'] not in {'collected','empty'}
