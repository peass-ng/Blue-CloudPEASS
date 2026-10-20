"""Native pricing declarations; independent finite ARM data, no live protection claim."""
from copy import deepcopy
import socket
from urllib.parse import urlsplit

import pytest
from peaso.collectors import azure
from peaso.engine import evaluate_snapshot
from tests.test_peaso_azure_bulk_native import SUB, SCOPE, Transport, parent

# Explicit native plan names and contracts, independent of runtime CASES/closures.
PLANS = [
 ('azure.port.security_center_defender_for_api_enabled', 'Api', 'current'),
 ('azure.port.security_center_defender_for_cloudposture_enabled', 'CloudPosture', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_appservice', 'AppServices', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_containers', 'Containers', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_cosmosdb', 'CosmosDbs', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_keyvault', 'KeyVaults', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_opensource_relational_db', 'OpenSourceRelationalDatabases', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_resource_manager', 'Arm', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_server', 'VirtualMachines', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_sqldb', 'SqlServers', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_sqlservervm', 'SqlServerVirtualMachines', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_storage', 'StorageAccounts', 'current'),
 ('azure.port.securitycenter_azure_defender_on_for_containerregistry', 'ContainerRegistry', 'legacy'),
 ('azure.port.securitycenter_azure_defender_on_for_dns', 'Dns', 'legacy'),
 ('azure.port.securitycenter_azure_defender_on_for_k8s', 'KubernetesService', 'legacy'),
 ('azure.claude.defender_container_registry_plan_standard', 'ContainerRegistry', 'offered'),
 ('azure.claude.defender_dns_plan_standard', 'Dns', 'offered'),
 ('azure.claude.defender_kubernetes_plan_standard', 'KubernetesService', 'offered'),
 ('azure.claude.defender_plan_standard_any', 'StorageAccounts', 'resource'),
 ('azure.defender.standard_tier', 'StorageAccounts', 'resource'),
 ('azure.cis.agentless_scanning_machines_component_status', 'VirtualMachines', 'agentless'),
 ('azure.cis.file_integrity_monitoring_component_status', 'VirtualMachines', 'fim'),
 ('azure.claude.defender_container_registry_vulnerability_scanning', 'Containers', 'scanning'),
 ('azure.claude.defender_database_plans_standard', 'CosmosDbs', 'database-offered'),
 ('azure.port.securitycenter_azure_defender_on_for_database', 'CosmosDbs', 'database-required'),
]
DATABASES = ('CosmosDbs', 'OpenSourceRelationalDatabases', 'SqlServerVirtualMachines', 'SqlServers')
TYPE = 'Microsoft.Security/pricings'
ENDPOINT = SCOPE + '/providers/' + TYPE
MODES = ('standard', 'free', 'empty', 'denied', 'partial', 'foreign', 'malformed-tier', 'missing-properties', 'wrong-detail-type', 'wrong-detail-name', 'denied-detail')


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a, **k):
        pytest.fail('Pricing review forbids network, DNS and auth')
    for obj, name in ((socket,'create_connection'),(socket,'getaddrinfo'),(socket.socket,'connect'),
                      (socket.socket,'connect_ex'),(azure,'AzureTransport')):
        monkeypatch.setattr(obj, name, blocked)


def capture(spec, mode):
    cid, plan, contract = spec
    names = DATABASES if contract.startswith('database-') else (plan,)
    rows = []
    for name in names:
        props = {'pricingTier': 'Free' if mode == 'free' and name == plan else 'Standard'}
        if contract == 'fim': props.update(subPlan='P2', resourcesCoverageStatus='FullyCovered', extensions=[{'name':'FileIntegrityMonitoring','isEnabled':'True','operationStatus':{'code':'Succeeded'}}])
        if contract == 'agentless': props['extensions']=[{'name':'AgentlessVmScanning','isEnabled':'True'}]
        if contract == 'scanning': props['extensions']=[{'name':'ContainerRegistriesVulnerabilityAssessments','isEnabled':'True'}]
        if mode == 'coverage-partial': props['resourcesCoverageStatus'] = 'PartiallyCovered'
        if mode == 'extension-off':
            for extension in props.get('extensions', []): extension['isEnabled'] = 'False'
        if mode == 'activation-failed':
            for extension in props.get('extensions', []): extension['operationStatus'] = {'code':'Failed'}
        if mode == 'deprecated': props.update(deprecated=True, replacedBy=['Containers'], pricingTier='Free')
        if mode == 'malformed-tier': props['pricingTier'] = 'Unexpected'
        if mode == 'missing-properties': props = {}
        rid = ENDPOINT + '/' + name
        row = parent(rid, TYPE, props)
        if mode == 'foreign': row['id'] = rid.replace(SUB,'99999999-9999-9999-9999-999999999999')
        rows.append(row)
    routes = {ENDPOINT:{'value':deepcopy(rows)}}
    for row in rows: routes[row['id']] = deepcopy(row)
    for row in rows:
        if mode == 'wrong-detail-type': routes[row['id']]['type'] = 'Microsoft.Compute/virtualMachines'
        if mode == 'wrong-detail-name': routes[row['id']]['name'] = 'UnrelatedPlan'
        if mode == 'denied-detail': routes[row['id']] = azure.AzureReadError('Forbidden',403)
    if mode == 'empty': routes[ENDPOINT] = {'value':[]}
    if mode == 'denied': routes[ENDPOINT] = azure.AzureReadError('Forbidden',403)
    if mode == 'partial':
        def pages(query):
            if 'page' in query: raise azure.AzureReadError('Forbidden',403)
            return {'value':deepcopy(rows),'nextLink':azure.ARM+ENDPOINT+'?api-version=2024-01-01&page=2'}
        routes[ENDPOINT] = pages
    api=Transport(routes)
    snapshot=azure.collect({'provider':'azure','scopes':[SUB],'options':{'retries':0}},['security_pricing'],transport=api)
    result=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)
    return snapshot,api,result['findings']


@pytest.mark.parametrize('spec', PLANS, ids=lambda s:s[0])
@pytest.mark.parametrize('mode', MODES)
def test_native_pricing_read_and_deciding_branches(spec, mode):
    snapshot,api,findings=capture(spec,mode)
    status = {f['status'] for f in findings}
    contract=spec[2]
    if mode=='standard': expected={'PASS'}
    elif mode=='free': expected={'FAIL'}
    elif mode=='empty':
        expected={'EMPTY'} if contract=='resource' else {'NOT_APPLICABLE'} if contract in ('offered','scanning','database-offered') else {'FAIL'} if contract=='database-required' else {'UNKNOWN'}
    elif mode=='denied': expected={'DENIED'}
    elif mode=='partial' and contract=='resource':
        # A readable resource declaration can pass while the separate coverage
        # finding records that other resources could not be enumerated.
        expected={'PASS','UNKNOWN'}
    else: expected={'UNKNOWN'}
    assert status == expected, (spec,mode,findings)
    assert api.calls
    assert all(urlsplit(u).hostname=='management.azure.com' for u in api.calls)
    if mode in ('denied','partial','foreign'):
        assert all(c.get('status') not in ('collected','empty') for c in snapshot['collections'] if c['type']=='security_pricing')


@pytest.mark.parametrize('contract,mode,expected', [
 ('fim','coverage-partial','UNKNOWN'),('fim','activation-failed','UNKNOWN'),('fim','extension-off','FAIL'),
 ('agentless','extension-off','FAIL'),('agentless','activation-failed','PASS'),('scanning','extension-off','FAIL'),
])
def test_extension_activation_and_coverage_contracts(contract, mode, expected):
    spec=next(s for s in PLANS if s[2]==contract)
    _,_,findings=capture(spec,mode)
    assert {f['status'] for f in findings} == {expected}


@pytest.mark.parametrize('spec', [s for s in PLANS if s[2] in ('offered','legacy')], ids=lambda s:s[0])
def test_deprecated_legacy_plan_is_distinct_from_its_replacement(spec):
    _,_,findings=capture(spec,'deprecated')
    # Literal historic enrollment checks retain Free; offered-plan checks skip
    # a Microsoft-deprecated plan, never pretend the replacement is enabled.
    expected='FAIL' if spec[2]=='legacy' else 'NOT_APPLICABLE'
    assert {f['status'] for f in findings} == {expected}
