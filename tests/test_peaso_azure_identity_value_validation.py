"""Malformed Graph values must not establish a successful identity baseline."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

@pytest.mark.parametrize('slug', ['entra_ca_mfa_admin_portals','entra_ca_mfa_management_api'])
@pytest.mark.parametrize('control,status', [('notmfa','UNKNOWN'),('MFA','UNKNOWN'),('unknownFutureValue','UNKNOWN'),('mfa','PASS'),('compliantDevice','FAIL'),('block','FAIL'),('domainJoinedDevice','FAIL'),('approvedApplication','FAIL'),('compliantApplication','FAIL'),('passwordChange','FAIL'),('riskRemediation','FAIL')])
def test_declared_mfa_control_matches_only_documented_exact_member(slug,control,status):
    cid='azure.claude.'+slug
    c=next(c for c in CHECKS if c.id==cid)
    case=CASES[cid]; index=deepcopy(case['pass_index'])
    policy=index['conditional_access_policy'][0]['data']
    policy['grantControls']['builtInControls']=[control]
    assert c.evaluate(deepcopy(case['pass']),index)[0]==status

@pytest.mark.parametrize('value,status',[('garbage','UNKNOWN'),('','UNKNOWN'),(' false ','UNKNOWN'),('FALSE','PASS'),('false','PASS'),('true','FAIL'),('TRUE','FAIL')])
def test_group_creation_requires_a_recognized_boolean_string(value,status):
    cid='azure.claude.entra_m365_group_creation_restricted'
    c=next(c for c in CHECKS if c.id==cid);case=CASES[cid];index=deepcopy(case['pass_index'])
    index['directory_setting'][0]['data']['values'][0]['value']=value
    assert c.evaluate(deepcopy(case['pass']),index)[0]==status

@pytest.mark.parametrize('value,status',[({},'UNKNOWN'),(0,'UNKNOWN'),('P0D','UNKNOWN'),('P6D','UNKNOWN'),('P7D','PASS'),('P1M','PASS'),('P90D','PASS')])
def test_after_create_rotation_requires_supported_interval(value,status):
    cid='azure.claude.keyvault_key_automatic_rotation_after_create';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass']);item['properties']['rotationPolicy']['lifetimeActions'][0]['trigger']['timeAfterCreate']=value
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('value,status',[({},'UNKNOWN'),(True,'UNKNOWN'),({'logAnalyticsWorkspaceResourceID':''},'UNKNOWN'),({'logAnalyticsWorkspaceResourceID':'/w'},'UNKNOWN'),({'logAnalyticsWorkspaceResourceID':'/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w'},'PASS')])
def test_container_insights_requires_a_real_workspace_declaration(value,status):
    cid='azure.claude.aks_container_insights_logging';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass']);item['properties']['addonProfiles']['omsagent']['config']=value
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('days,status',[(-1,'UNKNOWN'),('365','UNKNOWN'),(True,'UNKNOWN'),(0,'PASS'),(365,'PASS')])
def test_audit_archive_retention_rejects_malformed_counts(days,status):
    cid='azure.claude.managed_hsm_audit_logging';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass']);item['diagnosticSettings'][0]['properties']['logs'][0]['retentionPolicy']['days']=days
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('slug,key',[('eventhub_namespace_logging','diagnostic_logging_enabled'),('iot_hub_logging','diagnostic_logging_enabled'),('keyvault_key_rotation_policy','rotate_action_present')])
@pytest.mark.parametrize('state,expected',[('pass',True),('fail',False)])
def test_evidence_retains_decisive_boolean_not_ambiguous_item_count(slug,key,state,expected):
    cid='azure.claude.'+slug;c=next(c for c in CHECKS if c.id==cid)
    status,evidence=c.evaluate(deepcopy(CASES[cid][state]),{})
    assert status==state.upper()
    assert evidence[key] is expected

@pytest.mark.parametrize('ranges,status',[([''],'UNKNOWN'),(['garbage'],'UNKNOWN'),([' 203.0.113.0/24'],'UNKNOWN'),(['999.0.0.0/24'],'UNKNOWN'),(['203.0.113.0/24'],'PASS'),(['0.0.0.0/0'],'PASS'),([],'FAIL')])
def test_authorized_sources_reject_malformed_ranges_without_inventing_a_narrowness_criterion(ranges,status):
    cid='azure.claude.aks_authorized_ip_ranges';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass']);item['properties']['apiServerAccessProfile']['authorizedIPRanges']=ranges
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('value,status',[({},'UNKNOWN'),(True,'UNKNOWN'),('','UNKNOWN'),(' fqdn ','UNKNOWN'),('x.privatelink.eastus.azmk8s.io','PASS')])
def test_private_api_fqdn_must_be_a_nonempty_string(value,status):
    cid='azure.claude2.aks_private_cluster_nodes_without_public_ip';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass']);item['properties']['privateFQDN']=value
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('state,expected',[('pass',True),('fail',False)])
def test_batch_logs_include_matching_boolean_even_without_setting_name(state,expected):
    cid='azure.claude2.batch_account_resource_logs';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid][state]);before=deepcopy(item)
    status,evidence=c.evaluate(item,{})
    assert status==state.upper()
    assert evidence['matching_enabled_logs'] is expected
    assert item==before

@pytest.mark.parametrize('slug',['entra_lockout_duration_min_60','entra_lockout_threshold_max_10'])
@pytest.mark.parametrize('value',['0','-1','--1','garbage'])
def test_lockout_numeric_settings_cannot_prove_compliance_with_nonpositive_or_malformed_values(slug,value):
    cid='azure.claude2.'+slug;c=next(c for c in CHECKS if c.id==cid);case=CASES[cid]
    index=deepcopy(case['pass_index']);index['directory_setting'][0]['data']['values'][0]['value']=value
    assert c.evaluate(deepcopy(case['pass']),index)[0]=='UNKNOWN'

@pytest.mark.parametrize('value,status',[(-1,'UNKNOWN'),(0,'PASS'),(1,'FAIL')])
def test_vulnerability_scan_counts_cannot_be_negative(value,status):
    cid='azure.claude.sql_database_va_findings_resolved';c=next(c for c in CHECKS if c.id==cid)
    item=deepcopy(CASES[cid]['pass'])
    for scan in item['vulnerabilityAssessmentScans']:
        scan['properties']['numberOfFailedSecurityChecks']=value
    assert c.evaluate(item,{})[0]==status

@pytest.mark.parametrize('source,status',[('garbage','UNKNOWN'),('Microsoft.Storage','FAIL'),('Microsoft.KeyVault','PASS')])
def test_legacy_vhd_key_source_requires_recognized_native_metadata(source,status):
    cid='azure.claude.storage_vhd_accounts_cmk';c=next(c for c in CHECKS if c.id==cid);case=CASES[cid]
    index=deepcopy(case['pass_index']);index['storage_account'][0]['data']['properties']['encryption']['keySource']=source
    result,evidence=c.evaluate(deepcopy(case['pass']),index)
    assert result==status
    if status=='PASS':assert evidence['platform_key_vhd_accounts']==[]
