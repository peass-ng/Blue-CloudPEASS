"""Owner criteria survive public intake; observations remain collector-only."""
import copy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import json
import pytest
from fastapi import HTTPException
from peaso.azure_sw32_policy import normalize_sw32
from peaso.collectors import azure
from peaso.server.validation import validate_connector
from tests.test_peaso_azure_bulk_native import SCOPE,BASE,Transport

GUID='11111111-2222-3333-4444-555555555555'
FOREIGN='99999999-9999-9999-9999-999999999999'
ROLE=SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+GUID
WORKSPACE=BASE+'Microsoft.OperationalInsights/workspaces/logs'
DASHBOARD=BASE+'Microsoft.Portal/dashboards/dashboard'
PEER='/subscriptions/'+FOREIGN+'/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/peer'
FIELDS={
 'acr_max_untagged_days':30,
 'later_stage_deployment_limit':0,
 'max_registry_scan_age_seconds':86400,
 'registry_vulnerability_assessment_key':'expected-assessment-v1',
 'approved_cosmos_workspaces':[WORKSPACE],
 'required_role_assignments':[{'principalId':GUID,'roleDefinitionId':ROLE,'scope':SCOPE}],
 'approved_key_algorithms':{'industry_standard_confirmed':True,'minimum_rsa_bits':3072,'approved_ec_curves':['P-256','P-384','P-521','P-256K']},
 'sensitive_dashboard_ids':[DASHBOARD],
 'approved_dashboard_viewers':[GUID],
 'approved_peer_ids':[PEER],
}

def policy(**fields):return {'status':'collected','scope':SCOPE,**copy.deepcopy(fields)}
def options(value):return {'retries':1,'compliance_policy':{'sw32':value}}

@pytest.mark.parametrize('key',list(FIELDS))
def test_each_existing_consumer_criterion_accepted_hosted_local_and_public_collector(key):
 value=policy(**{key:FIELDS[key]});original=copy.deepcopy(value)
 for mode in ('local','cognito'):
  validate_connector('azure',{'method':'token','arm_token':'controlled-arm-token'},options(value),SimpleNamespace(auth_mode=mode))
 result=normalize_sw32(value,expected_scope=SCOPE.upper());assert result==value and result is not value
 snap=azure.collect({'scopes':[SCOPE],'options':options(value)},['storage_account'],transport=Transport({SCOPE+'/providers/Microsoft.Storage/storageAccounts':{'value':[]}}))
 assert snap['metadata']['compliance_policy']['sw32']==value
 assert value==original
 assert all(name not in json.dumps(snap['metadata']['compliance_policy']['sw32'])for name in ('rbac_relevant_scopes_complete','finding_coverage_complete','unapproved_peering_prevention'))


def test_mixed_new_and_legacy_criteria_copy_purity_and_real_api_roundtrip(tmp_path):
 now=datetime.now(timezone.utc)
 value=policy(**FIELDS,incident_review={'start':(now-timedelta(days=1)).isoformat(),'end':now.isoformat(),'approved':True,'allowed_classifications':['TruePositive'],'allowed_priorities':['High']},vulnerability_severity_criteria={'approved':True,'version':'v1','expectedSeverityByAssessmentName':{GUID:'High'}})
 original=copy.deepcopy(value);result=normalize_sw32(value)
 result['approved_cosmos_workspaces'].clear();result['required_role_assignments'][0]['principalId']=FOREIGN
 assert value==original
 from fastapi.testclient import TestClient
 from peaso.server import create_app
 from peaso.server.config import Settings
 from tests.test_peaso_api import TestIdentities
 settings=Settings(state_dir=tmp_path/'state',identity_dir=tmp_path/'identity',local_token='controlled-local-api-token')
 with TestClient(create_app(settings,authenticator=TestIdentities()),base_url='http://127.0.0.1:8000')as client:
  client.headers['Authorization']='Bearer alice'
  response=client.post('/api/connectors',json={'name':'Explicit SW32 criteria','provider':'azure','scopes':[SCOPE.split('/')[-1]],'auth':{'method':'token','arm_token':'controlled-arm-token'},'options':options(value)})
  assert response.status_code==201,response.text
  assert response.json()['options']['compliance_policy']['sw32']==value
  fetched=client.get('/api/connectors/'+response.json()['id']);assert fetched.status_code==200
  assert fetched.json()['options']['compliance_policy']['sw32']==value
 assert value==original

@pytest.mark.parametrize('field',['acr_max_untagged_days','later_stage_deployment_limit','max_registry_scan_age_seconds'])
@pytest.mark.parametrize('bad',[True,False,1.5,'30',None,-1,2**53])
def test_integer_criteria_reject_bool_and_nonintegers(field,bad):
 with pytest.raises(ValueError):normalize_sw32(policy(**{field:bad}))

@pytest.mark.parametrize('field,minimum',[('acr_max_untagged_days',1),('later_stage_deployment_limit',0),('max_registry_scan_age_seconds',1)])
def test_exact_integer_boundaries(field,minimum):
 assert normalize_sw32(policy(**{field:minimum}))[field]==minimum
 assert normalize_sw32(policy(**{field:2**53-1}))[field]==2**53-1
 if minimum:
  with pytest.raises(ValueError):normalize_sw32(policy(**{field:0}))

@pytest.mark.parametrize('field',['approved_cosmos_workspaces','sensitive_dashboard_ids','approved_peer_ids','approved_dashboard_viewers'])
@pytest.mark.parametrize('mode',['duplicate','wrongtype','wrongkind','query','fragment','escape','traversal','trailing','overcount'])
def test_approved_id_lists_are_strict_unique_bounded(field,mode):
 raw=copy.deepcopy(FIELDS[field]);first=raw[0]
 if mode=='duplicate':raw.append(first.upper())
 if mode=='wrongtype':raw=[True]
 if mode=='wrongkind':raw=[GUID if field!='approved_dashboard_viewers'else WORKSPACE]
 if mode=='query':raw=[first+'?foo=1']
 if mode=='fragment':raw=[first+'#foreign']
 if mode=='escape':raw=[first.replace('/providers/','/%70roviders/')]if field!='approved_dashboard_viewers'else['%31'+first[1:]]
 if mode=='traversal':raw=[first+'/../other']
 if mode=='trailing':raw=[first+'/']
 if mode=='overcount':raw=[first]*257
 with pytest.raises(ValueError):normalize_sw32(policy(**{field:raw}))

@pytest.mark.parametrize('field',['approved_cosmos_workspaces','sensitive_dashboard_ids','approved_peer_ids','approved_dashboard_viewers','required_role_assignments'])
def test_empty_normative_allowlist_is_not_an_inventory_assertion(field):
 assert normalize_sw32(policy(**{field:[]}))[field]==[]

@pytest.mark.parametrize('bad',['',None,True,'name/child','name?query','%6eame','x'*129])
def test_assessment_selector_name_is_bounded_not_fabricated_proof(bad):
 with pytest.raises(ValueError):normalize_sw32(policy(registry_vulnerability_assessment_key=bad))

@pytest.mark.parametrize('field,bad',[('industry_standard_confirmed',False),('industry_standard_confirmed',1),('minimum_rsa_bits',True),('minimum_rsa_bits',1024),('minimum_rsa_bits',2**53),('approved_ec_curves',[]),('approved_ec_curves',['P-192']),('approved_ec_curves',['P-256','p-256']),('algorithm_policy_approved',True),('encryption_use',True),('import_provenance','generated')])
def test_crypto_approval_rejects_unsafe_or_observed_fields(field,bad):
 value=copy.deepcopy(FIELDS['approved_key_algorithms']);value[field]=bad
 with pytest.raises(ValueError):normalize_sw32(policy(approved_key_algorithms=value))

@pytest.mark.parametrize('mutation',['principal','role','roleforeignpath','scopeforeign','scopetraversal','badprovider','badpair','duplicate','extra','missing'])
def test_required_assignment_exact_tuple_identity_and_scope(mutation):
 rows=copy.deepcopy(FIELDS['required_role_assignments']);row=rows[0]
 if mutation=='principal':row['principalId']='not-a-guid'
 if mutation=='role':row['roleDefinitionId']=ROLE.replace('roleDefinitions','roleAssignments')
 if mutation=='roleforeignpath':row['roleDefinitionId']=ROLE+'/foreign'
 if mutation=='scopeforeign':row['scope']=SCOPE.replace(SCOPE.split('/')[-1],FOREIGN)
 if mutation=='scopetraversal':row['scope']=SCOPE+'/resourceGroups/../rg'
 if mutation=='badprovider':row['scope']=SCOPE+'/providers/invalid/type/name'
 if mutation=='badpair':row['scope']=SCOPE+'/providers/Microsoft.Compute/virtualMachines'
 if mutation=='duplicate':rows.append({k:v.upper()for k,v in row.items()})
 if mutation=='extra':row['observed']=True
 if mutation=='missing':row.pop('scope')
 with pytest.raises(ValueError):normalize_sw32(policy(required_role_assignments=rows))

@pytest.mark.parametrize('prefix',['','/subscriptions/'+FOREIGN,'/providers/Microsoft.Management/managementGroups/approved'])
def test_role_definition_root_crosssubscription_and_management_group_are_normative(prefix):
 row={'principalId':GUID,'roleDefinitionId':prefix+'/providers/Microsoft.Authorization/roleDefinitions/'+GUID,'scope':SCOPE}
 assert normalize_sw32(policy(required_role_assignments=[row]))['required_role_assignments']==[row]

@pytest.mark.parametrize('scope',[SCOPE,SCOPE+'/resourceGroups/rg',SCOPE+'/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm',SCOPE+'/providers/Microsoft.Authorization/policyAssignments/policy','/providers/Microsoft.Management/managementGroups/approved'])
def test_approved_assignment_scope_is_not_observed_ancestry(scope):
 row={**FIELDS['required_role_assignments'][0],'scope':scope}
 assert normalize_sw32(policy(required_role_assignments=[row]))['required_role_assignments']==[row]

@pytest.mark.parametrize('field',['rbac_relevant_scopes_complete','unapproved_peering_prevention','provenance','_provenance','coverage','findings','finding_coverage_complete','native_status','unknown'])
def test_observation_injection_rejected_through_hosted_and_local_intake(field):
 value=policy(**FIELDS);value[field]=True
 with pytest.raises(ValueError):normalize_sw32(value)
 for mode in ('local','cognito'):
  with pytest.raises(HTTPException):validate_connector('azure',{'method':'token','arm_token':'controlled-arm-token'},options(value),SimpleNamespace(auth_mode=mode))
 with pytest.raises(ValueError):azure.collect({'scopes':[SCOPE],'options':options(value)},['storage_account'],transport=Transport({}))


def test_policy_scope_and_total_bounds_preserved():
 with pytest.raises(ValueError):normalize_sw32(policy(**FIELDS),expected_scope='/subscriptions/'+FOREIGN)
 with pytest.raises(ValueError):normalize_sw32({'status':'collected','scope':SCOPE})
 value=policy(approved_peer_ids=[PEER[:-4]+'peer'+str(i)+'a'*250 for i in range(256)])
 with pytest.raises(ValueError):normalize_sw32(value)


def test_criteria_do_not_produce_missing_rbac_or_scan_observations():
 from tests.archived_check_contract import evaluate_snapshot
 from peaso.snapshot import make_snapshot
 # The concrete current SW32 IDs are selected from their reviewed declaration, without importing drafts.
 from pathlib import Path
 import ast
 module=Path(__file__).resolve().parents[1]/'peaso/checks/compliance_new_sw32.py'
 specs=next(ast.literal_eval(n.value)for n in ast.parse(module.read_text()).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='SPECS'for t in n.targets))
 selected=[cid for cid,row in specs.items()if row.get('resource_kind')in {'vault_key','container_registry','role_assignment','dashboard','vnet','devops_project'}]
 assert selected
 snap=make_snapshot('azure',[SCOPE],[{'type':kind,'scope':SCOPE,'status':'not_collected','items':[]}for kind in ('vault_key','container_registry','role_assignment','role_definition','dashboard','vnet','devops_project')],metadata={'compliance_policy':{'sw32':policy(**FIELDS)}})
 report=evaluate_snapshot(snap,checks=selected)
 assert report['findings']and all(row['status']=='UNKNOWN'for row in report['findings'])
