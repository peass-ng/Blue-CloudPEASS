import copy,json
from pathlib import Path
import pytest
from peaso.checks import CHECKS,evaluate_check
from peaso.collectors import bulk_evidence
from peaso.snapshot import make_snapshot
from scripts.peaso_compliance_compile import verified_file
from scripts.peaso_compliance_compile import REVIEWED_NATIVE_ALIASES_20261021
from tests.release_successor_history import registered_before_bulk

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=json.loads((ROOT/'peaso/checks/bulk_pending.json').read_text())
# Reviewed native collection successors preserve the frozen authoring manifest.
DEPENDENCY_SUCCESSORS = {
 'aws_log_archive_immutable': (['s3_bucket', 'cloudtrail'], ['s3_bucket', 'cloudtrail_account_inventory']),
 'aws_nist_apigateway_stage_logging_enabled': (['http_api_stage', 'rest_api_stage'], ['http_api_stage', 'rest_api_stage', 'rest_api_method']),
 'aws_nist_cloudtrail_trail_integrated_with_logs': (['cloudtrail_account_inventory', 'log_group', 'cloudtrail_delivery_role_scope'], ['cloudtrail_account_inventory', 'log_group']),
 # Native managed-policy documents join by ARN; delivery metadata is retained
 # on the account trail inventory rather than a generic bucket projection.
 'aws_cis_lambda_execution_role_no_admin': (['lambda_function', 'iam_role'], ['lambda_function', 'iam_role', 'iam_policy']),
 'aws_cloudtrail_s3_siem_delivery': (['cloudtrail_account_inventory', 'bucket'], ['cloudtrail_account_inventory']),
 # Reviewed Azure identity, full native AKS Pod/Namespace, HTTP-log and
 # Synapse evidence successors; signed predecessor dependencies stay intact.
 'azure.cis.multifactor_auth_status_privileged_users': (['directory_user', 'conditional_access_policy'], ['directory_user', 'conditional_access_policy', 'azure_identity_enforcement_native']),
 'azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9': (['directory_user', 'conditional_access_policy'], ['directory_user', 'conditional_access_policy', 'azure_identity_enforcement_native']),
 'azure_directory_user_entra_privileged_user_has_mfa_6f6d584': (['directory_user', 'conditional_access_policy'], ['directory_user', 'conditional_access_policy', 'azure_identity_enforcement_native']),
 'azure_directory_user_7_2_1_19_28e2aa7': (['directory_user'], ['directory_user', 'azure_identity_enforcement_native']),
 'azure_aks_cluster_7_2_1_6_93c4fab': (['aks_cluster'], ['aks_cluster', 'aks_legacy_pod_inventory']),
 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524': (['aks_cluster'], ['aks_cluster', 'aks_legacy_pod_inventory']),
 'azure_application_gateway_app_http_logs_enabled_2de0361': (['application_gateway', 'load_balancer', 'diagnostic_setting', 'diagnostic_category', 'log_analytics_workspace', 'storage_account'], ['application_gateway', 'diagnostic_setting', 'diagnostic_category', 'log_analytics_workspace', 'storage_account']),
 'azure_pci_1_3_1_33': (['synapse_workspace'], ['synapse_workspace', 'synapse_sql_private_endpoint_evidence']),
}

# HTTP access-log evidence is scoped to Application Gateways; native Layer4
# LoadBalancer health logging cannot satisfy that reviewed criterion.
KIND_SUCCESSORS = {
 'azure_application_gateway_app_http_logs_enabled_2de0361': ('application_gateway_and_load_balancer', 'application_gateway'),
}

def test_all_signed_pending_ids_are_unique_and_registered_once():
 ids=[c.id for c in CHECKS];assert len(ids)==len(set(ids))
 baseline=MANIFEST['baseline_native_checks']
 original={c.id for c in registered_before_bulk(CHECKS)}
 bulk=set(MANIFEST['checks'])
 assert len(original)==baseline==3434 and len(bulk)==552
 retired=set(REVIEWED_NATIVE_ALIASES_20261021)
 assert retired <= original
 original -= retired
 ledger=ROOT/'docs/compliance-ledgers'
 supervisor=json.loads((ledger/'manifest.json').read_bytes())
 extension_ids=[]
 extension_paths=[]
 for entry in supervisor['native_extensions']:
  # Check the supervisor's approval and exact file hash before using its IDs.
  document,_=verified_file(ledger,entry,prefix='native-extensions/')
  assert document['schema_version']==1
  extension_paths.append(entry['path'])
  extension_ids.extend(row['spec']['id'] for row in document['checks'])
 assert len(extension_paths)==len(set(extension_paths))
 assert len(extension_ids)==len(set(extension_ids))
 extensions=set(extension_ids)
 assert not original & bulk and not (original|bulk) & extensions
 held={
  'aws.route53resolver.query_log_config_delivery_ready',
  'aws.organizations.resource_tag_policy_compliance',
  'aws.organizations.effective_tag_policy_values',
  'azure.vm.iaas_antimalware_extension_minor_version_selection',
 }
 assert not held.intersection(ids)
 assert set(ids[:len(original)])==original
 assert len(ids)==3434-len(retired)+552+len(extensions)
 assert set(ids[len(original):])==bulk|extensions
 assert set(ids)==original|bulk|extensions
 for c in CHECKS:
  if c.id in MANIFEST['checks']:
   r=MANIFEST['checks'][c.id]
   expected = r['dependencies']
   if c.id in DEPENDENCY_SUCCESSORS:
    original, expected = DEPENDENCY_SUCCESSORS[c.id]
    assert r['dependencies'] == original
   expected_kind = r['kind']
   if c.id in KIND_SUCCESSORS:
    original_kind, expected_kind = KIND_SUCCESSORS[c.id]
    assert r['kind'] == original_kind
   assert (c.provider,c.kind,c.dependencies)==(r['provider'],expected_kind,expected)

@pytest.mark.parametrize('ident',MANIFEST['checks'])
def test_each_new_definition_rejects_absent_and_denied_input(ident):
 for data in ({},None,{'collection_status':'denied'}):assert evaluate_check(ident,data,{})[0]=='UNKNOWN'

def test_unavailable_projection_is_not_an_empty_success_and_alias_uses_native_data():
 class Provider:
  AWS_TYPES={'bucket'}
  def collect(self,config,requirements):return make_snapshot('aws',['123456789012/global'],[{'type':'bucket','scope':'123456789012/global','status':'collected','items':[{'Name':'native-bucket'}]}])
 connector={'provider':'aws','options':{'inventories':['s3_bucket','aws_data_resource_coverage']}}
 result=bulk_evidence.collect(Provider(),connector,['s3_bucket','aws_data_resource_coverage'])
 aliases=[c for c in result['collections']if c['type']=='s3_bucket'];assert len(aliases)==1 and aliases[0]['items']==[{'Name':'native-bucket'}]
 gap=next(c for c in result['collections']if c['type']=='aws_data_resource_coverage');assert gap['status']=='not_collected'and gap['items']==[]
 assert result['metadata']['intentional_partial']is True

@pytest.mark.parametrize('options',[
 {'inventories':'bucket'}, {'inventories':[{}]},
 {'compliance_parameters':{'expiry':float('nan')}},
 {'compliance_parameters':{'token':'x'*50001}},
 {'compliance_policy':[]},
])
def test_invalid_bulk_options_are_rejected_before_provider_calls(options):
 class Provider:
  AWS_TYPES={'bucket'}
  def collect(self,*args):raise AssertionError('provider must not be called')
 with pytest.raises(ValueError):bulk_evidence.collect(Provider(),{'provider':'aws','options':options},[])

def test_public_catalog_separates_declared_contracts_from_native_collection():
 from peaso.engine import get_catalog
 catalog=get_catalog()
 for provider,row in catalog['inventory_coverage'].items():
  assert not set(row['native_types']) & set(row['unavailable_projections'])
  assert not set(row['unavailable_projections']) & set(catalog['inventories'][provider])
  assert all(c.category in catalog['categories'] for c in CHECKS if c.provider==provider)

@pytest.mark.parametrize('value',[{'expiry':float('nan')}, {'expiry':float('inf')}, ['invalid'], {'text':'x'*50001}])
def test_invalid_parameters_return_a_validation_error(value):
 from types import SimpleNamespace
 from fastapi import HTTPException
 from peaso.server.validation import validate_connector
 with pytest.raises(HTTPException) as failure:
  validate_connector('aws',{}, {'compliance_parameters':value}, SimpleNamespace(auth_mode='local'))
 assert failure.value.status_code==422

@pytest.mark.parametrize('status',['denied','partial','unknown','empty'])
def test_alias_preserves_native_scope_and_collection_failure(status):
 class Provider:
  AWS_TYPES={'bucket'}
  def collect(self,config,requirements):
   assert requirements==['bucket']
   assert config['options']['inventories']==['bucket']
   return make_snapshot('aws',['123456789012/global'],[{'type':'bucket','scope':'123456789012/global','status':status,'items':[]}])
 connector={'provider':'aws','options':{'inventories':['s3_bucket']}}
 before=copy.deepcopy(connector)
 result=bulk_evidence.collect(Provider(),connector,['s3_bucket'])
 row=next(c for c in result['collections']if c['type']=='s3_bucket')
 assert (row['scope'],row['status'],row['items'])==('123456789012/global',status,[])
 assert connector==before
