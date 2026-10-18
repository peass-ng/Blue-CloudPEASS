import copy,json
from pathlib import Path
import pytest
from peaso.checks import CHECKS,evaluate_check
from peaso.collectors import bulk_evidence
from peaso.snapshot import make_snapshot

MANIFEST=json.loads(Path('peaso/checks/bulk_pending.json').read_text())
# Reviewed native collection successors preserve the frozen authoring manifest.
DEPENDENCY_SUCCESSORS = {
 'aws_log_archive_immutable': (['s3_bucket', 'cloudtrail'], ['s3_bucket', 'cloudtrail_account_inventory']),
 'aws_nist_apigateway_stage_logging_enabled': (['http_api_stage', 'rest_api_stage'], ['http_api_stage', 'rest_api_stage', 'rest_api_method']),
 'aws_nist_cloudtrail_trail_integrated_with_logs': (['cloudtrail_account_inventory', 'log_group', 'cloudtrail_delivery_role_scope'], ['cloudtrail_account_inventory', 'log_group']),
}

def test_all_signed_pending_ids_are_unique_and_registered_once():
 ids=[c.id for c in CHECKS];assert len(ids)==len(set(ids))
 baseline=MANIFEST['baseline_native_checks']
 held={
  'aws.route53resolver.query_log_config_delivery_ready',
  'aws.organizations.resource_tag_policy_compliance',
  'aws.organizations.effective_tag_policy_values',
  'azure.vm.iaas_antimalware_extension_minor_version_selection',
 }
 assert not held.intersection(ids)
 assert len(ids)==baseline+len(MANIFEST['checks'])
 assert set(ids[baseline:])==set(MANIFEST['checks'])
 assert set(MANIFEST['checks'])<=set(ids)
 for c in CHECKS:
  if c.id in MANIFEST['checks']:
   r=MANIFEST['checks'][c.id]
   expected = r['dependencies']
   if c.id in DEPENDENCY_SUCCESSORS:
    original, expected = DEPENDENCY_SUCCESSORS[c.id]
    assert r['dependencies'] == original
   assert (c.provider,c.kind,c.dependencies)==(r['provider'],r['kind'],expected)

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
