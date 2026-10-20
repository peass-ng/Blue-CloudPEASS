"""Reconcile independently sourced service candidates with native network plans.

Run after audit_network_service_inventory.py. This writes a review matrix, not
proof of a customer's live inventory or permission to call a cloud API.
"""
import json
from pathlib import Path
from peaso.collectors import aws, azure
from peaso.analysis.network_services import SERVICE_TYPES
from peaso.analysis.network import NETWORK_TYPES
from peaso.analysis.network_catalog import CONTROL_TYPES
from peaso.analysis.network_catalog import NETWORK_SERVICE_LABELS
from peaso.collectors.gcp_network_catalog import PRIVATE_SERVICES, REGIONAL

AWS_OTHER = {
    'accessanalyzer': ('derived_configuration', 'Access previews are hypothetical proposed configurations; native deployed resources are collected separately.'),
    'cloudhsm': ('legacy_api', 'Classic CloudHSM API; current cluster/network inventory uses cloudhsmv2, including HSM ENIs and subnets.'),
    'codecatalyst': ('separate_identity_domain', 'Bearer-authenticated developer-space API, not an IAM-role/account/region inventory. Named VPC connections require separate platform credentials; native EC2 endpoints remain collected.'),
    'codestar-connections': ('api_alias', 'CodeStar Connections is the earlier namespace for the CodeConnections host API; collect the canonical codeconnections host inventory.'),
    'es': ('api_alias', 'Earlier SDK alias for OpenSearch; canonical opensearch domain and VPC endpoint inventories are collected.'),
    'fms': ('derived_violation', 'GetViolationDetails describes findings; underlying deployed firewall, SG, EC2, ENI and endpoint resources have native inventories.'),
    'guardduty': ('derived_finding', 'Finding resource/network evidence is not a separate deployed attachment; native EC2/EKS resources are collected.'),
    'inspector': ('legacy_finding', 'Classic Inspector finding/resource descriptions; not an additional live VPC endpoint.'),
    'inspector2': ('derived_finding', 'Findings, export-job status and saved filters; not an additional live VPC asset.'),
    'iotfleetwise': ('logical_device_network', 'Vehicle decoder CAN/OBD network interfaces do not represent VPC attachments.'),
    'logs': ('log_parser_definition', 'GetTransformer describes parsed log-field schemas, not deployed cloud network interfaces.'),
    'securityhub': ('derived_finding', 'Findings/insight definitions reuse network structures; native assets are collected separately.'),
    'snow-device-management': ('physical_edge_device', 'Snow appliance physical interfaces/local instances are outside the IAM-account VPC attachment inventory.'),
    'wickr': ('logical_security_group', 'Wickr chat security groups are not EC2/VPC security groups.'),
}
GOOGLE_OTHER = {
    **dict.fromkeys({'adexchangebuyer2', 'dfareporting', 'displayvideo', 'datamanager', 'realtimebidding', 'searchads360'},
        ('advertising_product', 'Advertising network names/settings, not GCP VPC resources.')),
    **dict.fromkeys({'admin', 'cloudidentity'}, ('identity_product', 'Directory/device/identity configuration, not a native VPC endpoint.')),
    **dict.fromkeys({'androidenterprise', 'androidmanagement', 'chromemanagement'},
        ('device_configuration', 'Device Wi-Fi/VPN and network telemetry, not GCP VPC resources.')),
    **dict.fromkeys({'area120tables', 'contentwarehouse', 'datalabeling', 'mybusinessqanda', 'poly'},
        ('non_vpc_product', 'No native cloud VPC deployment represented by this product; discovery retrieval status remains recorded in the source census.')),
    'cloudasset': ('asset_evidence', 'Cloud Asset snapshots/history duplicate provider resource representations; use native service collectors for current attachments.'),
    'migrationcenter': ('assessment_evidence', 'Imported guest/assessment network data and cost estimates do not establish native GCP resource ownership.'),
    'rapidmigrationassessment': ('assessment_product', 'Assessment collectors describe external source environments; not an additional managed GCP VPC workload. Public discovery was unavailable during this audit.'),
    'pagespeedonline': ('web_diagnostic', 'Page-load network statistics, not a GCP VPC deployment.'),
    'securitycenter': ('derived_finding', 'SCC findings reference resources; native network/service APIs supply attachment metadata.'),
    'storagetransfer': ('transfer_source_protocol', 'Candidate is S3-compatible source networkProtocol; no native VPC/subnet/PSC attachment is exposed. Agent hosts are represented by their native compute resources.'),
    'testing': ('test_definition', 'Test Lab network profiles/settings are test definitions, not GCP VPC attachments.'),
}


def build(root):
    folder = root / 'docs/network-audit'
    result = {'basis': 'Installed AWS SDK read-output census; preferred Google public discovery directory; Microsoft Private Link DNS resource list; reviewed Kubernetes API groups.',
        'limits': ['This is a service-family reconciliation, not operation-for-operation API parity.',
            'A registered collector does not prove live assets or readable permissions.',
            'Aliases, history, simulations, catalogs and derived evidence do not create additional deployed network assets.',
            'Private API endpoints do not place the provider service backend inside the customer VPC.',
            'Separate SaaS identity domains and arbitrary unreviewed Kubernetes CRDs are not silently treated as collected.'],
        'aws': [], 'gcp': []}
    for provider, exceptions in [('aws', AWS_OTHER), ('gcp', GOOGLE_OTHER)]:
        census = json.loads((folder / (provider + '-api-network-candidates.json')).read_text())
        for row in census['services']:
            service = row['service']
            if provider == 'aws':
                kinds = sorted(k for k in NETWORK_TYPES if k in aws.SPECS and aws.SPECS[k][0] == service)
            else:
                kinds = sorted(k for k in SERVICE_TYPES['gcp'] if NETWORK_SERVICE_LABELS['gcp'].get(k) == service)
                kinds = sorted(set(kinds) | {k for k,p in PRIVATE_SERVICES.items() if p['service'] == service}
                    | {k for k,p in REGIONAL.items() if p[0] == service})
                # Existing native managed-service collectors predate the added manifest.
                kinds = sorted(set(kinds) | ((SERVICE_TYPES['gcp'] | CONTROL_TYPES['gcp']) & {
                    'compute': {'instance', 'instance_template', 'instance_group_manager'}, 'container': {'gke_cluster'},
                    'cloudfunctions': {'function'}, 'alloydb': {'alloydb_cluster','alloydb_instance'},
                    'composer': {'composer_environment'}, 'notebooks': {'workbench_instance'},
                    'file': {'filestore_instance'}, 'vpcaccess': {'vpc_access_connector'}, 'sqladmin': {'sql_instance'},
                    'storage': {'bucket'}, 'accesscontextmanager': {'service_perimeter'},
                }.get(service,set())))
            classification, reason = exceptions.get(service, ('native_network_inventory', 'Native network/service metadata is registered for collection, topology and agent projection.'))
            if classification == 'native_network_inventory' and not kinds:
                raise ValueError('Undispositioned service family: ' + provider + '/' + service)
            result[provider].append({'service': service, 'classification': classification, 'reason': reason,
                'network_types': kinds, 'source': row.get('reference') or 'https://docs.aws.amazon.com/cli/latest/reference/' + service + '/',
                **({'discovery_status': row['status']} if 'status' in row else {})})
    census = json.loads((folder / 'azure-private-link-candidates.json').read_text())
    result['azure'] = [{'resource_type': native, 'classification': 'native_arm_inventory',
        'network_types': sorted(k for k,(t,_) in azure.ENDPOINTS.items() if t.casefold() == native.casefold()),
        'source': census['reference']} for native in census['resource_types']]
    if any(not row['network_types'] for row in result['azure']):
        raise ValueError('Azure Private Link type has no native network plan')
    result['k8s'] = []
    for name in ('k8s_network_extensions.json','k8s_network_route_extensions.json'):
        for kind, (groups, plural, namespace) in json.loads((root/'peaso/collectors'/name).read_text()).items():
            result['k8s'].append({'network_type':kind,'groups':groups,'resource':plural,'namespaced':namespace,
                'classification':'served_api_discovery_and_native_list'})
    (folder/'service-dispositions.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('Reconciled service candidates:', {provider:len(result[provider]) for provider in ('aws','gcp','azure','k8s')})


if __name__ == '__main__':
    build(Path(__file__).resolve().parents[1])
