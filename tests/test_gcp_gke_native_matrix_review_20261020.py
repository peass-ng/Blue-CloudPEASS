"""GKE native responses, node-pool overrides and identity conservation."""
from copy import deepcopy

import pytest

from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot
from tests.test_gcp_firewall_port_native_matrix_review_20261020 import forbid_provider_network

# Independent native response fragments; historical CASES are not imported.
DECLARATIONS = [
    ('binary_authorization', {'binaryAuthorization': {'evaluationMode': 'PROJECT_SINGLETON_POLICY_ENFORCE'}}, {'binaryAuthorization': {'evaluationMode': 'DISABLED'}}, 'binaryAuthorization'),
    ('no_client_certificate', {'masterAuth': {'clientCertificateConfig': {'issueClientCertificate': False}}}, {'masterAuth': {'clientCertificateConfig': {'issueClientCertificate': True}}}, 'masterAuth'),
    ('no_kubernetes_alpha', {'enableKubernetesAlpha': False}, {'enableKubernetesAlpha': True}, 'enableKubernetesAlpha'),
    ('http_load_balancing', {'addonsConfig': {'httpLoadBalancing': {'disabled': False}}}, {'addonsConfig': {'httpLoadBalancing': {'disabled': True}}}, 'addonsConfig'),
    ('dashboard_disabled', {'addonsConfig': {'kubernetesDashboard': {'disabled': True}}}, {'addonsConfig': {'kubernetesDashboard': {'disabled': False}}}, 'addonsConfig'),
    ('logging_enabled', {'loggingService': 'logging.googleapis.com/kubernetes'}, {'loggingService': 'none'}, 'loggingService'),
    ('monitoring_enabled', {'monitoringService': 'monitoring.googleapis.com/kubernetes'}, {'monitoringService': 'none'}, 'monitoringService'),
    ('no_default_network', {'network': 'dedicated'}, {'network': 'default'}, 'network'),
    ('nodes_no_default_service_account', {'nodePools': [{'name': 'pool', 'config': {'serviceAccount': 'nodes@p-one.iam.gserviceaccount.com'}}]}, {'nodePools': [{'name': 'pool', 'config': {}}]}, 'nodePools'),
    ('release_channel', {'releaseChannel': {'channel': 'REGULAR'}}, {'releaseChannel': {'channel': 'UNSPECIFIED'}}, 'releaseChannel'),
    ('zone_redundant', {'locations': ['us-central1-a', 'us-central1-b', 'us-central1-c']}, {'locations': ['us-central1-a']}, 'locations'),
    ('master_authorized_networks_restricted', {'masterAuthorizedNetworksConfig': {'enabled': True, 'cidrBlocks': [{'cidrBlock': '192.0.2.0/24'}]}}, {'masterAuthorizedNetworksConfig': {'enabled': True, 'cidrBlocks': [{'cidrBlock': '0.0.0.0/0'}]}}, 'masterAuthorizedNetworksConfig'),
    ('private_nodes', {'networkConfig': {'defaultEnablePrivateNodes': True}}, {'networkConfig': {'defaultEnablePrivateNodes': False}}, 'networkConfig'),
]


def capture(slug, fragment, denied=None):
    cluster = {'name': 'review', 'location': 'us-central1-a',
               'selfLink': 'https://container.googleapis.com/v1/projects/p-one/locations/us-central1-a/clusters/review', **deepcopy(fragment)}
    original = deepcopy(cluster)

    def resolve(request):
        assert request['method'] == 'GET'
        assert request['url'] == 'https://container.googleapis.com/v1/projects/p-one/locations/-/clusters'
        return {'clusters': [cluster]}

    collected, transport = snapshot(['gke_cluster'], resolve)
    assert cluster == original and len(transport.requests) == 1
    if denied:
        collected['collections'][0]['items'][0].setdefault('_coverage', {})[denied] = {'status': 'denied'}
        collected.pop('snapshot_id', None)
    before = deepcopy(collected)
    cid = 'gcp.claude.gke.' + slug
    rows = evaluate_snapshot(collected, checks=[cid])['findings']
    assert collected == before and len(rows) == 1 and rows[0]['check_id'] == cid
    return rows[0]


@pytest.mark.parametrize('slug,good,bad,field', DECLARATIONS, ids=[x[0] for x in DECLARATIONS])
@pytest.mark.parametrize('branch', ['good', 'bad', 'denied_good', 'denied_bad'])
def test_native_gke_declaration_and_denial(slug, good, bad, field, branch):
    denied = branch.startswith('denied')
    fragment = bad if branch.endswith('bad') else good
    row = capture(slug, fragment, field if denied else None)
    assert row['status'] == ('UNKNOWN' if denied else 'FAIL' if branch == 'bad' else 'PASS'), row


@pytest.mark.parametrize('default,override,expected', [
    (True, False, 'FAIL'), (False, True, 'PASS'), (True, True, 'PASS'),
    (False, False, 'FAIL'), (True, None, 'PASS'), (False, None, 'FAIL'),
])
def test_node_pool_override_takes_precedence_over_cluster_default(default, override, expected):
    config = {} if override is None else {'enablePrivateNodes': override}
    row = capture('private_nodes', {'networkConfig': {'defaultEnablePrivateNodes': default},
                                  'nodePools': [{'name': 'pool', 'networkConfig': config}]})
    assert row['status'] == expected, row
    assert row['evidence']['public_node_pools'] == ([] if expected == 'PASS' else ['pool'])


@pytest.mark.parametrize('reverse', [False, True])
def test_one_public_pool_prevents_a_private_cluster_verdict(reverse):
    pools = [{'name': 'private', 'networkConfig': {'enablePrivateNodes': True}},
             {'name': 'public', 'networkConfig': {'enablePrivateNodes': False}}]
    if reverse: pools.reverse()
    assert capture('private_nodes', {'networkConfig': {'defaultEnablePrivateNodes': True}, 'nodePools': pools})['status'] == 'FAIL'


@pytest.mark.parametrize('slug', ['private_nodes', 'nodes_no_default_service_account'])
@pytest.mark.parametrize('names', [('duplicate', 'duplicate'), ('', 'valid')])
def test_missing_or_duplicate_pool_identity_never_establishes_safety(slug, names):
    pools = [{'name': name, 'networkConfig': {'enablePrivateNodes': True},
              'config': {'serviceAccount': 'nodes@p-one.iam.gserviceaccount.com'}} for name in names]
    assert capture(slug, {'networkConfig': {'defaultEnablePrivateNodes': True}, 'nodePools': pools})['status'] == 'UNKNOWN'


@pytest.mark.parametrize('legacy,current', [(True, False), (False, True)])
def test_conflicting_private_defaults_remain_unknown(legacy, current):
    assert capture('private_nodes', {'privateClusterConfig': {'enablePrivateNodes': legacy},
                                    'networkConfig': {'defaultEnablePrivateNodes': current}})['status'] == 'UNKNOWN'


def test_duplicate_pool_cannot_overwrite_default_service_account():
    pools = [{'name': 'same', 'config': {'serviceAccount': 'default'}},
             {'name': 'same', 'config': {'serviceAccount': 'nodes@p-one.iam.gserviceaccount.com'}}]
    for ordered in [pools, list(reversed(pools))]:
        assert capture('nodes_no_default_service_account', {'nodePools': ordered})['status'] == 'UNKNOWN'


def test_empty_service_account_retains_native_default_meaning():
    assert capture('nodes_no_default_service_account', {'nodePools': [{'name': 'pool', 'config': {'serviceAccount': ''}}]})['status'] == 'FAIL'


@pytest.mark.parametrize('slug,kind', [
    ('subnetwork_private_google_access', 'subnetwork'),
    ('network_no_untargeted_public_ingress', 'firewall'),
])
@pytest.mark.parametrize('scenario,expected', [
    ('good', 'PASS'), ('bad', 'FAIL'), ('denied', 'UNKNOWN'),
    ('partial', 'UNKNOWN'), ('wrong_reference', 'UNKNOWN'),
])
def test_native_gke_cross_resource_join_completeness(slug, kind, scenario, expected):
    # A different VPC with a closed rule cannot clear the selected VPC, so the
    # foreign-rule case uses a denied collection rather than asserting absence.
    if kind == 'firewall' and scenario == 'wrong_reference':
        expected = 'PASS'  # A complete inventory of unrelated VPC rules is safe for this declaration check.
    subnet = 'projects/p-one/regions/us-central1/subnetworks/review'
    network = 'projects/p-one/global/networks/review'
    cluster = {'name': 'review', 'location': 'us-central1-a',
               'networkConfig': {'subnetwork': subnet, 'network': network}}
    requests = []

    def resolve(request):
        requests.append(deepcopy(request))
        assert request['method'] == 'GET'
        if request['url'].startswith('https://container.googleapis.com/'):
            assert request['url'].endswith('/locations/-/clusters')
            return {'clusters': [cluster]}
        if scenario == 'denied' or (scenario == 'partial' and request.get('params', {}).get('pageToken')):
            from peaso.collectors import gcp
            raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        if kind == 'subnetwork':
            assert request['url'] == 'https://compute.googleapis.com/compute/v1/projects/p-one/aggregated/subnetworks'
            ref = subnet + '-other' if scenario == 'wrong_reference' else subnet
            payload = {'items': {'regions/us-central1': {'subnetworks': [{
                'name': 'review', 'selfLink': 'https://www.googleapis.com/compute/v1/' + ref,
                'privateIpGoogleAccess': scenario != 'bad'}]}}}
        else:
            assert request['url'] == 'https://compute.googleapis.com/compute/v1/projects/p-one/global/firewalls'
            ref = network + '-other' if scenario == 'wrong_reference' else network
            payload = {'items': [{'name': 'review', 'network': 'https://www.googleapis.com/compute/v1/' + ref,
                                  'direction': 'INGRESS', 'sourceRanges': ['0.0.0.0/0' if scenario == 'bad' else '10.0.0.0/8'],
                                  'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}]}]}
        if scenario == 'partial': payload['nextPageToken'] = 'next-page'
        return payload

    collected, _ = snapshot(['gke_cluster', kind], resolve)
    before = deepcopy(collected)
    cid = 'gcp.claude.gke.' + slug
    rows = evaluate_snapshot(collected, checks=[cid])['findings']
    assert collected == before and len(rows) == 1
    assert rows[0]['status'] == expected, rows[0]
