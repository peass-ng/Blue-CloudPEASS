"""Core GKE configuration declarations remain undecided on contradictory facts."""
from copy import deepcopy

import pytest

from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot
from tests.test_gcp_firewall_port_native_matrix_review_20261020 import forbid_provider_network

DECLARATIONS = [
    ('no_legacy_abac', {'legacyAbac': {'enabled': False}}, {'legacyAbac': {'enabled': True}}, 'legacyAbac'),
    ('private_endpoint', {'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'enablePublicEndpoint': False}}}, {'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'enablePublicEndpoint': True}}}, 'controlPlaneEndpointsConfig'),
    ('shielded_nodes', {'shieldedNodes': {'enabled': True}}, {'shieldedNodes': {'enabled': False}}, 'shieldedNodes'),
    ('private_nodes', {'networkConfig': {'defaultEnablePrivateNodes': True}}, {'networkConfig': {'defaultEnablePrivateNodes': False}}, 'networkConfig'),
    ('authorized_networks', {'masterAuthorizedNetworksConfig': {'enabled': True}}, {'masterAuthorizedNetworksConfig': {'enabled': False}}, 'masterAuthorizedNetworksConfig'),
    ('network_policy', {'networkPolicy': {'enabled': True}}, {'networkPolicy': {'enabled': False}}, 'networkPolicy'),
    ('workload_identity', {'workloadIdentityConfig': {'workloadPool': 'p-one.svc.id.goog'}}, {'workloadIdentityConfig': {}}, 'workloadIdentityConfig'),
    ('node_pools_gke_metadata', {'nodePools': [{'name': 'review', 'config': {'workloadMetadataConfig': {'mode': 'GKE_METADATA'}}}]}, {'nodePools': [{'name': 'review', 'config': {'workloadMetadataConfig': {'mode': 'GCE_METADATA'}}}]}, 'nodePools'),
    ('secrets_encryption', {'databaseEncryption': {'state': 'ENCRYPTED'}}, {'databaseEncryption': {'state': 'DECRYPTED'}}, 'databaseEncryption'),
]


def capture(slug, fragment, denied=None):
    cluster = {'name': 'review', 'location': 'us-central1-a', **deepcopy(fragment)}
    def resolve(request):
        assert request['method'] == 'GET'
        assert request['url'] == 'https://container.googleapis.com/v1/projects/p-one/locations/-/clusters'
        return {'clusters': [cluster]}
    collected, transport = snapshot(['gke_cluster'], resolve)
    if denied:
        row = collected['collections'][0]['items'][0]
        parts = denied.split('.')
        for key in parts[:-1]: row = row[key]
        row.setdefault('_coverage', {})[parts[-1]] = {'status': 'denied'}
        collected.pop('snapshot_id', None)
    before = deepcopy(collected)
    rows = evaluate_snapshot(collected, checks=['gcp.gke.' + slug])['findings']
    assert len(transport.requests) == 1 and collected == before and len(rows) == 1
    return rows[0]


@pytest.mark.parametrize('slug,good,bad,field', DECLARATIONS, ids=[r[0] for r in DECLARATIONS])
@pytest.mark.parametrize('branch', ['good', 'bad', 'denied'])
def test_native_core_gke_deciding_fields(slug, good, bad, field, branch):
    row = capture(slug, bad if branch == 'bad' else good, field if branch == 'denied' else None)
    assert row['status'] == ('PASS' if branch == 'good' else 'FAIL' if branch == 'bad' else 'UNKNOWN'), row


@pytest.mark.parametrize('legacy', [False, True])
def test_opposite_endpoint_observations_never_pass(legacy):
    row = capture('private_endpoint', {'privateClusterConfig': {'enablePrivateEndpoint': legacy},
                  'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'enablePublicEndpoint': legacy}}})
    assert row['status'] == 'UNKNOWN'


@pytest.mark.parametrize('legacy', [False, True])
def test_opposite_node_defaults_never_pass(legacy):
    row = capture('private_nodes', {'privateClusterConfig': {'enablePrivateNodes': legacy},
                  'networkConfig': {'defaultEnablePrivateNodes': not legacy}})
    assert row['status'] == 'UNKNOWN'


@pytest.mark.parametrize('legacy', [False, True])
def test_opposite_authorized_network_flags_never_pass(legacy):
    row = capture('authorized_networks', {'masterAuthorizedNetworksConfig': {'enabled': legacy},
                  'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'authorizedNetworksConfig': {'enabled': not legacy}}}})
    assert row['status'] == 'UNKNOWN'


@pytest.mark.parametrize('field,fragment', [
    ('networkConfig.datapathProvider', {'networkConfig': {'datapathProvider': 'ADVANCED_DATAPATH'}}),
    ('autopilot.enabled', {'autopilot': {'enabled': True}}),
])
def test_unreadable_network_policy_shortcut_never_claims_enforcement(field, fragment):
    assert capture('network_policy', fragment, field)['status'] == 'UNKNOWN'


def test_unrecognized_datapath_provider_is_not_a_supported_engine():
    assert capture('network_policy', {'networkConfig': {'datapathProvider': 'FUTURE_MODE'},
                                     'networkPolicy': {'enabled': True}})['status'] == 'UNKNOWN'
