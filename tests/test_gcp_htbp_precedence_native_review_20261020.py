"""Native GKE pool identity and Artifact Registry priority counterexamples."""
from copy import deepcopy

import pytest

from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot
from tests.test_gcp_firewall_port_native_matrix_review_20261020 import forbid_provider_network

KUBELET = 'gcp.htbp.gke.kubelet_readonly_port_disabled'
REGISTRY = 'gcp.htbp.artifactregistry.virtual_repo_private_precedence'
PREFIX = 'projects/p-one/locations/us-central1/repositories/'


def cluster_status(fragment):
    cluster = {'name': 'review', 'location': 'us-central1-a', **deepcopy(fragment)}
    def resolve(request):
        assert request['method'] == 'GET'
        assert request['url'] == 'https://container.googleapis.com/v1/projects/p-one/locations/-/clusters'
        return {'clusters': [cluster]}
    collected, _ = snapshot(['gke_cluster'], resolve)
    return evaluate_snapshot(collected, checks=[KUBELET])['findings'][0]['status']


def pool(name, flag):
    return {'name': name, 'config': {'kubeletConfig': {'insecureKubeletReadonlyPortEnabled': flag}}}


@pytest.mark.parametrize('flags,expected', [([False], 'PASS'), ([True], 'FAIL'),
    ([False, True], 'FAIL'), ([True, False], 'FAIL')])
def test_every_distinct_native_pool_is_checked(flags, expected):
    assert cluster_status({'nodePools': [pool('pool-' + str(i), flag) for i, flag in enumerate(flags)]}) == expected


@pytest.mark.parametrize('flags', [[True, False], [False, True]])
def test_duplicate_pool_names_never_hide_an_enabled_readonly_port(flags):
    assert cluster_status({'nodePools': [pool('duplicate', flag) for flag in flags]}) == 'UNKNOWN'


def test_unreadable_nested_kubelet_flag_never_passes():
    row = pool('one', False)
    # An explicit unavailable fact models a post-collection read failure.
    def resolve(request): return {'clusters': [{'name': 'review', 'location': 'us-central1-a', 'nodePools': [row]}]}
    collected, _ = snapshot(['gke_cluster'], resolve)
    item = collected['collections'][0]['items'][0]['nodePools'][0]['config']['kubeletConfig']
    item['_coverage'] = {'insecureKubeletReadonlyPortEnabled': {'status': 'denied'}}
    collected.pop('snapshot_id', None)
    assert evaluate_snapshot(collected, checks=[KUBELET])['findings'][0]['status'] == 'UNKNOWN'


def test_automatic_pool_defaults_are_checked_alongside_standard_defaults():
    assert cluster_status({'nodePoolDefaults': {'nodeConfigDefaults': {'nodeKubeletConfig': {'insecureKubeletReadonlyPortEnabled': False}}},
                          'nodePoolAutoConfig': {'nodeKubeletConfig': {'insecureKubeletReadonlyPortEnabled': True}},
                          'nodePools': [{'name': 'one', 'config': {}}]}) == 'FAIL'


@pytest.mark.parametrize('private,remote,expected', [([100], [10], 'PASS'), ([100], [100], 'FAIL'),
    ([100, 5], [10], 'FAIL'), ([100, 50], [10, 20], 'PASS'), ([10], [20], 'FAIL')])
def test_every_private_upstream_precedes_every_public_upstream(private, remote, expected):
    rows = registry_rows(private, remote)
    assert sorted(row['status'] for row in rows) == sorted([expected] + ['NOT_APPLICABLE'] * (len(private) + len(remote)))


def registry_rows(private, remote, override_mode=None):
    repos = []
    policies = []
    for mode, priorities in [('STANDARD_REPOSITORY', private), ('REMOTE_REPOSITORY', remote)]:
        for i, priority in enumerate(priorities):
            name = PREFIX + ('private' if mode == 'STANDARD_REPOSITORY' else 'remote') + str(i)
            repos.append({'name': name, 'mode': override_mode if mode == 'REMOTE_REPOSITORY' and override_mode else mode})
            policies.append({'id': str(len(policies)), 'repository': name, 'priority': priority})
    repos.append({'name': PREFIX + 'virtual', 'mode': 'VIRTUAL_REPOSITORY',
                  'virtualRepositoryConfig': {'upstreamPolicies': policies}})
    def resolve(request):
        assert request['method'] == 'GET'
        if request['url'].endswith(':getIamPolicy'):
            assert any(request['url'] == 'https://artifactregistry.googleapis.com/v1/' + repo['name'] + ':getIamPolicy' for repo in repos)
            return {'version': 3, 'bindings': []}
        assert request['url'] == 'https://artifactregistry.googleapis.com/v1/projects/p-one/locations/us-central1/repositories'
        return {'repositories': repos}
    collected, _ = snapshot(['artifact_repository'], resolve, artifactregistry_locations=['us-central1'])
    rows = evaluate_snapshot(collected, checks=[REGISTRY])['findings']
    return rows


@pytest.mark.parametrize('automatic,expected', [(False, 'MANUAL'), (True, 'PASS')])
def test_automatic_defaults_never_certify_manual_pools(automatic, expected):
    assert cluster_status({'nodePoolAutoConfig': {'nodeKubeletConfig': {'insecureKubeletReadonlyPortEnabled': False}},
                          'nodePools': [{'name': 'one', 'config': {}, 'autoscaling': {'autoprovisioned': automatic}}]}) == expected


@pytest.mark.parametrize('mode', ['VIRTUAL_REPOSITORY', 'FUTURE_MODE'])
def test_nested_or_unknown_upstream_does_not_prove_private_precedence(mode):
    rows = registry_rows([100], [10], override_mode=mode)
    virtual = next(row for row in rows if row['native_resource_id'].endswith('/repositories/virtual'))
    assert virtual['status'] == 'UNKNOWN'
