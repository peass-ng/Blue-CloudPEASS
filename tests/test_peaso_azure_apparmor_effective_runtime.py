"""AppArmor declared policy versus independently measured applied profiles."""
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = '/subscriptions/sub'
CLUSTER = SCOPE + '/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks'
NOW = '2026-10-12T12:00:00+00:00'
CHECK = 'azure.gap.kubernetes_cluster_container_use_allowed_apparmor_profile'


def signed_snapshot():
    names = [('containers', 'main'), ('initContainers', 'init'), ('ephemeralContainers', 'debug')]
    pod = {'metadata': {'uid': 'pod-uid', 'name': 'pod', 'namespace': 'ns'},
           '_provenance': {'cluster_id': CLUSTER, 'source_operation': 'list_pods', 'representation': 'full'},
           'spec': {kind: [{'name': name, 'securityContext': {'appArmorProfile': {'type': 'RuntimeDefault'}}}]
                    for kind, name in names}}
    scope = {'id': 'scope', 'clusters': [{'id': CLUSTER, 'kind': 'AKS', 'namespaces': ['ns'],
             '_coverage': {'namespaces': {'status': 'collected'}, 'pods': {'status': 'collected'}}}]}
    runtime = {'id': 'runtime', 'clusterId': CLUSTER, 'podUid': 'pod-uid', 'nodeOs': 'linux',
               'kubernetesVersion': 'v1.31.0', 'appArmorEnabled': True, 'runtimeDefaultSupported': True}
    collections = [{'type': kind, 'scope': SCOPE, 'status': 'collected', 'items': items}
                   for kind, items in [('kubernetes_scope', [scope]), ('pod', [pod]), ('pod_runtime', [runtime])]]
    metadata = {'sw25_policy': {CHECK: {'scope': SCOPE, 'allowedProfiles': [{'type': 'RuntimeDefault'}],
                 'nonLinuxApplies': False, 'containerKinds': [kind for kind, _ in names]}},
                'tenant_verified': True, 'tenant_id': 'tenant', 'credential_context_id': 'capture',
                'customer_context_id': 'customer', 'subscription_tenants': {SCOPE: 'tenant'}}
    return make_snapshot('azure', [SCOPE], collections, metadata=metadata, created_at=NOW)


def finding(snapshot):
    return next(f for f in evaluate_snapshot(snapshot, checks=[CHECK])['findings']
                if f['check_id'] == CHECK)


def test_capability_and_declaration_alone_cannot_pass():
    result = finding(signed_snapshot())
    assert result['status'] == 'UNKNOWN', result


def measured_snapshot():
    from copy import deepcopy
    original = signed_snapshot()
    collections = deepcopy(original['collections'])
    pod = next(c for c in collections if c['type'] == 'pod')['items'][0]
    runtime = next(c for c in collections if c['type'] == 'pod_runtime')['items'][0]
    pod['spec']['nodeName'] = 'node-a'
    names = [('containers', 'containerStatuses', 'main'),
             ('initContainers', 'initContainerStatuses', 'init'),
             ('ephemeralContainers', 'ephemeralContainerStatuses', 'debug')]
    pod['status'] = {status: [{'name': name, 'containerID': 'containerd://' + name}]
                     for _, status, name in names}
    common = {'clusterId': CLUSTER, 'podUid': 'pod-uid', 'nodeName': 'node-a',
              'nodeUid': 'node-uid', 'observer': 'independent-host-observer',
              'sourceDocumentId': 'external-measurement-1', 'readOnly': True,
              'observedAt': '2026-10-12T11:59:00Z',
              'credential_context_id': 'capture', 'customer_context_id': 'customer'}
    runtime['appArmorNodeEvidence'] = {**common, 'sourceOperation': 'external_node_runtime_read',
        'nodeOs': 'linux', 'appArmorEnabled': True, 'kubernetesVersion': 'v1.31.0',
        'runtimeDefaultSupported': True, 'runtimeDefaultProfileName': 'measured-runtime-default'}
    runtime['appArmorProfiles'] = [{**common,
        'sourceOperation': 'external_container_kernel_profile_read',
        'containerKind': kind, 'containerName': name, 'containerId': 'containerd://' + name,
        'profileType': 'RuntimeDefault', 'appliedProfileName': 'measured-runtime-default',
        'enforcementMode': 'enforce'} for kind, _, name in names]
    return collections, original['metadata'], original['created_at']


def sealed(collections, metadata, created_at):
    return make_snapshot('azure', [SCOPE], collections, metadata=metadata, created_at=created_at)


def test_exact_external_measured_profiles_pass():
    assert finding(sealed(*measured_snapshot()))['status'] == 'PASS'


import pytest


@pytest.mark.parametrize('mutation,expected', [
    ('unconfined', 'FAIL'), ('complain', 'FAIL'), ('other_localhost', 'FAIL'),
    ('missing_container', 'UNKNOWN'), ('foreign_pod_uid', 'UNKNOWN'),
    ('foreign_node_uid', 'UNKNOWN'), ('wrong_container_id', 'UNKNOWN'),
    ('stale_measurement', 'UNKNOWN'), ('foreign_customer', 'UNKNOWN'),
    ('measured_windows_excluded', 'NOT_APPLICABLE'),
])
def test_applied_profile_binding_and_mode(mutation, expected):
    collections, metadata, created_at = measured_snapshot()
    pod = next(c for c in collections if c['type'] == 'pod')['items'][0]
    runtime = next(c for c in collections if c['type'] == 'pod_runtime')['items'][0]
    proof = runtime['appArmorProfiles'][0]
    if mutation == 'unconfined':
        proof.update(profileType='Unconfined', appliedProfileName='unconfined', enforcementMode='unconfined')
    elif mutation == 'complain':
        proof['enforcementMode'] = 'complain'
    elif mutation == 'other_localhost':
        proof.update(profileType='Localhost', appliedProfileName='other-kernel-profile',
                     resolvedLocalhostProfile='other-localhost')
    elif mutation == 'missing_container':
        runtime['appArmorProfiles'].pop()
    elif mutation == 'foreign_pod_uid':
        proof['podUid'] = 'prior-pod'
    elif mutation == 'foreign_node_uid':
        proof['nodeUid'] = 'prior-node'
    elif mutation == 'wrong_container_id':
        proof['containerId'] = 'containerd://prior-container'
    elif mutation == 'stale_measurement':
        proof['observedAt'] = '2026-10-12T11:00:00Z'
    elif mutation == 'foreign_customer':
        proof['customer_context_id'] = 'other-customer'
    elif mutation == 'measured_windows_excluded':
        runtime['appArmorNodeEvidence']['nodeOs'] = 'windows'
    actual = finding(sealed(collections, metadata, created_at))
    assert actual['status'] == expected, actual
