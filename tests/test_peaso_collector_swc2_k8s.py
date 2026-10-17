"""Wave 2 Kubernetes collector contracts with provider-owned mocked API responses."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from peaso.collectors import k8s


class API:
    server = 'https://fixture.invalid'
    api_client = SimpleNamespace(configuration=SimpleNamespace(host=server))

    def __init__(self, *, items=None, paged=False, fail=None, partial=False):
        self.items = items if items is not None else [
            {'metadata': {'name': 'first', 'uid': 'p1'}, 'spec': {'validations': [{'expression': 'true'}]}},
            {'metadata': {'name': 'second', 'uid': 'p2'}, 'spec': {'validations': [{'expression': 'false'}]}},
        ]
        self.paged, self.fail, self.partial, self.calls = paged, fail, partial, []

    def get_json(self, path, params=None):
        self.calls.append((path, deepcopy(params or {})))
        if path == '/apis':
            return {'groups': [{'name': 'admissionregistration.k8s.io', 'versions': [{'version': 'v1'}]}]}
        if path == '/apis/admissionregistration.k8s.io/v1':
            return {'resources': [{'name': 'validatingadmissionpolicies'}]}
        if path == '/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies':
            offset = int((params or {}).get('continue', '0'))
            if self.fail == offset:
                raise k8s.K8sReadError('permission_denied', 403)
            if self.partial and offset == 1:
                raise ValueError('malformed second page')
            selected = self.items[offset:offset + 1] if self.paged else self.items
            more = self.paged and offset + 1 < len(self.items)
            return {'metadata': {'resourceVersion': '1', 'continue': str(offset + 1) if more else ''}, 'items': deepcopy(selected)}
        raise AssertionError(path)


def collect(api, scopes=None, options=None):
    return k8s.collect({'auth': {'cluster_id': 'fixture'}, 'scopes': scopes or ['one', 'two'],
                        'options': {'inventories': ['admission_policy'], 'retries': 0, **(options or {})}}, api=api)


def policies(snapshot):
    return [row for row in snapshot['collections'] if row['type'] == 'admission_policy']


def test_admission_pagination_shared_across_scopes():
    api = API(paged=True)
    rows = policies(collect(api))
    assert [(row['scope'], row['status'], len(row['items'])) for row in rows] == [
        ('one', 'collected', 2), ('two', 'collected', 2)]
    assert rows[0]['items'][0]['spec']['validations'][0]['expression'] == 'true'
    assert rows[1]['items'][0]['provenance']['cluster_id'] == 'fixture'
    calls = [params for path, params in api.calls if path.endswith('/validatingadmissionpolicies')]
    assert len(calls) == 2 and calls[1]['continue'] == '1'


@pytest.mark.parametrize('api,status', [
    (API(items=[]), 'empty'), (API(fail=0), 'denied'),
    (API(paged=True, partial=True), 'partial'),
])
def test_admission_incomplete_or_empty_copied_to_every_scope(api, status):
    rows = policies(collect(api))
    assert len(rows) == 2
    assert all(row['status'] == status for row in rows)
    assert len(rows[0]['items']) == len(rows[1]['items'])


def test_admission_resource_budget_marks_later_scope_partial():
    rows = policies(collect(API(), options={'max_resources': 3}))
    assert rows[0]['status'] == 'collected'
    assert rows[1]['status'] == 'partial'


def test_owner_policy_wave2_fields_and_invalid_rejection():
    raw = {'cluster_id': 'fixture', 'max_policy_items': 20,
           'approved_images': ['registry.example/app@sha256:' + 'a' * 64],
           'allowed_public_ports': [{'protocol': 'TCP', 'port': 443}],
           'allowed_ports': [{'protocol': 'TCP', 'port': 'http'}],
           'authorized_subjects': ['User:alice'],
           'authorized_utility_namespaces': ['ops'],
           'privileged_utility_pods': ['ops/tool'],
           'classification_label_key': 'data/classification', 'approved_values': ['public'],
           'approved_control_namespaces': ['ops'], 'approved_clock_skew': 30,
           'resolved_etcd_accounts': {'node-1': {'uid': 100, 'gid': 101}},
           'network_policy_intent': {'ops/deny': {'policyTypes': ['Ingress'], 'ingress': [], 'egress': []}},
           'environment_matrix': {'environment_key': 'environment', 'namespaces': {'ops': 'prod'},
                                  'subject_environments': {'User:alice': 'prod'}, 'allowed_cross_environment': []}}
    policy = collect(API(items=[]), options={'compliance_policy': raw})['metadata']['compliance_policy']
    assert policy['status'] == 'collected' and policy['approved_clock_skew'] == 30
    assert policy['network_policy_intent']['ops/deny']['ingress'] == []
    for key, value in [('approved_images', ['app:latest']), ('allowed_public_ports', [{'protocol': 'TCP', 'port': 0}]),
                       ('approved_clock_skew', True), ('authorized_subjects', ['User:alice', 'User:alice'])]:
        invalid = deepcopy(raw)
        invalid[key] = value
        result = collect(API(items=[]), options={'compliance_policy': invalid})['metadata']['compliance_policy']
        assert result['status'] == 'unknown' and key not in result


def test_component_flag_and_windows_configuration_projection():
    projected = k8s._component_config({'command': ['kube-apiserver'],
                                       'args': ['--admission-control-config-file=/etc/kubernetes/admission.yaml']})
    assert projected['flags']['admission-control-config-file'] == '/etc/kubernetes/admission.yaml'
    assert k8s._configuration_metadata({'IPAddressDeny': 'Any'}, 'kubelet') == {'IPAddressDeny': 'Any'}
    with pytest.raises(ValueError):
        k8s._configuration_metadata({'IPAddressDeny': 'Any'}, 'etcd')
