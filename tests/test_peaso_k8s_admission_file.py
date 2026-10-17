"""Native Pod/immutable ConfigMap joins, with no Secret or host access."""
from __future__ import annotations

import copy
import json

import pytest

from peaso.collectors.k8s import collect
from peaso.collectors.k8s_admission_file import _plugins

CLUSTER = 'admission-native-test'
PATH = '/etc/admission/admission.yaml'
CONFIG = '''apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  configuration:
    imagePolicy:
      kubeConfigFile: /etc/admission/webhook.kubeconfig
      unrelatedPassword: do-not-export-this
'''


def pod():
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'apiserver', 'namespace': 'control',
        'uid': 'pod-uid', 'resourceVersion': '12', 'creationTimestamp': '2026-10-14T10:00:00Z'},
        'spec': {'containers': [{'name': 'apiserver', 'command': ['kube-apiserver'],
            'args': ['--enable-admission-plugins=ImagePolicyWebhook', '--disable-admission-plugins=Foo',
                     '--admission-control-config-file=' + PATH],
            'volumeMounts': [{'name': 'config', 'mountPath': '/etc/admission', 'readOnly': True}]}],
            'volumes': [{'name': 'config', 'configMap': {'name': 'admission-config'}}]}}


def configmap():
    return {'apiVersion': 'v1', 'kind': 'ConfigMap', 'immutable': True,
        'metadata': {'name': 'admission-config', 'namespace': 'control', 'uid': 'config-uid',
            'resourceVersion': '11', 'creationTimestamp': '2026-10-14T09:00:00Z',
            'managedFields': [{'fieldsType': 'FieldsV1', 'time': '2026-10-14T09:00:00Z',
                'fieldsV1': {'f:immutable': {}, 'f:data': {'f:admission.yaml': {}, 'f:config': {}}}}]},
        'data': {'admission.yaml': CONFIG, 'unrelated': 'secret-value-must-never-leak'}}


class Api:
    def __init__(self):
        self.pod = pod()
        self.configmap = configmap()
        self.calls = []
        self.deny = False

    def get_json(self, path, params=None):
        self.calls.append(path)
        if path == '/api/v1/namespaces/control/pods':
            return {'items': [copy.deepcopy(self.pod)], 'metadata': {'resourceVersion': '12'}}
        if path == '/api/v1/namespaces/control/configmaps/admission-config':
            if self.deny:
                raise PermissionError('denied')
            return copy.deepcopy(self.configmap)
        raise AssertionError('Unexpected API call: ' + path)


def snapshot(api):
    return collect({'provider': 'k8s', 'scopes': ['control'], 'auth': {'cluster_id': CLUSTER},
                    'options': {'workers': 1}}, ['admission_configuration_file'], api=api)


def envelope(value):
    return next(row for row in value['collections'] if row['type'] == 'admission_configuration_file')


def test_native_immutable_configmap_is_selectively_projected():
    api = Api()
    result = snapshot(api)
    row = envelope(result)
    assert row['status'] == 'collected'
    item, = row['items']
    assert item['pod_uid'] == 'pod-uid'
    assert item['path'] == PATH
    assert item['plugins'] == [{'name': 'ImagePolicyWebhook', 'configuration': {
        'kubeConfigFile': '/etc/admission/webhook.kubeconfig'}}]
    assert item['provenance']['configmap_uid'] == 'config-uid'
    assert item['provenance']['runtime_verified'] is False
    serialized = json.dumps(result)
    for secret in ('do-not-export-this', 'unrelatedPassword', 'secret-value-must-never-leak'):
        assert secret not in serialized
    assert api.calls == ['/api/v1/namespaces/control/pods',
                         '/api/v1/namespaces/control/configmaps/admission-config']


@pytest.mark.parametrize('mutation', [
    lambda a: a.configmap.update(immutable=False),
    lambda a: a.configmap['metadata'].update(uid=''),
    lambda a: a.configmap['metadata'].update(namespace='foreign'),
    lambda a: a.configmap['metadata'].update(name='foreign'),
    lambda a: a.configmap['metadata'].update(resourceVersion=''),
    lambda a: a.configmap['metadata'].pop('managedFields'),
    lambda a: a.configmap['metadata']['managedFields'][0].update(time='2026-10-14T11:00:00Z'),
    lambda a: a.configmap['metadata']['managedFields'][0]['fieldsV1'].pop('f:immutable'),
    lambda a: a.configmap['metadata'].update(creationTimestamp='2026-10-14T11:00:00Z'),
    lambda a: a.pod['metadata'].pop('creationTimestamp'),
    lambda a: a.pod['spec']['containers'][0]['volumeMounts'][0].update(subPath='admission.yaml'),
    lambda a: a.pod['spec']['volumes'][0].update(secret={'secretName': 'forbidden'}),
    lambda a: a.pod['spec']['volumes'][0].update(configMap={'name': '../escape'}),
    lambda a: a.configmap.update(data={}),
    lambda a: a.pod['metadata'].update(annotations={'kubernetes.io/config.source': 'file'}),
    lambda a: setattr(a, 'deny', True),
])
def test_unverified_bindings_are_not_complete(mutation):
    api = Api()
    mutation(api)
    row = envelope(snapshot(api))
    assert row['status'] not in ('collected', 'empty')
    assert row['items'] == []
    assert not any('/secrets' in path or '/proxy' in path or '/exec' in path for path in api.calls)


def test_projected_key_path_and_shared_configmap_get():
    api = Api()
    api.pod['spec']['volumes'][0]['configMap']['items'] = [{'key': 'config', 'path': 'admission.yaml'}]
    api.configmap['data'] = {'config': CONFIG}
    assert envelope(snapshot(api))['status'] == 'collected'


@pytest.mark.parametrize('text', [
    'kind: AdmissionConfiguration\nkind: Other\n',
    'kind: AdmissionConfiguration\napiVersion: apiserver.config.k8s.io/v1\nplugins: &x [*x]',
    'kind: Wrong\nplugins: []',
    CONFIG.replace('imagePolicy:', 'wrong:'),
    CONFIG.replace('configuration:', 'path: /other/file\n  configuration:'),
    CONFIG + '\n---\nsecond: document',
    'x' * 262145,
])
def test_malformed_or_indirect_yaml_is_not_complete(text):
    api = Api()
    api.configmap['data']['admission.yaml'] = text
    assert envelope(snapshot(api))['status'] not in ('collected', 'empty')


def test_verified_empty_plugin_declaration_is_retained():
    assert _plugins('apiVersion: apiserver.config.k8s.io/v1\nkind: AdmissionConfiguration\nplugins: []') == []


def test_real_collector_to_published_check_pass_fail_unknown():
    from peaso.engine import evaluate_snapshot
    check_id = 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller'
    def status(api):
        report = evaluate_snapshot(snapshot(api), checks=[check_id])
        findings = [row for row in report['findings'] if row['check_id'] == check_id]
        assert len(findings) == 1
        return findings[0]['status']
    assert status(Api()) == 'PASS'
    absent = Api()
    absent.configmap['data']['admission.yaml'] = (
        'apiVersion: apiserver.config.k8s.io/v1\nkind: AdmissionConfiguration\nplugins: []')
    assert status(absent) == 'FAIL'
    unverified = Api()
    unverified.configmap['immutable'] = False
    assert status(unverified) == 'UNKNOWN'
