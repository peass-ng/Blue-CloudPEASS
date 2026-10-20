"""Admission YAML stored in ConfigMaps uses the existing optional content reader."""
import json

import pytest

from tests import test_k8s_literal_secret_review_20261020 as native

offline = native.offline


@pytest.mark.parametrize('positive', [False, True])
def test_real_native_configmap_admission_yaml_is_scanned_without_exec(monkeypatch, positive):
    selected = native.target('ConfigMap', 'admission-config')
    document = native.native(selected)
    value = native.TOKEN if positive else 'disabled'
    document['data'] = {'admission.yaml':
        'apiVersion: apiserver.config.k8s.io/v1\nkind: AdmissionConfiguration\n'
        'plugins:\n- name: ExampleWebhook\n  configuration:\n    token: ' + value + '\n'}
    snapshot, trace = native.capture(monkeypatch, targets=[selected],
        documents={native.route(selected): document}, real=True)
    findings = native.findings(snapshot)
    assert {f['status'] for f in findings} == ({'FAIL'} if positive else {'PASS'})
    assert len(trace.calls) == 2
    assert all(method == 'GET' and '/configmaps/' in path for method, _, path in trace.calls)
    assert all(response.closed and response.released for response in trace.responses)
    status, evidence = native.checks.evaluate(*native.item_index(snapshot))
    assert status == findings[0]['status'] and evidence['complete'] is True
    assert {(e['engine'], e['status']) for e in evidence['parts'][0]['engines']} == {
        ('kingfisher', 'complete'), ('trufflehog', 'complete')}
    retained = json.dumps([snapshot, findings])
    assert native.TOKEN not in retained and 'ExampleWebhook' not in retained
    if positive:
        assert len(findings) == 1 and len(findings[0]['evidence']['secret_leaks']) == 1
    # This proves only API-visible ConfigMap text, never mounted node/runtime bytes.
    assert evidence['coverage'] == 'selected_observed_literals_only'
