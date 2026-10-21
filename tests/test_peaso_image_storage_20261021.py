from copy import deepcopy
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
from types import SimpleNamespace

from peaso.storage.artifacts import FileArtifacts
from peaso.image_findings_storage import attach_to_manifest
from peaso.server.image_findings_routes import install_routes
from peaso.image_findings import build_report
from tests.test_peaso_image_findings_20261021 import BASE

SCAN = 'a' * 32


def test_native_observation_persist_to_authenticated_api(tmp_path):
    store = FileArtifacts(tmp_path)
    observation = deepcopy(BASE)
    observation['scan']['stderr'] = observation['credentials'] = 'synthetic-sensitive-canary'
    original = {'bundle_version': 1, 'summary': {}}
    manifest = attach_to_manifest(original, store, 'workspace-a', SCAN,
                                  {'selected': True, 'observations': [observation]})
    assert original == {'bundle_version': 1, 'summary': {}}
    payload = store.get('workspace-a', manifest['image_vulnerability_scan']['artifact'])
    assert 'synthetic-sensitive-canary' not in json.dumps(payload)
    app = FastAPI()
    install_routes(app, identity=lambda: SimpleNamespace(tenant_id='workspace-a'),
                   owned_bundle=lambda tenant, ident: ({}, manifest), artifacts=store)
    response = TestClient(app).get(f'/api/scans/{SCAN}/image-findings')
    assert response.status_code == 200
    assert response.json()['rows'][0]['vulnerability_id'] == 'CVE-2026-12345'
    assert response.json()['complete']


def test_unselected_never_writes():
    class NoWrites:
        def put(*args): raise AssertionError('unexpected write')
    result = attach_to_manifest({}, NoWrites(), 'workspace-a', SCAN, {'selected': False})
    assert 'image_vulnerability_scan' not in result


def test_malformed_values_not_persisted_or_reported_clean(tmp_path):
    observation = deepcopy(BASE)
    observation['scan']['findings'][0]['vulnerability_id'] = 'synthetic-sensitive-canary'
    store = FileArtifacts(tmp_path)
    manifest = attach_to_manifest({}, store, 'workspace-a', SCAN,
                                  {'selected': True, 'observations': [observation]})
    payload = store.get('workspace-a', manifest['image_vulnerability_scan']['artifact'])
    assert 'synthetic-sensitive-canary' not in json.dumps(payload)
    projected = build_report(payload['observations'], selected=True)
    assert not projected['complete'] and projected['coverage'] == 'UNKNOWN'
    assert projected['rows'] == []
