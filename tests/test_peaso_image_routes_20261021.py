from copy import deepcopy
from types import SimpleNamespace
import importlib.abc
import json
import sys

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
import pytest
from peaso.storage.artifacts import job_prefix

from peaso.server.image_findings_routes import install_routes, SCHEMA, page_report, MAX_PAGE_BYTES
from peaso.image_findings import build_report
from tests.test_peaso_image_findings_20261021 import BASE

SCAN = 'a' * 32
REF = job_prefix('workspace-a', SCAN) + 'detail-' + 'b' * 32 + '.json'


def client(metadata='default', payload=None):
    calls = []
    app = FastAPI()
    def identity(authorization: str | None = Header(default=None)):
        if authorization is None:
            raise HTTPException(401, 'Sign in required')
        return SimpleNamespace(tenant_id=authorization)
    def owned_bundle(tenant, ident):
        calls.append(('job', tenant, ident))
        if tenant != 'workspace-a' or ident != SCAN:
            raise HTTPException(404, 'Scan not found')
        chosen = {'selected': True, 'artifact': REF} if metadata == 'default' else metadata
        return {}, {} if chosen is None else {'image_vulnerability_scan': chosen}
    class Artifacts:
        def get(self, tenant, reference):
            calls.append(('artifact', tenant, reference))
            assert tenant == 'workspace-a' and reference == REF
            return (payload if payload is not None else
                    {'schema': SCHEMA, 'scan_id': SCAN, 'observations': [BASE]})
    install_routes(app, identity=identity, owned_bundle=owned_bundle, artifacts=Artifacts())
    return TestClient(app), calls


def test_owned_scan_finding_and_assets():
    c, calls = client()
    result = c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'})
    assert result.status_code == 200
    body = result.json()
    assert body['coverage'] == 'COMPLETE' and body['total'] == 1
    assert body['rows'][0]['affected_asset_count'] == 1
    ident = body['rows'][0]['id']
    assets = c.get(f'/api/scans/{SCAN}/image-findings/{ident}/assets', headers={'Authorization': 'workspace-a'})
    assert assets.status_code == 200
    assert assets.json()['items'][0]['resource_id'] == BASE['asset_id']
    assert all(row[1] == 'workspace-a' for row in calls)


def test_no_auth_or_other_workspace_never_reads_image_artifact():
    c, calls = client()
    assert c.get(f'/api/scans/{SCAN}/image-findings').status_code == 401
    assert calls == []
    assert c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-b'}).status_code == 404
    assert not any(row[0] == 'artifact' for row in calls)


@pytest.mark.parametrize('reference', [
    job_prefix('workspace-b', SCAN) + 'detail-' + 'b' * 32 + '.json',
    job_prefix('workspace-a', 'c' * 32) + 'detail-' + 'b' * 32 + '.json',
    job_prefix('workspace-a', SCAN) + '../../private.json',
])
def test_wrong_tenant_scan_or_path_is_not_read(reference):
    c, calls = client({'selected': True, 'artifact': reference})
    assert c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'}).status_code == 409
    assert not any(row[0] == 'artifact' for row in calls)


@pytest.mark.parametrize('payload', [
    {'schema': SCHEMA, 'scan_id': 'c' * 32, 'observations': [BASE]},
    {'schema': 'other', 'scan_id': SCAN, 'observations': [BASE]},
])
def test_artifact_body_must_belong_to_this_scan(payload):
    c, _ = client(payload=payload)
    assert c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'}).status_code == 409


def test_legacy_scan_has_not_scanned_state():
    c, calls = client(None)
    body = c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'}).json()
    assert body['coverage'] == 'NOT_SCANNED' and not body['complete']
    assert not any(row[0] == 'artifact' for row in calls)


def test_selection_without_results_never_claims_clean():
    c, _ = client(payload={'schema': SCHEMA, 'scan_id': SCAN, 'observations': []})
    body = c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'}).json()
    assert body['coverage'] == 'UNKNOWN' and not body['complete']


def test_query_limits_enforced_before_loading():
    c, calls = client()
    for suffix in ('?offset=-1', '?limit=0', '?limit=101'):
        assert c.get(f'/api/scans/{SCAN}/image-findings{suffix}', headers={'Authorization': 'workspace-a'}).status_code == 422
    assert not calls


def test_unknown_finding_assets_are_not_disclosed():
    c, _ = client()
    assert c.get(f'/api/scans/{SCAN}/image-findings/foreign/assets', headers={'Authorization': 'workspace-a'}).status_code == 404


def test_finding_pagination_and_asset_preview_are_explicit():
    observations = []
    for i in range(12):
        o = deepcopy(BASE)
        o['asset_id'] += f'-{i}'
        observations.append(o)
    c, _ = client(payload={'schema': SCHEMA, 'scan_id': SCAN, 'observations': observations})
    page = c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'}).json()
    row = page['rows'][0]
    assert row['affected_asset_count'] == 12 and len(row['affected_assets']) == 10 and row['assets_truncated']
    assets = c.get(f'/api/scans/{SCAN}/image-findings/{row["id"]}/assets?limit=5', headers={'Authorization': 'workspace-a'}).json()
    assert assets['total'] == 12 and len(assets['items']) == 5 and assets['next_offset'] == 5


def test_page_response_bounded_without_silent_missing_rows():
    observations = []
    for i in range(150):
        o = deepcopy(BASE)
        o['scan']['findings'][0]['vulnerability_id'] = f'CVE-2026-{10000+i}'
        observations.append(o)
    report = build_report(observations, selected=True)
    first, second = page_report(report, 0, 100), page_report(report, 100, 100)
    assert first['next_offset'] == 100 and second['next_offset'] is None
    assert len(first['rows']) + len(second['rows']) == first['total'] == 150
    assert len(json.dumps(first).encode()) < MAX_PAGE_BYTES


def test_routes_need_no_native_registry_engine_or_analysis_imports():
    import os
    import subprocess
    code = """import importlib.abc, sys
from tests.test_peaso_image_routes_20261021 import client, SCAN
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ('peaso.checks', 'peaso.engine', 'peaso.analysis'):
            raise AssertionError('native boot forbidden')
assert not any(name in sys.modules for name in ('peaso.checks', 'peaso.engine', 'peaso.analysis'))
sys.meta_path.insert(0, Block())
c, _ = client()
r = c.get('/api/scans/' + SCAN + '/image-findings', headers={'Authorization':'workspace-a'})
assert r.status_code == 200, r.text
"""
    result = subprocess.run([sys.executable, '-c', code], cwd=str(__import__('pathlib').Path(__file__).parent),
        env={**os.environ, 'PYTHONPATH': os.pathsep.join(sys.path), 'PYTHONDONTWRITEBYTECODE':'1'},
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
