"""Leaks navigation selects detector positives, never secret-related posture checks."""
from copy import deepcopy
import pytest
from fastapi.testclient import TestClient
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts
from peaso.storage.reports import publish_report
from tests.test_peaso_api import TestIdentities


@pytest.mark.parametrize('chunked', [False, True])
def test_detector_only_selection_survives_indexing_grouping_and_pagination(tmp_path, chunked):
    store, artifacts = SQLiteStore(tmp_path / 'state'), FileArtifacts(tmp_path / 'artifacts')
    connector = store.add_connector('alice', {'provider': 'aws', 'name': 'fixture'}, 'encrypted')
    job = store.enqueue('alice', {'connector_id': connector['id']})
    base = dict(provider='aws', category='hardening', check_id='fixture.secret', finding_type='secrets',
                title='Credential configuration', service='lambda', severity='high', status='FAIL',
                scope='123456789012/us-east-1', resource_id='lambda', frameworks=[], evidence={})
    rows = [dict(base, id='configuration'), dict(base, id='empty-scanner', status='UNKNOWN')]
    for number in range(2):
        fp = str(number) * 64
        rows.append(dict(base, id='secret-' + fp, secret_fingerprint=fp, title='Exposed secret in scanned content'))
    report = dict(schema_version='1.0', snapshot_id='fixture', provider='aws', scopes=[base['scope']],
                  created_at='2026-10-22T00:00:00Z', findings=rows, coverage=[], resources=[], graphs={}, stats={})
    original = deepcopy(report)
    ref = publish_report(artifacts, 'alice', job['id'], report) if chunked else artifacts.put('alice', job['id'], 'report', report)
    with store.transaction() as db:
        db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?", (ref, job['id']))
    app = create_app(Settings(state_dir=tmp_path/'settings', identity_dir=tmp_path/'identity'), store=store,
                     artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url='http://127.0.0.1:8000', headers={'Authorization': 'Bearer alice'}) as client:
        path = f"/api/scans/{job['id']}/findings"
        for aggregation in ('none', 'check'):
            data = client.get(path, params={'finding_type': 'detected_leaks', 'aggregation': aggregation, 'limit': 1}).json()
            assert data['total'] == 2
            assert len(data['items']) == 1
            assert data['items'][0]['secret_fingerprint'] in ('0'*64, '1'*64)
        assert client.get(path).json()['total'] == 4
    assert report == original
