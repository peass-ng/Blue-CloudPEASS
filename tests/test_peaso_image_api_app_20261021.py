from copy import deepcopy
import importlib.abc
import sys
from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts
from peaso.image_findings_storage import attach_to_manifest
from tests.test_peaso_image_findings_20261021 import BASE


class Auth:
    def authenticate(self, authorization):
        if authorization not in ('Bearer alice', 'Bearer bob'):
            raise HTTPException(401, 'Sign in required')
        return Identity(authorization.removeprefix('Bearer '))


def _proof(tmp_path):
    class Block(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname in ('peaso.checks', 'peaso.engine', 'peaso.analysis'):
                raise AssertionError('native cold import forbidden')
    assert not any(name in sys.modules for name in ('peaso.checks', 'peaso.engine', 'peaso.analysis'))
    block = Block()
    sys.meta_path.insert(0, block)
    try:
        settings = Settings(state_dir=tmp_path / 'state', identity_dir=tmp_path / 'identity',
                            local_token='synthetic-local-test-token-0123456789')
        store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(tmp_path / 'artifacts')
        connector = store.add_connector('alice', {'provider': 'gcp'}, 'encrypted')
        job = store.enqueue('alice', {'connector_id': connector['id']})
        collector = store.claim('collector')
        store.finish(job['id'], collector['owner'], 'collected', artifacts.put('alice', job['id'], 'snapshot', {}))
        analyzer = store.claim('analyzer')
        manifest = attach_to_manifest({'bundle_version': 1}, artifacts, 'alice', job['id'],
                                      {'selected': True, 'observations': [deepcopy(BASE)]})
        reference = artifacts.put('alice', job['id'], 'manifest', manifest)
        store.finish(job['id'], analyzer['owner'], 'completed', reference)
        app = create_app(settings, store=store, artifacts=artifacts, authenticator=Auth())
        with TestClient(app, base_url='http://127.0.0.1') as client:
            url = f'/api/scans/{job["id"]}/image-findings'
            own = client.get(url, headers={'Authorization': 'Bearer alice'})
            assert own.status_code == 200, own.text
            assert own.json()['rows'][0]['package'] == 'busybox'
            denied = client.get(url, headers={'Authorization': 'Bearer bob'})
            assert denied.status_code == 404
            assert client.get(url).status_code == 401
        assert not any(name in sys.modules for name in ('peaso.checks', 'peaso.engine', 'peaso.analysis'))
    finally:
        sys.meta_path.remove(block)


def test_real_app_sqlite_artifact_and_workspace_boundary_without_native_boot(tmp_path):
    import os
    import subprocess
    from pathlib import Path
    result = subprocess.run([sys.executable, '-c',
        'from pathlib import Path; from tests.test_peaso_image_api_app_20261021 import _proof; import sys; _proof(Path(sys.argv[1]))', str(tmp_path)],
        cwd=str(Path(__file__).parent), env={**os.environ, 'PYTHONPATH':os.pathsep.join(sys.path), 'PYTHONDONTWRITEBYTECODE':'1'},
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
