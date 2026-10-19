"""The shared GCP collector identity never enters a shell-enabled AI task."""
import json
import multiprocessing

import pytest

from tests.test_peaso_ai_review import environment


@pytest.mark.parametrize('method,allowed', [('platform-service-account', False), ('service-account', True)])
def test_collector_withholds_shared_identity_and_derived_tokens(method, allowed, environment, monkeypatch):
    from peaso.ai import access
    from peaso.ai.crypto import AICipher
    from peaso.snapshot import make_snapshot
    from peaso.worker import _process
    settings, _, artifacts = environment

    def collect(_):
        assert access.enabled() is allowed
        access.bearer('gcp', 'https://www.googleapis.com', 'synthetic-cloud-session')
        access.remember('k8s', 'derived-cluster', {'format': 'kubeconfig', 'token': 'synthetic-derived-session'})
        return make_snapshot('gcp', ['fixture'], [{'type': 'project', 'scope': 'fixture',
            'status': 'collected', 'items': [{'projectId': 'fixture'}]}])

    monkeypatch.setattr('peaso.engine.collect_snapshot', collect)
    monkeypatch.setattr('peaso.gcp_platform.load_service_account', lambda _: {})
    context = multiprocessing.get_context('fork')
    parent, child = context.Pipe(duplex=False)
    request = {'artifact_config': {'mode': 'file', 'root': str(artifacts.root)}, 'tenant_id': 'alice',
        'scan_id': 'c' * 32, 'connector': {'provider': 'gcp', 'auth': {'method': method}, 'options': {}},
        'ai_context': {'identity_dir': str(settings.identity_dir)}}
    process = context.Process(target=_process, args=('collector', request, child))
    try:
        process.start()
        child.close()
        assert parent.poll(15)
        success, reference, *rest = parent.recv()
        assert success, rest
        snapshot = artifacts.get('alice', reference)
        assert 'synthetic-cloud-session' not in json.dumps(snapshot)
        assert 'synthetic-derived-session' not in json.dumps(snapshot)
        if allowed:
            sealed = artifacts.get('alice', snapshot['metadata']['ai_access_reference'])['sealed']
            entries = AICipher(settings.identity_dir).decrypt(sealed)['entries']
            assert {entry['provider'] for entry in entries} == {'gcp', 'k8s'}
        else:
            assert 'ai_access_reference' not in snapshot['metadata']
    finally:
        process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join()
        parent.close()
