"""Scheduling must not turn a one-off bearer session into recurring failures."""
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from peaso.server import create_app
from peaso.server.config import Settings
from peaso.server.schedule_credentials import scheduling_eligibility
from peaso.worker import Worker
from test_peaso_api import TestIdentities
from test_peaso_calendar_schedules import store


@pytest.mark.parametrize('provider,auth,allowed', [
    ('aws', {'method': 'access_keys', 'aws_access_key_id': 'ASIAexample', 'aws_secret_access_key': 'test', 'aws_session_token': 'test'}, False),
    ('aws', {'method': 'assume_role', 'role_arn': 'role', 'aws_access_key_id': 'ASIAexample', 'aws_secret_access_key': 'test'}, False),
    ('aws', {'method': 'access_keys', 'aws_access_key_id': 'AKIAexample', 'aws_secret_access_key': 'test'}, True),
    ('aws', {'method': 'assume_role', 'role_arn': 'role'}, False),
    ('aws', {'method': 'sso'}, False),
    ('gcp', {'method': 'token', 'token': 'opaque-with-no-exp'}, False),
    ('gcp', {'method': 'external-account', 'subject_token': 'test'}, False),
    ('gcp', {'method': 'platform-service-account'}, True),
    ('gcp', {'sa_json': json.dumps({'type': 'service_account', 'private_key': 'test', 'client_email': 'test@example.invalid'})}, True),
    ('gcp', {'sa_json': {'type': 'authorized_user', 'refresh_token': 'test'}}, False),
    ('azure', {'method': 'token', 'arm_token': 'test'}, False),
    ('azure', {'method': 'workload-identity', 'federated_token': 'test'}, False),
    ('azure', {'method': 'client-secret', 'tenant_id': 'test', 'client_id': 'test', 'client_secret': 'test'}, True),
    ('azure', {'method': 'client-secret', 'tenant_id': 'test', 'client_id': 'test', 'client_secret': 'test', 'graph_token': 'test'}, False),
    ('azure', {'method': 'managed-identity'}, True),
    ('k8s', {'method': 'token', 'token': 'opaque-with-no-exp'}, False),
    ('k8s', {'method': 'client-cert', 'client_cert_data': 'test', 'client_key_data': 'test'}, True),
    ('k8s', {'method': 'in-cluster'}, True),
    ('other', {}, False),
])
def test_classification(provider, auth, allowed):
    result = scheduling_eligibility(provider, auth)
    assert result['allowed'] is allowed
    assert 'opaque-with-no-exp' not in str(result)


def test_inline_kubeconfig_uses_selected_context():
    config = {'current-context': 'selected', 'contexts': [{'name': 'selected', 'context': {'user': 'selected', 'cluster': 'cluster'}}],
        'clusters': [{'name': 'cluster', 'cluster': {'server': 'https://example.invalid'}}],
        'users': [{'name': 'selected', 'user': {'token': 'test'}}]}
    assert not scheduling_eligibility('k8s', {'method': 'inline', 'kubeconfig_data': config})['allowed']
    config['users'][0]['user'] = {'client-certificate-data': 'test', 'client-key-data': 'test'}
    assert scheduling_eligibility('k8s', {'method': 'inline', 'kubeconfig_data': config})['allowed']


def test_api_rejects_new_and_reactivated_schedules_but_allows_disabling_and_manual_scan(tmp_path):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity', local_token='test-local-token-12345678')
    app = create_app(settings, authenticator=TestIdentities())
    store, cipher = app.state.store, app.state.cipher
    private = {'auth': {'method': 'token', 'token': 'synthetic-private-token'}, 'options': {}}
    connector = store.add_connector('alice', {'provider': 'gcp', 'name': 'Temporary', 'scopes': ['project'], 'input_mode': 'live'}, cipher.encrypt(private))
    selectors = {'connector_id': connector['id'], 'ai_enabled': False, 'interval_hours': 24}
    with TestClient(app, base_url='http://127.0.0.1') as client:
        client.headers['Authorization'] = 'Bearer alice'
        public = client.get('/api/connectors').json()['items'][0]
        assert public['scheduling']['allowed'] is False
        assert client.get('/api/connectors/'+connector['id']).json()['scheduling'] == public['scheduling']
        assert 'synthetic-private-token' not in json.dumps(public)
        response = client.post('/api/schedules', json=selectors)
        assert response.status_code == 422, response.text
        assert not store.schedules('alice')
        saved = store.add_schedule('alice', selectors, 1, True)
        assert client.patch('/api/schedules/'+saved['id'], json={'enabled': True}).status_code == 422
        assert client.patch('/api/schedules/'+saved['id'], json={'enabled': False}).status_code == 200
        durable = store.add_connector('alice', {'provider': 'azure', 'name': 'Durable'}, cipher.encrypt({
            'auth': {'method': 'client-secret', 'tenant_id': 'test', 'client_id': 'test', 'client_secret': 'test'}, 'options': {}}))
        assert client.patch('/api/schedules/'+saved['id'], json={'connector_id': durable['id'], 'enabled': True}).status_code == 200
        assert client.patch('/api/schedules/'+saved['id'], json={'connector_id': connector['id']}).status_code == 422
        assert client.patch('/api/schedules/'+saved['id'], json={'connector_id': 'not-owned'}).status_code == 404
        response = client.post('/api/scans', json={'connector_id': connector['id'], 'ai_enabled': False})
        assert response.status_code == 201, response.text


def test_scheduler_pauses_legacy_temporary_schedule_before_quota_or_dispatch(tmp_path, store):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    worker = Worker('collector', settings, store=store, authenticator=SimpleNamespace(is_paid=lambda tenant: pytest.fail('must not charge quota')))
    connector = worker.store.add_connector('alice', {'provider': 'aws', 'name': 'Temporary'}, worker.cipher.encrypt({
        'auth': {'aws_access_key_id': 'ASIAexample', 'aws_secret_access_key': 'test', 'aws_session_token': 'test'}, 'options': {}}))
    worker.store.add_schedule('alice', {'connector_id': connector['id'], 'ai_enabled': False, 'interval_hours': 24}, 1)
    assert worker.schedule_tick(now=2) == []
    saved = worker.store.schedules('alice')[0]
    assert saved['enabled'] is False
    assert 'temporary or unverified credentials' in saved['last_error']
    assert not worker.store.jobs('alice')


@pytest.mark.parametrize('variant,allowed', [('valid', True), ('expired', False), ('bound', False), ('forged', False), ('unavailable', False), ('duplicate-key', False)])
def test_nonexpiring_k8s_requires_cluster_signature_not_unsigned_claims(monkeypatch, variant, allowed):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from peaso.server.schedule_credentials import verify_nonexpiring_token
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public['kid'] = 'cluster-key'
    claims = {'iss': 'kubernetes/serviceaccount', 'sub': 'system:serviceaccount:default:scanner',
        'kubernetes.io/serviceaccount/namespace': 'default',
        'kubernetes.io/serviceaccount/service-account.name': 'scanner',
        'kubernetes.io/serviceaccount/service-account.uid': 'uid',
        'kubernetes.io/serviceaccount/secret.name': 'scanner-token'}
    if variant == 'expired':
        claims['exp'] = 1
    if variant == 'bound':
        claims['aud'] = ['cluster']
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if variant == 'forged' else key
    token = jwt.encode(claims, signing_key, algorithm='RS256', headers={'kid': 'cluster-key'})
    auth = {'method': 'token', 'server': 'https://example.invalid', 'token': token}
    calls = []
    def cluster_jwks(auth, *, hosted):
        calls.append(('/openid/v1/jwks', 'GET'))
        if variant == 'unavailable':
            raise PermissionError('denied')
        return {'keys': [public, public] if variant == 'duplicate-key' else [public]}
    monkeypatch.setattr('peaso.server.schedule_credentials._cluster_jwks', cluster_jwks)
    proof = verify_nonexpiring_token('k8s', auth)
    assert bool(proof) is allowed
    assert scheduling_eligibility('k8s', auth, proof=proof)['allowed'] is allowed
    assert not scheduling_eligibility('k8s', dict(auth, token=token+'changed'), proof=proof)['allowed']
    assert all(call == ('/openid/v1/jwks', 'GET') for call in calls)
    assert token not in json.dumps(proof)


def test_hosted_assume_role_renews_but_explicit_temporary_source_never_does():
    auth = {'method': 'assume_role', 'role_arn': 'role'}
    assert scheduling_eligibility('aws', auth, hosted=True)['allowed']
    assert not scheduling_eligibility('aws', dict(auth, aws_session_token='test'), hosted=True)['allowed']
    assert not scheduling_eligibility('aws', dict(auth, profile='unverified'), hosted=True)['allowed']


def test_cluster_key_read_is_tls_pinned_bounded_and_never_follows_redirects(monkeypatch):
    from peaso.server.schedule_credentials import _cluster_jwks
    calls = []
    monkeypatch.setattr('peaso.collectors.k8s._public_server', lambda server: ('https://203.0.113.5:6443', 'example.invalid'))
    class Response:
        status = 200
        def read(self, size):
            assert size == 1_048_577
            return b'{"keys": []}'
        def close(self): pass
        def release_conn(self): pass
    class Pool:
        def __init__(self, host, **kwargs):
            assert host == '203.0.113.5'
            assert kwargs['assert_hostname'] == kwargs['server_hostname'] == 'example.invalid'
            assert kwargs['ssl_context'].verify_mode != 0
        def urlopen(self, method, path, **kwargs):
            calls.append((method, path))
            assert kwargs['redirect'] is False and kwargs['retries'] is False
            assert kwargs['headers'] == {'Authorization': 'Bearer test', 'Host': 'example.invalid:6443'}
            return Response()
        def close(self): pass
    monkeypatch.setattr('urllib3.HTTPSConnectionPool', Pool)
    assert _cluster_jwks({'method': 'token', 'server': 'https://example.invalid:6443', 'token': 'test'}, hosted=True) == {'keys': []}
    assert calls == [('GET', '/openid/v1/jwks')]
