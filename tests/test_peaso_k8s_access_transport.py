"""Hosted preflight retains bounded read-only TLS without the generated SDK."""
import json
import sys

import pytest

from peaso.server.k8s_access_transport import AccessReadError, HostedAccessApi, MAX_RESPONSE
from peaso.server.access_check import check_access
from peaso.server.config import Settings


@pytest.fixture
def transport(monkeypatch):
    requests = []
    class Response:
        status = 200
        def __init__(self, data): self.raw = json.dumps(data).encode()
        def read(self, size): return self.raw[:size]
        def close(self): pass
        def release_conn(self): pass
    class Pool:
        def __init__(self, host, **kwargs):
            assert host == '203.0.113.5'
            assert kwargs['assert_hostname'] == kwargs['server_hostname'] == 'cluster.example.test'
            assert kwargs['ssl_context'].verify_mode != 0
        def request(self, method, url, **kwargs):
            requests.append((method, url, kwargs))
            assert kwargs['redirect'] is False and kwargs['retries'] is False
            assert kwargs['headers']['Authorization'] == 'Bearer synthetic-token'
            if method == 'POST':
                assert url.endswith('/apis/authorization.k8s.io/v1/selfsubjectaccessreviews')
                assert json.loads(kwargs['body'])['kind'] == 'SelfSubjectAccessReview'
                return Response({'status': {'allowed': True}})
            return Response({'metadata': {'name': 'test'}})
        def close(self): pass
    monkeypatch.setitem(sys.modules, 'kubernetes', None)
    monkeypatch.setattr('peaso.server.k8s_access_transport._public_server',
        lambda server: ('https://203.0.113.5', 'cluster.example.test'))
    monkeypatch.setattr('urllib3.HTTPSConnectionPool', Pool)
    return requests


def auth():
    return {'method': 'token', 'server': 'https://cluster.example.test', 'token': 'synthetic-token'}


def test_hosted_namespace_and_rbac_preflight_without_kubernetes_sdk(transport):
    result = check_access('k8s', auth(), ['first', 'second'], {}, Settings(auth_mode='cognito'))
    assert result['status'] == 'pass', result
    assert len(result['principals']) == 2
    assert len(transport) == 2 + 20 + 7
    assert all('synthetic-token' not in url for _, url, _ in transport)


@pytest.mark.parametrize('method,path,body', [
    ('DELETE', '/api/v1/namespaces/test', None),
    ('GET', '//other.example.test/api', None),
    ('GET', '/api/v1/namespaces/test/secrets/private', None),
    ('POST', '/api/v1/namespaces', {'kind': 'Namespace'}),
])
def test_preflight_does_not_allow_other_writes_or_secret_reads(transport, method, path, body):
    api = HostedAccessApi(auth())
    api.rest_client.pool_manager.allow_self_subject_access_review = True
    try:
        with pytest.raises(ValueError): api.call_api(path, method, body=body)
        assert not transport
    finally: api.close()


def test_access_response_is_bounded(transport, monkeypatch):
    api = HostedAccessApi(auth())
    response = api.call_api('/api/v1/namespaces/test', 'GET')
    response.response.raw = b'x' * (MAX_RESPONSE + 1)
    try:
        with pytest.raises(ValueError, match='exceeds'): _ = response.data
    finally:
        response.close(); response.release_conn(); api.close()


def test_access_http_denial_does_not_read_or_disclose_response(transport, monkeypatch):
    api = HostedAccessApi(auth())
    class Denied:
        status = 403
        def read(self, *args): pytest.fail('denied response body must not be consumed')
        def close(self): pass
        def release_conn(self): pass
    monkeypatch.setattr(api.pool, 'request', lambda *args, **kwargs: Denied())
    try:
        with pytest.raises(AccessReadError) as error:
            api.call_api('/api/v1/namespaces/test', 'GET')
        assert error.value.status == 403
        assert str(error.value) == 'Kubernetes access check failed'
    finally: api.close()
