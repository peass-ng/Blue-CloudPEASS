"""Untrusted uploads must be bounded before parsing or expanding references."""
import asyncio
import json
import socket

import pytest
from fastapi.testclient import TestClient

from peaso.auth.documents import credential_document
from peaso.auth.secrets import credential_values, redact
from peaso.collectors.k8s import validate_inline_kubeconfig
from peaso.server import create_app
from peaso.server.body_limit import RequestBodyLimit
from peaso.server.config import Settings


def kubeconfig_yaml(padding=''):
    return padding + '''
apiVersion: v1
kind: Config
current-context: scan
clusters: [{name: target, cluster: {server: "https://cluster.example"}}]
users: [{name: reader, user: {token: inert-token}}]
contexts: [{name: scan, context: {cluster: target, user: reader}}]
'''


def alias_bomb():
    rows = ['padding:', '  a0: &a0 {value: inert}']
    for level in range(1, 32):
        rows.append(f'  a{level}: &a{level} [*a{level-1}, *a{level-1}]')
    return kubeconfig_yaml('\n'.join(rows) + '\n')


@pytest.mark.parametrize('padding', [alias_bomb(), kubeconfig_yaml('padding: &cycle [*cycle]\n')])
def test_kubeconfig_alias_graphs_are_rejected_before_expansion(padding):
    with pytest.raises(ValueError, match='aliases'):
        validate_inline_kubeconfig(padding)


def test_hosted_kubeconfig_bomb_cannot_reach_storage_or_dns(tmp_path, monkeypatch):
    def no_dns(*args, **kwargs):
        pytest.fail('unsafe credential document reached DNS')
    monkeypatch.setattr(socket, 'getaddrinfo', no_dns)
    settings = Settings(auth_mode='cognito', state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    from peaso.auth import Identity
    class Auth:
        def authenticate(self, authorization): return Identity('owner')
    app = create_app(settings, authenticator=Auth())
    with TestClient(app, base_url='https://cspm.hacktricks.wiki') as client:
        result = client.post('/api/connectors', headers={'Authorization': 'Bearer inert'}, json={
            'name': 'Bomb', 'provider': 'k8s', 'auth': {'method': 'inline', 'kubeconfig_data': alias_bomb()}})
    assert result.status_code == 422
    assert app.state.store.connectors('owner') == []


def test_bounded_credential_yaml_preserves_safe_multicontext_input():
    selected = validate_inline_kubeconfig(kubeconfig_yaml())
    assert selected['token'] == 'inert-token'
    assert selected['server'] == 'https://cluster.example'
    assert 'inert-token' in set(credential_values({'kubeconfig_data': kubeconfig_yaml()}))


@pytest.mark.parametrize('value', ['[' * 100 + '0' + ']' * 100,
                                  '[' + ','.join('0' for _ in range(20_001)) + ']'])
def test_credential_parser_enforces_depth_and_node_limits(value):
    with pytest.raises(ValueError, match='structure'):
        credential_document(value)


def test_credential_extraction_terminates_on_shared_and_cyclic_values():
    shared = {'token': 'private-marker'}
    data = [shared] * 1000
    data.append(data)
    assert list(credential_values(data)) == ['private-marker']
    secrets = tuple(credential_values({'credentials': ['list-secret-marker']}))
    assert 'list-secret-marker' not in json.dumps(redact({'note': 'list-secret-marker'}, secrets))


async def exchange(app, chunks, headers=(), *, path='/', fail_after=None):
    sent, count = [], 0
    items = iter(chunks)
    async def receive():
        nonlocal count
        count += 1
        if fail_after is not None and count > fail_after:
            pytest.fail('continued reading oversized upload')
        try:
            return {'type': 'http.request', 'body': next(items), 'more_body': True}
        except StopIteration:
            return {'type': 'http.request', 'body': b'', 'more_body': False}
    async def send(message): sent.append(message)
    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1',
             'method': 'POST', 'scheme': 'http', 'path': path, 'raw_path': path.encode(),
             'query_string': b'', 'headers': [(b'host', b'localhost'), *headers],
             'server': ('localhost', 8000), 'client': ('127.0.0.1', 1234)}
    await app(scope, receive, send)
    return next(message['status'] for message in sent if message['type'] == 'http.response.start')


@pytest.mark.parametrize('headers', [[], [(b'transfer-encoding', b'chunked')], [(b'content-length', b'1')]])
def test_actual_body_limit_stops_before_router_and_before_rest_of_upload(headers):
    async def forbidden(*args): pytest.fail('oversized request reached router')
    app = RequestBodyLimit(forbidden, max_bytes=8)
    assert asyncio.run(exchange(app, [b'1234', b'5678', b'9'], headers, fail_after=3)) == 413


@pytest.mark.parametrize('length,status', [(b'-1', 400), (b'nan', 400), (b'9'*5000, 413), (b'2', 400)])
def test_invalid_body_length_never_reaches_router(length, status):
    async def forbidden(*args): pytest.fail('malformed request reached router')
    assert asyncio.run(exchange(RequestBodyLimit(forbidden, max_bytes=8), [b'1'],
                                [(b'content-length', length)])) == status


def test_duplicate_lengths_are_rejected():
    async def forbidden(*args): pytest.fail('ambiguous length reached router')
    assert asyncio.run(exchange(RequestBodyLimit(forbidden), [],
                                [(b'content-length', b'0'), (b'content-length', b'1')])) == 400


def test_conflicting_transfer_and_content_length_are_rejected():
    async def forbidden(*args): pytest.fail('ambiguous framing reached router')
    assert asyncio.run(exchange(RequestBodyLimit(forbidden), [],
                                [(b'content-length', b'0'), (b'transfer-encoding', b'chunked')])) == 400


def test_valid_stream_is_replayed_exactly_once():
    observed = []
    async def router(scope, receive, send):
        message = await receive()
        observed.append(message)
        await send({'type': 'http.response.start', 'status': 204, 'headers': []})
        await send({'type': 'http.response.body', 'body': b''})
    assert asyncio.run(exchange(RequestBodyLimit(router, max_bytes=8), [b'123', b'45678'])) == 204
    assert observed == [{'type': 'http.request', 'body': b'12345678', 'more_body': False}]


def test_unauthenticated_chunked_api_upload_is_bounded_before_json_parser(tmp_path):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity',
                        local_token='local-resource-bound-test-token')
    app = create_app(settings)
    assert asyncio.run(exchange(app, [b' ' * 1024 * 1024] * 17,
                                [(b'transfer-encoding', b'chunked')], path='/api/connectors', fail_after=17)) == 413
