"""Inert smart-HTTP fixtures, with no repository or credential side effects."""
import base64
import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest
from peaso.collectors import gcp_git_transport as git

COMMIT = 'a' * 40
REPO = 'projects/review/repos/example'
SCOPE = 'projects/review'
TOKEN = 'fake-csr-token-canary'


def advertisement(commit=COMMIT, caps=b'ofs-delta no-progress side-band-64k thin-pack'):
    return (git._encode(b'# service=git-upload-pack\n') + b'0000' +
            git._encode(commit.encode() + b' refs/heads/main\0' + caps + b'\n') + b'0000')


class Response:
    def __init__(self, payload, mime, status=200, extra=None):
        self.payload, self.position, self.status_code = payload, 0, status
        self.headers = {'Content-Type': mime, 'Content-Length': str(len(payload)), **(extra or {})}
        self.raw, self.closed = self, False
        self.url, self.history = None, []

    def read(self, size, *, decode_content):
        assert decode_content is False and 0 < size <= 16384
        chunk = self.payload[self.position:self.position + size]
        self.position += len(chunk)
        return chunk

    def close(self):
        self.closed = True


def fixture(monkeypatch, *, responses=None):
    monkeypatch.setattr(socket.socket, 'connect', lambda *a, **k: pytest.fail('unmocked network'))
    responses = responses if responses is not None else [
        Response(advertisement(), 'application/x-git-upload-pack-advertisement'),
        Response(git._encode(b'NAK\n') + b'PACK-inert-private-content', 'application/x-git-upload-pack-result')]
    transport = SimpleNamespace(lock=threading.Lock(), max_calls=None, calls=0, timeout=20,
        evidence=[], check_cancelled=lambda: None, credentials=SimpleNamespace(headers=lambda: {'Authorization': 'Bearer ' + TOKEN}))
    calls, closed = [], []
    def request(method, url, **kwargs):
        assert kwargs['allow_redirects'] is False and kwargs['stream'] is True
        assert kwargs['headers']['Accept-Encoding'] == 'identity'
        assert 0 < kwargs['timeout'] <= 20
        assert kwargs['headers']['Authorization'] == 'Basic ' + base64.b64encode(('git-service-account:' + TOKEN).encode()).decode()
        calls.append((method, url, kwargs))
        response = responses[len(calls) - 1]
        if response.url is None:
            response.url = url
        return response
    session = SimpleNamespace(request=request, cookies=SimpleNamespace(clear=lambda: None), close=lambda: closed.append(True))
    monkeypatch.setattr(git, '_session', lambda: session)
    return transport, calls, responses, closed


def test_exact_advertised_commit_and_read_only_routes(monkeypatch):
    transport, calls, responses, closed = fixture(monkeypatch)
    assert git.fetch_pack(transport, SCOPE, REPO, COMMIT, enabled=True) == b'PACK-inert-private-content'
    assert [(m, u) for m, u, _ in calls] == [
        ('GET', 'https://source.developers.google.com/p/review/r/example/info/refs?service=git-upload-pack'),
        ('POST', 'https://source.developers.google.com/p/review/r/example/git-upload-pack')]
    request = calls[1][2]['data']
    assert b'want ' + COMMIT.encode() + b' ofs-delta no-progress\n' in request
    assert b'side-band' not in request and b'thin-pack' not in request
    assert all(r.closed for r in responses) and closed == [True]
    persisted = json.dumps(transport.evidence)
    assert TOKEN not in persisted and 'refs/heads/main' not in persisted and 'private-content' not in persisted
    assert all(r['status'] == 'collected' for r in transport.evidence)


@pytest.mark.parametrize('repo,scope,commit,enabled', [
    (REPO,SCOPE,COMMIT,False),(REPO,SCOPE,COMMIT,'true'),
    (REPO,'projects/foreign',COMMIT,True),('https://example.invalid',SCOPE,COMMIT,True),
    (REPO + '/extra',SCOPE,COMMIT,True),(REPO + '?secret=x',SCOPE,COMMIT,True),
    ('projects/review/repos/..',SCOPE,COMMIT,True),(REPO,SCOPE,'main',True),
    (REPO,SCOPE,'0'*40,True),(REPO,SCOPE,'A'*40,True),
])
def test_invalid_or_disabled_before_credentials(monkeypatch, repo, scope, commit, enabled):
    monkeypatch.setattr(git, '_session', lambda: pytest.fail('session before validation'))
    with pytest.raises(git.Incomplete, match='^git_selection$'):
        git.fetch_pack(SimpleNamespace(), scope, repo, commit, enabled=enabled)


@pytest.mark.parametrize('payload', [b'',b'zzzz',b'0001',b'0004',b'0008NAK\n',advertisement('b'*40),
    advertisement()[:-4],advertisement()+b'0000',advertisement(caps=b'object-format=sha256'),
    advertisement().replace(b'refs/heads/main',b'refs/heads/m\x00n')])
def test_bad_advertisement_is_not_an_implicit_branch_tip(payload):
    with pytest.raises(git.Incomplete):
        git.fetch_request(payload,COMMIT)


@pytest.mark.parametrize('status,extra', [(403,{}),(302,{}),(206,{}),(200,{'Content-Encoding':'gzip'}),
    (200,{'Content-Range':'bytes 0-1/2'}),(200,{'Content-Length':'1'}),
    (200,{'Content-Length':'999999999999'}),(200,{'Content-Type':'text/html'})])
def test_denied_partial_or_encoded_read_is_unknown_and_closed(monkeypatch,status,extra):
    r=Response(advertisement(),'application/x-git-upload-pack-advertisement',status,extra)
    transport,calls,responses,closed=fixture(monkeypatch,responses=[r])
    with pytest.raises(git.Incomplete):
        git.fetch_pack(transport,SCOPE,REPO,COMMIT,enabled=True)
    assert len(calls)==1 and r.closed and closed == [True]
    assert TOKEN not in json.dumps(transport.evidence)


def test_fixed_byte_and_call_budgets(monkeypatch):
    transport,calls,_,_=fixture(monkeypatch)
    transport.max_calls=0
    with pytest.raises(git.Incomplete,match='git_call_limit'):
        git.fetch_pack(transport,SCOPE,REPO,COMMIT,enabled=True)
    assert calls==[]
    transport,calls,_,_=fixture(monkeypatch)
    monkeypatch.setattr(git,'MAX_ADVERTISEMENT',8)
    with pytest.raises(git.Incomplete):
        git.fetch_pack(transport,SCOPE,REPO,COMMIT,enabled=True)
    assert len(calls)==1


def test_protocol_v1_and_sha1_capability():
    prefix=git._encode(b'# service=git-upload-pack\n')+b'0000'
    original=advertisement(caps=b'object-format=sha1 ofs-delta')
    assert b'ofs-delta' in git.fetch_request(prefix+git._encode(b'version 1\n')+original[len(prefix):],COMMIT)


def test_session_has_no_ambient_auth_proxy_or_cookie_state():
    session=git._session()
    try:
        assert session.trust_env is False and callable(session.auth) and not session.cookies
    finally:
        session.close()


def test_deadline_and_pack_framing_are_strict():
    with pytest.raises(git.Incomplete,match='git_deadline'):
        git._check(SimpleNamespace(check_cancelled=lambda:None),time.monotonic()-1)
    for data in (b'',git._encode(b'ACK '+COMMIT.encode()+b'\n')+b'PACK',git._encode(b'NAK\n')+b'0004',b'PACK'):
        with pytest.raises(git.Incomplete):
            git.pack_response(data)


@pytest.mark.parametrize('deadline', [True, 'future', float('nan'), float('inf'), 0])
def test_invalid_or_expired_shared_deadline_precedes_session(monkeypatch, deadline):
    monkeypatch.setattr(git, '_session', lambda: pytest.fail('session before deadline validation'))
    with pytest.raises(git.Incomplete, match='git_deadline'):
        git.fetch_pack(SimpleNamespace(), SCOPE, REPO, COMMIT, enabled=True, deadline=deadline)


def test_credential_refresh_cannot_send_content_after_shared_deadline(monkeypatch):
    transport, calls, _, closed = fixture(monkeypatch)
    clock = [100.0]
    monkeypatch.setattr(git.time, 'monotonic', lambda: clock[0])
    def refreshed():
        clock[0] = 102.0
        return {'Authorization': 'Bearer ' + TOKEN}
    transport.credentials.headers = refreshed
    with pytest.raises(git.Incomplete, match='git_deadline'):
        git.fetch_pack(transport, SCOPE, REPO, COMMIT, enabled=True, deadline=101.0)
    assert calls == [] and closed == [True]


@pytest.mark.parametrize('route,history', [('https://example.invalid/unrelated', []), ('https://source.developers.google.com/p/review/r/foreign/info/refs?service=git-upload-pack', []), (None, [object()])])
def test_changed_final_route_or_redirect_history_is_rejected_before_content(monkeypatch, route, history):
    response = Response(advertisement(), 'application/x-git-upload-pack-advertisement')
    response.url, response.history = route, history
    transport, calls, _, closed = fixture(monkeypatch, responses=[response])
    with pytest.raises(git.Incomplete, match='git_final_route_mismatch'):
        git.fetch_pack(transport, SCOPE, REPO, COMMIT, enabled=True)
    assert response.position == 0 and response.closed and closed == [True]
    assert len(calls) == 1 and transport.evidence[-1]['final_route_verified'] is False



def test_slow_final_eof_does_not_return_pack_after_shared_deadline(monkeypatch):
    transport, calls, responses, closed = fixture(monkeypatch)
    clock = [100.0]
    monkeypatch.setattr(git.time, 'monotonic', lambda: clock[0])
    read = responses[1].read
    def delayed_eof(size, *, decode_content):
        chunk = read(size, decode_content=decode_content)
        if not chunk:
            clock[0] = 102.0
        return chunk
    responses[1].read = delayed_eof
    with pytest.raises(git.Incomplete, match='git_deadline'):
        git.fetch_pack(transport, SCOPE, REPO, COMMIT, enabled=True, deadline=101.0)
    assert len(calls) == 2 and responses[1].closed and closed == [True]
    assert transport.evidence[-1]['status'] == 'unavailable'
