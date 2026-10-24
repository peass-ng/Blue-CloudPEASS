"""Public streaming Reader methods against a synthetic Artifact Registry 302."""
import hashlib
from pathlib import Path
from threading import RLock
from types import SimpleNamespace

import pytest
from peaso.collectors import gcp_image_stream_reader_20261021 as module

DATA = b'bounded synthetic layer bytes'
DIGEST = 'sha256:' + hashlib.sha256(DATA).hexdigest()
URI = 'us-central1-docker.pkg.dev/test-project/images/app@' + DIGEST
ORIGIN = 'https://us-central1-docker.pkg.dev'
FIRST = ORIGIN + '/v2/test-project/images/app/blobs/' + DIGEST
HOP = '/artifacts-downloads/namespaces/test-project/repositories/images/downloads/opaque-id'

class Response:
    def __init__(self, status, url, data=b'', headers=None):
        self.status_code, self.url, self.data = status, url, data
        self.headers = headers if headers is not None else {'Content-Length': str(len(data))}
        self.history, self.closed = [], False
    def iter_content(self, chunk_size):
        for i in range(0, len(self.data), chunk_size):
            yield self.data[i:i + chunk_size]
    def close(self): self.closed = True

class Session:
    def __init__(self, first, second=None):
        self.responses, self.calls = [first] + ([second] if second is not None else []), []
        self.cookies = SimpleNamespace(clear=lambda: None)
    def request(self, method, url, **kwargs):
        assert method == 'GET' and kwargs['allow_redirects'] is False and kwargs['stream'] is True
        assert url.startswith(ORIGIN + '/')
        assert kwargs['headers']['Authorization'].startswith('Basic ')
        self.calls.append(url)
        return self.responses[len(self.calls) - 1]
    def close(self): pass

def make(location=HOP, payload=DATA, status=200, *, max_calls=4, cancel=None):
    first = Response(302, FIRST, headers={'Location': location, 'Content-Length': '141'})
    second = Response(status, ORIGIN + location, payload) if location.startswith('/') else None
    session = Session(first, second)
    transport = SimpleNamespace(lock=RLock(), calls=0, max_calls=max_calls, timeout=10,
        credentials=SimpleNamespace(headers=lambda: {'Authorization': 'Bearer synthetic-offline-token'}),
        check_cancelled=cancel or (lambda: None))
    return module.Reader(transport, session=session), session, first, second

def layer(reader, path):
    return reader.get_layer(URI, {'digest': DIGEST, 'size': len(DATA),
        'mediaType': 'application/vnd.oci.image.layer.v1.tar'}, path)

def test_live_shape_metadata_and_layer_public_methods(tmp_path):
    reader, session, first, second = make()
    assert reader.get(URI, 'blobs', DIGEST, 1024, len(DATA)) == DATA
    assert session.calls == [FIRST, ORIGIN + HOP]
    assert first.closed and second.closed
    assert reader.transport.calls == reader.calls == 2
    assert reader.transport.evidence[0]['http_attempts'] == 2
    assert reader.transport.evidence[0]['same_origin_blob_redirect'] is True
    assert 'synthetic-offline-token' not in repr(reader.transport.evidence)
    reader, session, first, second = make()
    path = tmp_path / 'layer'
    assert layer(reader, path) == path and path.read_bytes() == DATA
    assert path.stat().st_mode & 0o777 == 0o600
    assert session.calls == [FIRST, ORIGIN + HOP]
    assert first.closed and second.closed

@pytest.mark.parametrize('location', [
    'https://evil.invalid/file', 'http://us-central1-docker.pkg.dev/file',
    '//evil.invalid/file', 'https://user@us-central1-docker.pkg.dev/file',
    '/artifacts-downloads/namespaces/other-project/repositories/images/downloads/x',
    '/artifacts-downloads/namespaces/test-project/repositories/other/downloads/x',
    '/artifacts-downloads/namespaces/test-project/repositories/images/downloads/../x',
    '/artifacts-downloads/namespaces/test-project/repositories/images/downloads/%2e%2e',
    '/artifacts-downloads/namespaces/test-project/repositories/images/downloads/%2F',
    '/artifacts-downloads/namespaces/test-project/repositories/images/downloads/%252F',
    '/artifacts-downloads/namespaces/test-project/repositories/images/downloads//x',
    HOP + '#fragment', HOP + '?token=value', HOP + '\\escape', HOP + '\r\nX:bad',
    '/v2/test-project/images/app/blobs/' + DIGEST, HOP * 100,
])
def test_untrusted_location_rejected_before_followup(location, tmp_path):
    reader, session, first, _ = make(location)
    with pytest.raises(ValueError): layer(reader, tmp_path / 'layer')
    assert session.calls == [FIRST] and first.closed
    assert reader.transport.calls == 1
    assert not (tmp_path / 'layer').exists()

def test_manifest_redirect_rejected():
    reader, session, first, _ = make()
    with pytest.raises(ValueError): reader.get(URI, 'manifests', DIGEST, 1024, len(DATA))
    assert len(session.calls) == 1 and first.closed

@pytest.mark.parametrize('status', [302, 307, 401, 403, 500])
def test_second_response_never_redirects_again(status, tmp_path):
    reader, session, first, second = make(status=status)
    with pytest.raises(ValueError): layer(reader, tmp_path / 'layer')
    assert len(session.calls) == 2 and first.closed and second.closed
    assert not (tmp_path / 'layer').exists()

@pytest.mark.parametrize('payload', [b'wrong-size', b'bounded synthetic layer byteX'])
def test_size_or_digest_failure_removes_owned_scratch(payload, tmp_path):
    reader, session, first, second = make(payload=payload)
    with pytest.raises(ValueError): layer(reader, tmp_path / 'layer')
    assert not (tmp_path / 'layer').exists() and first.closed and second.closed

def test_existing_destination_preserved(tmp_path):
    reader, _, _, _ = make()
    path = tmp_path / 'layer'
    path.write_bytes(b'existing')
    with pytest.raises(FileExistsError): layer(reader, path)
    assert path.read_bytes() == b'existing'

def test_second_call_budget_and_cancellation(tmp_path):
    reader, session, first, _ = make(max_calls=1)
    with pytest.raises(ValueError, match='budget'): layer(reader, tmp_path / 'layer')
    assert len(session.calls) == 1 and first.closed
    count = [0]
    def cancel():
        count[0] += 1
        if count[0] == 3: raise RuntimeError('synthetic cancellation')
    reader, session, first, _ = make(cancel=cancel)
    with pytest.raises(RuntimeError, match='cancellation'): layer(reader, tmp_path / 'layer')
    assert len(session.calls) == 1 and first.closed
    assert not (tmp_path / 'layer').exists()

def test_oversize_stream_removes_partial_scratch(tmp_path):
    reader, session, first, second = make(payload=DATA + b'extra')
    second.headers.pop('Content-Length')
    with pytest.raises(ValueError, match='bound'): layer(reader, tmp_path / 'layer')
    assert not (tmp_path / 'layer').exists() and first.closed and second.closed

@pytest.mark.parametrize('mutation', ['source_url', 'source_history', 'source_challenge',
    'source_encoding', 'final_url', 'final_history', 'final_challenge', 'final_encoding'])
def test_source_and_final_response_identity_checks(mutation, tmp_path):
    reader, session, first, second = make()
    target = first if mutation.startswith('source_') else second
    if mutation.endswith('url'): target.url = ORIGIN + '/unrelated'
    elif mutation.endswith('history'): target.history = [object()]
    elif mutation.endswith('challenge'): target.headers['WWW-Authenticate'] = 'Basic realm=unexpected'
    else: target.headers['Content-Encoding'] = 'gzip'
    with pytest.raises(ValueError): layer(reader, tmp_path / 'layer')
    assert len(session.calls) == (1 if mutation.startswith('source_') else 2)
    assert first.closed and (mutation.startswith('source_') or second.closed)
    assert not (tmp_path / 'layer').exists()

def test_reader_call_cap_blocks_second_request(tmp_path):
    reader, session, first, _ = make()
    reader.calls = module.MAX_CALLS - 1
    with pytest.raises(ValueError, match='registry call bound'): layer(reader, tmp_path / 'layer')
    assert len(session.calls) == 1 and first.closed
