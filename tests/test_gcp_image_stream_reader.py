import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import threading

import pytest

from peaso.collectors import gcp_image_stream_reader_20261021 as module

URI = 'europe-west1-docker.pkg.dev/example-project/example-repo/example-image@sha256:' + 'a' * 64


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


class Response:
    def __init__(self, data, **changes):
        self.data, self.closed = data, False
        self.status_code, self.history = 200, []
        self.headers = {'Content-Length': str(len(data))}
        self.__dict__.update(changes)

    def iter_content(self, chunk_size):
        for start in range(0, len(self.data), chunk_size):
            yield self.data[start:start + chunk_size]

    def close(self):
        self.closed = True


def reader(response):
    class Session:
        def request(self, method, url, **kwargs):
            assert method == 'GET'
            assert kwargs['allow_redirects'] is False
            assert kwargs['stream'] is True
            response.url = getattr(response, 'url', url)
            return response
        def close(self):
            pass
    transport = SimpleNamespace(lock=threading.RLock(), calls=0, max_calls=64, timeout=10,
        credentials=SimpleNamespace(headers=lambda: {'Authorization': 'Bearer synthetic-offline-token'}),
        check_cancelled=lambda: None)
    return module.Reader(transport, session=Session())


def descriptor(data):
    return {'digest': digest(data), 'size': len(data),
            'mediaType': 'application/vnd.oci.image.layer.v1.tar'}


def test_layer_larger_than_old_eight_mib_limit_streams_to_private_file(tmp_path):
    data = b'x' * (9 * 1024 * 1024)
    response = Response(data)
    current = reader(response)
    path = tmp_path / 'layer'
    assert current.get_layer(URI, descriptor(data), path) == path
    assert path.stat().st_size == len(data)
    assert path.stat().st_mode & 0o777 == 0o600
    assert digest(path.read_bytes()) == digest(data)
    assert response.closed
    assert current.transport.evidence[0]['status'] == 'collected'
    assert 'synthetic-offline-token' not in repr(current.transport.evidence)


@pytest.mark.parametrize('change', [
    {'status_code': 403}, {'status_code': 302}, {'url': 'https://external.example.invalid/blob'},
    {'history': [object()]}, {'headers': {'Content-Encoding': 'gzip'}},
    {'headers': {'WWW-Authenticate': 'Bearer realm=external'}},
    {'headers': {'Docker-Content-Digest': 'sha256:' + 'b' * 64}},
    {'headers': {'Content-Length': '1'}},
])
def test_untrusted_response_never_creates_content(tmp_path, change):
    response = Response(b'layer bytes', **change)
    current = reader(response)
    path = tmp_path / 'layer'
    with pytest.raises(ValueError):
        current.get_layer(URI, descriptor(response.data), path)
    assert not path.exists()
    assert response.closed
    assert current.transport.evidence[0]['status'] in ('denied', 'unavailable')


def test_descriptor_hash_mismatch_removes_partial_owned_file(tmp_path):
    response = Response(b'other bytes')
    desc = descriptor(b'layer bytes')
    current = reader(response)
    path = tmp_path / 'layer'
    with pytest.raises(ValueError, match='descriptor'):
        current.get_layer(URI, desc, path)
    assert not path.exists()
    assert response.closed


def test_existing_destination_is_preserved(tmp_path):
    response = Response(b'layer')
    current = reader(response)
    path = tmp_path / 'layer'
    path.write_bytes(b'existing')
    with pytest.raises(FileExistsError):
        current.get_layer(URI, descriptor(response.data), path)
    assert path.read_bytes() == b'existing'
    assert response.closed


def test_low_disk_never_creates_file(tmp_path, monkeypatch):
    response = Response(b'layer')
    current = reader(response)
    monkeypatch.setattr(module.shutil, 'disk_usage', lambda _: SimpleNamespace(free=1))
    path = tmp_path / 'layer'
    with pytest.raises(ValueError, match='scratch disk'):
        current.get_layer(URI, descriptor(response.data), path)
    assert not path.exists()
    assert response.closed


def test_cancellation_removes_partial_file(tmp_path):
    data = b'x' * (module.CHUNK * 2)
    response = Response(data)
    current = reader(response)
    count = [0]
    def check():
        count[0] += 1
        if count[0] == 4:
            raise RuntimeError('cancelled')
    current.transport.check_cancelled = check
    path = tmp_path / 'layer'
    with pytest.raises(RuntimeError, match='cancelled'):
        current.get_layer(URI, descriptor(data), path)
    assert not path.exists()
    assert response.closed


def test_small_metadata_keeps_bytes_contract():
    data = b'{"schemaVersion":2}'
    response = Response(data)
    current = reader(response)
    assert current.get(URI, 'manifests', digest(data), 262144) == data
    assert response.closed


def test_metadata_cannot_allocate_layer_sized_buffer():
    current = reader(Response(b'layer'))
    with pytest.raises(ValueError, match='metadata'):
        current.get(URI, 'blobs', digest(b'layer'), module.MAX_LAYER)
    assert current.calls == 0


def test_transport_close_failure_removes_its_owned_completed_file(tmp_path):
    response = Response(b'layer')
    def fail():
        raise OSError('synthetic close failure')
    response.close = fail
    current = reader(response)
    path = tmp_path / 'layer'
    with pytest.raises(OSError, match='synthetic close failure'):
        current.get_layer(URI, descriptor(response.data), path)
    assert not path.exists()


def test_capacity_includes_every_advertised_layer_request():
    assert module.MAX_CALLS == module.native.MAX_IMAGES * (64 + 2)
    response = Response(b'{}')
    current = reader(response)
    current.calls = 65
    assert current.get(URI, 'manifests', digest(b'{}'), 262144) == b'{}'
    current.calls = module.MAX_CALLS
    with pytest.raises(ValueError, match='registry call bound'):
        current.get(URI, 'manifests', digest(b'{}'), 262144)
