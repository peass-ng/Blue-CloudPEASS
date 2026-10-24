"""Selected image batches retain the serial source and part contracts."""
from contextlib import contextmanager
from copy import deepcopy
import gzip
import io
import json
import tarfile
import pytest

import test_k8s_registry_image as fixture
from peaso.collectors import k8s_selected_registry_image_20261021 as image
from peaso import secret_scanning_batch


def two_files():
    target, pod, blobs = fixture.fixture()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as tar:
        for number in range(2):
            payload = ('ordinary line %d\n' % number).encode()
            entry = tarfile.TarInfo('app/document-%d.txt' % number)
            entry.size = len(payload)
            tar.addfile(entry, io.BytesIO(payload))
    raw = output.getvalue()
    layer = gzip.compress(raw, mtime=0)
    old_manifest = blobs[('manifests', target['image'].rsplit('@', 1)[1])]
    manifest = json.loads(old_manifest)
    old_config = blobs[('blobs', manifest['config']['digest'])]
    config = json.loads(old_config)
    config['rootfs']['diff_ids'] = [fixture.digest(raw)]
    config_raw = json.dumps(config, separators=(',', ':')).encode()
    manifest['config'].update(digest=fixture.digest(config_raw), size=len(config_raw))
    manifest['layers'][0].update(digest=fixture.digest(layer), size=len(layer))
    manifest_raw = json.dumps(manifest, separators=(',', ':')).encode()
    target['image'] = 'ghcr.io/owned/demo@' + fixture.digest(manifest_raw)
    pod['spec']['containers'][0]['image'] = target['image']
    pod['status']['containerStatuses'][0]['image'] = target['image']
    pod['status']['containerStatuses'][0]['imageID'] = 'docker-pullable://' + target['image']
    blobs = {('manifests', fixture.digest(manifest_raw)): manifest_raw,
             ('blobs', fixture.digest(config_raw)): config_raw,
             ('blobs', fixture.digest(layer)): layer}
    return target, pod, blobs


def run(target, pod, blobs, *, scanner=image._scan):
    wire = fixture.FakeWire(blobs)
    marker = image.inspect(target, lambda _: deepcopy(pod), allowed_hosts=['ghcr.io'],
        registry_factory=lambda h, r, c, **kw: image.RegistryReader(h, r, c, open_https=wire, **kw),
        scanner=scanner)
    marker.pop('registry_receipts')
    return marker


def clean(raw, path, timeout, **kwargs):
    return {'complete': True, 'engines': [
        {'engine': 'kingfisher', 'version': '1.4.0', 'status': 'complete'},
        {'engine': 'trufflehog', 'version': '3.92.5', 'status': 'complete'}], 'leaks': []}


def test_batched_parts_equal_serial_including_exact_file_paths(monkeypatch):
    batches = []
    @contextmanager
    def batch(items, *, timeout):
        assert 0 < timeout <= 60
        batches.append(list(items))
        yield
    monkeypatch.setattr(image, 'scan_content', clean)
    monkeypatch.setattr(image, 'prepared_content_batch', batch)
    target, pod, blobs = two_files()
    serial = run(target, pod, blobs, scanner=lambda *a, **kw: image._scan(*a, **kw))
    queued = run(target, pod, blobs)
    assert queued == serial
    assert len(batches) == 1
    assert [path for _, path in batches[0]] == [p['part'] for p in queued['parts'][3:]]
    assert '.file-4.name' in queued['parts'][3]['part']
    assert '.file-6.name' in queued['parts'][5]['part']


def test_ordinary_archive_error_flushes_prior_positive(monkeypatch):
    original = image.archive.visit_files
    @contextmanager
    def batch(items, *, timeout):
        yield
    def fail_after(*args, **kwargs):
        original(*args, **kwargs)
        raise image.Incomplete('later_archive_failure')
    def positive(raw, path, timeout, **kwargs):
        result = clean(raw, path, timeout, **kwargs)
        if '.file-6.chunk-' in path:
            result['leaks'] = [{'fingerprint': 'a' * 64,
                'detectors': [{'engine': 'kingfisher', 'rule': 'synthetic'}],
                'locations': [{'path': path, 'line': 1}]}]
        return result
    monkeypatch.setattr(image, 'scan_content', positive)
    monkeypatch.setattr(image, 'prepared_content_batch', batch)
    monkeypatch.setattr(image.archive, 'visit_files', fail_after)
    result = run(*two_files())
    assert result['status'] == 'FAIL' and result['complete'] is False
    assert result['reason'] == 'later_archive_failure'
    assert '.file-6.chunk-' in result['leaks'][0]['locations'][0]['path']


def test_typed_cancellation_during_batch_propagates(monkeypatch):
    class Cancelled(Exception):
        code = 'collection_cancelled'
    @contextmanager
    def cancelled(items, *, timeout):
        raise Cancelled()
        yield
    monkeypatch.setattr(image, 'scan_content', clean)
    monkeypatch.setattr(image, 'prepared_content_batch', cancelled)
    target, pod, blobs = two_files()
    with pytest.raises(Cancelled):
        run(target, pod, blobs)


def test_failed_batch_preparation_reverts_to_serial(monkeypatch):
    attempts = []
    def unavailable(items, timeout):
        attempts.append(len(items))
        raise RuntimeError('synthetic batch preparation failure')
    monkeypatch.setattr(image, 'scan_content', clean)
    monkeypatch.setattr(secret_scanning_batch, '_prepare_trufflehog_batch', unavailable)
    target, pod, blobs = two_files()
    serial = run(target, pod, blobs, scanner=lambda *a, **kw: image._scan(*a, **kw))
    batched = run(target, pod, blobs)
    assert attempts == [4] and batched == serial
