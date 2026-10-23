"""Bounded hosted uploads retain exact bytes, ownership and manifest dependencies."""
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from itertools import count
import threading

import pytest

from peaso.storage import artifacts as storage
from peaso.storage import reports


TENANT, JOB = 'owner', 'a' * 32


class MemoryS3:
    def __init__(self):
        self.objects, self.order = {}, []
        self.lock = threading.Lock()

    def put_object(self, **request):
        with self.lock:
            self.objects[request['Key']] = request
            self.order.append(request['Key'])

    def get_object(self, Bucket, Key):
        return {'Body': BytesIO(self.objects[Key]['Body'])}


def write_bundle(artifacts):
    detail = artifacts.put(TENANT, JOB, 'detail', {'evidence': 'exact native value · 数据 ' * 5000})
    findings = artifacts.put(TENANT, JOB, 'findings', {'items': [{'id': 'finding', '_detail_reference': detail}]})
    markdown = artifacts.put_text(TENANT, JOB, 'markdown', '# Report\n\nExact evidence · 数据\n' * 4000)
    graph = artifacts.put(TENANT, JOB, 'graph-iam', {'nodes': [{'id': 'principal'}], 'edges': []})
    return artifacts.put(TENANT, JOB, 'manifest', {
        'finding_chunks': [findings], 'report_markdown': markdown, 'graphs': {'iam': graph}})


def test_batch_retains_exact_artifacts_and_references(monkeypatch):
    def run(parallel):
        identifiers = count()

        def reference(tenant, job_id, kind):
            suffix = 'md' if kind == 'markdown' else 'json'
            return f'{storage.prefix(tenant)}/{job_id}/{kind}-{next(identifiers):032x}.{suffix}'

        monkeypatch.setattr(storage, 'reference_for', reference)
        client = MemoryS3()
        artifacts = storage.S3Artifacts('private', client=client, kms_key='workspace-key')
        if parallel:
            with artifacts.batch() as writer:
                manifest = write_bundle(writer)
        else:
            manifest = write_bundle(artifacts)
        return manifest, client.objects

    assert run(False) == run(True)


def test_uploads_overlap_but_manifest_waits_for_every_object():
    entered, release = threading.Barrier(5, timeout=5), threading.Event()

    class GatedS3(MemoryS3):
        def put_object(self, **request):
            if '/manifest-' not in request['Key']:
                entered.wait()
                assert release.wait(5)
            super().put_object(**request)

    client = GatedS3()
    artifacts = storage.S3Artifacts('private', client=client)

    def publish():
        with artifacts.batch(workers=4) as writer:
            refs = [writer.put(TENANT, JOB, 'findings', {'chunk': i}) for i in range(4)]
            return writer.put(TENANT, JOB, 'manifest', {'references': refs})

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(publish)
        try:
            entered.wait()  # All four uploads are running before any finishes.
            assert not future.done()
            assert not any('/manifest-' in key for key in client.objects)
        finally:
            release.set()
        manifest = future.result(timeout=5)
    assert client.order[-1] == 'artifacts/' + manifest
    assert all('artifacts/' + ref in client.objects for ref in artifacts.get(TENANT, manifest)['references'])
    assert not any(thread.name.startswith('peaso-artifact') for thread in threading.enumerate())


def test_queued_objects_capture_values_before_later_mutation():
    entered, release = threading.Event(), threading.Event()

    class GatedS3(MemoryS3):
        def put_object(self, **request):
            entered.set()
            assert release.wait(5)
            super().put_object(**request)

    client = GatedS3()
    artifacts = storage.S3Artifacts('private', client=client)
    with artifacts.batch(workers=1) as writer:
        value = {'items': [{'evidence': {'recorded': ['before']}}]}
        reference = writer.put(TENANT, JOB, 'findings', value)
        try:
            assert entered.wait(5)
            value['items'][0]['evidence']['recorded'].append('after')
        finally:
            release.set()
    assert artifacts.get(TENANT, reference)['items'][0]['evidence']['recorded'] == ['before']


def test_count_and_byte_backpressure_never_drop_large_evidence():
    client = MemoryS3()
    artifacts = storage.S3Artifacts('private', client=client)
    with artifacts.batch(workers=2, max_pending_bytes=1000) as writer:
        references = []
        for i in range(20):
            value = {'ordinal': i, 'evidence': 'large ' * (5000 if i == 7 else 20)}
            references.append((writer.put(TENANT, JOB, 'findings', value), value))
            assert len(writer.pending) <= 4
            assert writer.pending_bytes <= 1000 or len(writer.pending) == 1
    assert len(client.objects) == 20
    for reference, value in references:
        assert artifacts.get(TENANT, reference) == value


def test_failed_dependency_cannot_publish_manifest_even_if_flush_error_is_caught():
    class FailingS3(MemoryS3):
        def put_object(self, **request):
            if '/findings-' in request['Key']:
                raise OSError('synthetic upload failure')
            super().put_object(**request)

    client = FailingS3()
    artifacts = storage.S3Artifacts('private', client=client)
    with pytest.raises(OSError, match='synthetic upload failure'):
        with artifacts.batch() as writer:
            reference = writer.put(TENANT, JOB, 'findings', {'items': []})
            with pytest.raises(OSError):
                writer.flush()
            writer.put(TENANT, JOB, 'manifest', {'reference': reference})
    assert not any('/manifest-' in key for key in client.objects)
    assert not any(thread.name.startswith('peaso-artifact') for thread in threading.enumerate())


def test_context_exit_propagates_upload_failure_without_manifest():
    class FailingS3(MemoryS3):
        def put_object(self, **request):
            raise OSError('synthetic upload failure')

    artifacts = storage.S3Artifacts('private', client=FailingS3())
    with pytest.raises(OSError):
        with artifacts.batch() as writer:
            writer.put(TENANT, JOB, 'report', {'findings': []})
    with pytest.raises(RuntimeError, match='closed'):
        writer.put(TENANT, JOB, 'manifest', {})


def test_producer_error_closes_workers_and_preserves_original_exception():
    client = MemoryS3()
    artifacts = storage.S3Artifacts('private', client=client)
    with pytest.raises(ValueError, match='synthetic rendering failure'):
        with artifacts.batch() as writer:
            writer.put(TENANT, JOB, 'report', {'findings': []})
            raise ValueError('synthetic rendering failure')
    assert not any('/manifest-' in key for key in client.objects)
    assert not any(thread.name.startswith('peaso-artifact') for thread in threading.enumerate())


def test_parallel_references_preserve_tenant_and_scan_boundaries():
    client = MemoryS3()
    artifacts = storage.S3Artifacts('private', client=client)
    with artifacts.batch() as writer:
        reference = writer.put(TENANT, JOB, 'report', {'private': True})
        with pytest.raises(ValueError, match='reference'):
            writer.put('other', '../unsafe', 'report', {})
    with pytest.raises(ValueError, match='reference'):
        artifacts.get('other', reference)
    assert len(client.objects) == 1
    assert next(iter(client.objects)).startswith('artifacts/' + storage.job_prefix(TENANT, JOB))


@pytest.mark.parametrize('workers,capacity', [(0, 1024), (True, 1024), (17, 1024), (2, 0), (2, True)])
def test_invalid_batch_limits_are_rejected(workers, capacity):
    artifacts = storage.S3Artifacts('private', client=MemoryS3())
    with pytest.raises(ValueError):
        artifacts.batch(workers=workers, max_pending_bytes=capacity)


def test_report_publication_uses_batch_and_returns_a_completed_manifest(monkeypatch):
    monkeypatch.setattr(reports, '_publish_report', lambda store, *args: write_bundle(store))
    client = MemoryS3()
    artifacts = storage.S3Artifacts('private', client=client)
    manifest = reports.publish_report(artifacts, TENANT, JOB, {})
    assert client.order[-1] == 'artifacts/' + manifest
    assert len(client.objects) == 5
    assert artifacts.get(TENANT, manifest)['finding_chunks']


@pytest.mark.parametrize('failed_kind', ['findings', 'manifest'])
def test_report_publication_propagates_failed_upload_and_never_returns_a_manifest(monkeypatch, failed_kind):
    monkeypatch.setattr(reports, '_publish_report', lambda store, *args: write_bundle(store))

    class FailingS3(MemoryS3):
        def put_object(self, **request):
            if '/' + failed_kind + '-' in request['Key']:
                raise OSError('synthetic publication failure')
            super().put_object(**request)

    client = FailingS3()
    artifacts = storage.S3Artifacts('private', client=client)
    with pytest.raises(OSError, match='synthetic publication failure'):
        reports.publish_report(artifacts, TENANT, JOB, {})
    assert not any('/manifest-' in key for key in client.objects)
    assert not any(thread.name.startswith('peaso-artifact') for thread in threading.enumerate())


@pytest.mark.parametrize('batch_attribute', [None, False, 'legacy metadata'])
def test_custom_stores_without_batch_keep_synchronous_publication(monkeypatch, batch_attribute):
    received = []

    def publish(store, *args):
        received.append(store)
        return 'reference'

    monkeypatch.setattr(reports, '_publish_report', publish)
    store = type('CustomStore', (), {'batch': batch_attribute})()
    assert reports.publish_report(store, TENANT, JOB, {}) == 'reference'
    assert received == [store]


def test_oversized_upload_is_committed_before_producer_continues():
    client = MemoryS3()
    artifacts = storage.S3Artifacts('private', client=client)
    with artifacts.batch(workers=2, max_pending_bytes=1000) as writer:
        reference = writer.put(TENANT, JOB, 'findings', {'evidence': 'native ' * 10000})
        assert 'artifacts/' + reference in client.objects
        assert writer.pending_bytes == 0
        assert not writer.pending
    assert writer.closed and writer.pending_bytes == 0 and not writer.pending


def test_private_secret_reference_and_download_restriction_survive_reserved_uploads():
    client = MemoryS3()
    artifacts = storage.S3Artifacts('private', client=client, kms_key='private-key')
    value = {'ciphertext': 'synthetic-sealed-value'}
    reference = artifacts.put_secret_evidence(TENANT, JOB, value)
    assert artifacts.get(TENANT, reference) == value
    request = client.objects['artifacts/' + reference]
    assert request['ServerSideEncryption'] == 'aws:kms'
    assert request['SSEKMSKeyId'] == 'private-key'
    with pytest.raises(ValueError, match='Private secret evidence'):
        artifacts.presign(TENANT, reference)
    with pytest.raises(ValueError, match='Invalid artifact reference'):
        artifacts.get('another-tenant', reference)
