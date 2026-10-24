"""Scan-local reuse must compose with durable, bounded report publication."""
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import json
import threading

import pytest

from peaso.storage.artifacts import FileArtifacts, S3Artifacts
from peaso.storage.report_reuse import ReusableReportArtifacts

TENANT, JOB = 'owner', 'a' * 32


class Objects:
    def __init__(self):
        self.requests = []
        self.fail_kind = None

    def put_object(self, **request):
        if self.fail_kind and '/' + self.fail_kind + '-' in request['Key']:
            raise OSError('synthetic failed upload')
        self.requests.append(request)

    def get_object(self, Bucket, Key):
        return {'Body': BytesIO(next(r['Body'] for r in self.requests if r['Key'] == Key))}


def store(client=None, **options):
    client = client or Objects()
    return ReusableReportArtifacts(S3Artifacts('private', client, kms_key='workspace-key'),
                                   TENANT, JOB, **options), client


def test_exact_bytes_reused_across_pending_batch_completed_batch_and_direct_writes():
    cached, client = store()
    value = {'items': ['café 数据']}
    body = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
    with cached.batch() as writer:
        first = writer._put_json_bytes(TENANT, JOB, 'resources', body)
        assert writer.put(TENANT, JOB, 'resources', value) == first
        text = writer.put_text(TENANT, JOB, 'markdown', '# Exact café\n')
        assert writer.put_text(TENANT, JOB, 'markdown', '# Exact café\n') == text
        assert not cached.entries  # No pending reference is globally reusable.
    with cached.batch() as writer:
        assert writer._put_json_bytes(TENANT, JOB, 'resources', body) == first
        assert writer.put_text(TENANT, JOB, 'markdown', '# Exact café\n') == text
    assert cached.put(TENANT, JOB, 'resources', value) == first
    assert len(client.requests) == 2
    assert cached.get(TENANT, first) == value
    assert all(r['ServerSideEncryption'] == 'aws:kms' and
               r['SSEKMSKeyId'] == 'workspace-key' for r in client.requests)
    assert all(isinstance(k[2], bytes) and len(k[2]) == 32 and isinstance(v, str)
               for k, v in cached.entries.items())
    with pytest.raises(RuntimeError, match='closed'):
        writer.put(TENANT, JOB, 'resources', value)


@pytest.mark.parametrize('failed_kind', ['resources', 'manifest'])
def test_failed_batch_does_not_promote_entries_and_retry_uploads(failed_kind):
    cached, client = store()
    stable = cached.put(TENANT, JOB, 'coverage', {'stable': True})
    before = cached.entries.copy()
    client.fail_kind = failed_kind
    with pytest.raises(OSError, match='synthetic failed upload'):
        with cached.batch() as writer:
            ref = writer.put(TENANT, JOB, 'resources', {'items': [1]})
            writer.put(TENANT, JOB, 'manifest', {'resource': ref})
    assert cached.entries == before
    assert cached.put(TENANT, JOB, 'coverage', {'stable': True}) == stable
    assert not any('/manifest-' in r['Key'] for r in client.requests)
    client.fail_kind = None
    with cached.batch() as writer:
        retry = writer.put(TENANT, JOB, 'resources', {'items': [1]})
        manifest = writer.put(TENANT, JOB, 'manifest', {'resource': retry})
    assert retry != ref
    assert client.requests[-1]['Key'] == 'artifacts/' + manifest


def test_cached_manifest_cannot_hide_failed_dependency_even_after_caught_flush_error():
    cached, client = store()
    cached.put(TENANT, JOB, 'manifest', {'same': True})
    before = cached.entries.copy()
    client.fail_kind = 'resources'
    with pytest.raises(OSError):
        with cached.batch() as writer:
            writer.put(TENANT, JOB, 'resources', {'items': [1]})
            with pytest.raises(OSError):
                writer.flush()
            writer.put(TENANT, JOB, 'manifest', {'same': True})
    assert cached.entries == before
    assert len(client.requests) == 1


def test_producer_error_discards_staging_and_closes_pool():
    cached, client = store()
    with pytest.raises(ValueError, match='rendering'):
        with cached.batch() as writer:
            first = writer.put(TENANT, JOB, 'findings', {'items': []})
            raise ValueError('rendering')
    assert not cached.entries
    with cached.batch() as writer:
        assert writer.put(TENANT, JOB, 'findings', {'items': []}) != first
    assert not any(t.name.startswith('peaso-artifact') for t in threading.enumerate())


def test_reuse_preserves_parallel_uploads_and_manifest_barrier():
    entered, release = threading.Barrier(5, timeout=5), threading.Event()

    class Gated(Objects):
        def put_object(self, **request):
            if '/manifest-' not in request['Key']:
                entered.wait()
                assert release.wait(5)
            super().put_object(**request)

    cached, client = store(Gated())

    def publish():
        with cached.batch(workers=4) as writer:
            refs = [writer.put(TENANT, JOB, 'resources', {'ordinal': n}) for n in range(4)]
            return writer.put(TENANT, JOB, 'manifest', {'references': refs})

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(publish)
        try:
            entered.wait()
            assert not future.done() and not cached.entries
            assert not any('/manifest-' in r['Key'] for r in client.requests)
        finally:
            release.set()
        manifest = future.result(timeout=5)
    assert client.requests[-1]['Key'] == 'artifacts/' + manifest
    assert len(cached.entries) == 5


@pytest.mark.parametrize('capacity', [0, 2])
def test_staging_is_bounded_and_eviction_only_reuploads(capacity):
    cached, client = store(max_entries=capacity)
    with cached.batch(workers=2, max_pending_bytes=1000) as writer:
        for ordinal in range(12):
            ref = writer.put(TENANT, JOB, 'resources', {
                'ordinal': ordinal, 'data': 'x' * (5000 if ordinal == 7 else 500)})
            assert len(writer.entries) <= capacity
            assert writer.writer.pending_bytes <= 1000
            assert len(writer.writer.pending) <= 4
        last = writer.put(TENANT, JOB, 'resources', {'ordinal': 11, 'data': 'x' * 500})
        assert (last == ref) is bool(capacity)
    assert len(cached.entries) <= capacity
    assert len(client.requests) == (12 if capacity else 13)


def test_bytes_kind_scope_private_and_closed_writer_boundaries():
    cached, client = store()
    with cached.batch() as writer:
        for tenant, job in [('other', JOB), (TENANT, 'b' * 32)]:
            with pytest.raises(ValueError):
                writer._put_json_bytes(tenant, job, 'resources', b'{}')
        with pytest.raises(TypeError):
            writer._put_json_bytes(TENANT, JOB, 'resources', bytearray(b'{}'))
        a = writer._put_json_bytes(TENANT, JOB, 'resources', b'{}')
        assert writer._put_json_bytes(TENANT, JOB, 'coverage', b'{}') != a
        assert writer._put_json_bytes(TENANT, JOB, 'resources', b'{ }') != a
        for _ in range(2):
            writer._put_json_bytes(TENANT, JOB, 'snapshot', b'{}')
    assert len(cached.entries) == 3 and len(client.requests) == 5
    with pytest.raises(RuntimeError, match='closed'):
        writer._put_json_bytes(TENANT, JOB, 'snapshot', b'{}')


def test_concurrent_batches_share_only_completed_uploads():
    cached, client = store()

    def publish(_):
        with cached.batch() as writer:
            return writer.put(TENANT, JOB, 'resources', {'same': True})

    with ThreadPoolExecutor(max_workers=8) as pool:
        refs = list(pool.map(publish, range(24)))
    assert len(set(refs)) == len(client.requests) == 1


def test_new_scan_or_wrapper_starts_without_prior_reference_reuse():
    cached, client = store()
    first = cached.put(TENANT, JOB, 'resources', {'same': True})
    for job in (JOB, 'b' * 32):
        fresh = ReusableReportArtifacts(cached.artifacts, TENANT, job)
        assert not fresh.entries
        with fresh.batch() as writer:
            assert writer.put(TENANT, job, 'resources', {'same': True}) != first
    assert len(client.requests) == 3


def test_active_batch_cannot_delete_or_nest_through_owner_or_facade():
    cached, client = store()
    with cached.batch() as writer:
        writer.put(TENANT, JOB, 'resources', {'items': []})
        for target in (cached, writer):
            with pytest.raises(RuntimeError):
                target.delete_job(TENANT, JOB)
            with pytest.raises(RuntimeError):
                target.delete_workspace(TENANT)
            with pytest.raises(RuntimeError):
                with target.batch():
                    pass
    assert len(client.requests) == 1


def test_file_and_custom_batch_policy_are_preserved(tmp_path):
    files = ReusableReportArtifacts(FileArtifacts(tmp_path), TENANT, JOB)
    assert not hasattr(files, '_put_json_bytes')
    with files.batch() as writer:
        first = writer.put(TENANT, JOB, 'resources', {'items': []})
        assert writer.put(TENANT, JOB, 'resources', {'items': []}) == first

    class Custom(S3Artifacts):
        def put(self, *args):
            raise AssertionError('custom batch must receive the original adapter')

    custom = Custom('private', Objects())
    wrapped = ReusableReportArtifacts(custom, TENANT, JOB)
    with wrapped.batch() as writer:
        assert writer.artifacts is custom
        writer.put(TENANT, JOB, 'resources', {})
    assert not wrapped.entries


def test_large_report_working_set_reuses_every_durable_chunk_next_checkpoint():
    # Captured large scans publish 1,421 resource chunks and 726 finding/index
    # chunks. A 2,048-entry LRU evicts the next cycle's first items and misses
    # every sequential lookup, despite all native bytes being unchanged.
    cached, client = store()
    chunks = [('resources', i) for i in range(1421)]
    chunks += [('findings', i) for i in range(363)]
    chunks += [('finding-index', i) for i in range(363)]
    references = []
    for cycle in range(2):
        with cached.batch() as writer:
            current = [writer.put(TENANT, JOB, kind, {'items': [i]})
                       for kind, i in chunks]
            current.append(writer.put(TENANT, JOB, 'manifest', {'chunks': current}))
        references.append(current)
    assert references[0] == references[1]
    assert len(client.requests) == len(chunks) + 1
    assert len(cached.entries) <= cached.max_entries
    assert all(type(key[2]) is bytes and len(key[2]) == 32
               and type(reference) is str for key, reference in cached.entries.items())
