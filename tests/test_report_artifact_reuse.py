import concurrent.futures
import json
from pathlib import Path

import boto3
from botocore.stub import Stubber
import pytest

from peaso.storage.artifacts import FileArtifacts, S3Artifacts
from peaso.storage.report_reuse import ReusableReportArtifacts

TENANT, IDENT = 'workspace', 'd'*32


class MeasuredFiles(FileArtifacts):
    writes = 0
    def _write(self, *args, **kwargs):
        self.writes += 1
        return super()._write(*args, **kwargs)


def test_exact_json_and_markdown_are_reused_without_retaining_payload(tmp_path):
    backend = MeasuredFiles(tmp_path)
    artifacts = ReusableReportArtifacts(backend, TENANT, IDENT)
    raw = {'items': [{'id': 'one', 'text': 'Synthetic café evidence'}]}
    first = artifacts.put(TENANT, IDENT, 'resources', raw)
    assert artifacts.put(TENANT, IDENT, 'resources', raw) == first
    markdown = artifacts.put_text(TENANT, IDENT, 'markdown', 'Report café\n'*100000)
    assert artifacts.put_text(TENANT, IDENT, 'markdown', 'Report café\n'*100000) == markdown
    assert backend.writes == 2
    assert backend.get(TENANT, first) == raw
    assert all(isinstance(key[2], bytes) and len(key[2]) == 32 for key in artifacts.entries)
    assert all(isinstance(value, str) for value in artifacts.entries.values())


def test_changed_content_kind_tenant_and_scan_cannot_share_cache_entry(tmp_path):
    artifacts = ReusableReportArtifacts(FileArtifacts(tmp_path), TENANT, IDENT)
    first = artifacts.put(TENANT, IDENT, 'findings', {'items': [1]})
    assert artifacts.put(TENANT, IDENT, 'findings', {'items': [2]}) != first
    assert artifacts.put(TENANT, IDENT, 'coverage', {'items': [1]}) != first
    with pytest.raises(ValueError):
        artifacts.put('another-workspace', IDENT, 'findings', {'items': [1]})
    with pytest.raises(ValueError):
        artifacts.put(TENANT, 'e'*32, 'findings', {'items': [1]})


def test_failed_write_is_not_cached_and_retry_reaches_backend(tmp_path, monkeypatch):
    backend = MeasuredFiles(tmp_path)
    artifacts = ReusableReportArtifacts(backend, TENANT, IDENT)
    original = backend._write
    def fail(*args, **kwargs): raise OSError('simulated failed durable write')
    monkeypatch.setattr(backend, '_write', fail)
    with pytest.raises(OSError):
        artifacts.put(TENANT, IDENT, 'resources', {'items': []})
    assert not artifacts.entries
    monkeypatch.setattr(backend, '_write', original)
    reference = artifacts.put(TENANT, IDENT, 'resources', {'items': []})
    assert backend.get(TENANT, reference) == {'items': []}


def test_lru_bound_and_missing_local_object_fall_back_to_normal_write(tmp_path):
    backend = MeasuredFiles(tmp_path)
    artifacts = ReusableReportArtifacts(backend, TENANT, IDENT, max_entries=2)
    first = artifacts.put(TENANT, IDENT, 'coverage', {'items': [1]})
    artifacts.put(TENANT, IDENT, 'coverage', {'items': [2]})
    artifacts.put(TENANT, IDENT, 'coverage', {'items': [3]})
    assert len(artifacts.entries) == 2
    assert artifacts.put(TENANT, IDENT, 'coverage', {'items': [1]}) != first
    last = artifacts.put(TENANT, IDENT, 'coverage', {'items': [3]})
    (tmp_path/last).unlink()
    replacement = artifacts.put(TENANT, IDENT, 'coverage', {'items': [3]})
    assert replacement != last and backend.get(TENANT, replacement) == {'items': [3]}


def test_deletion_clears_scoped_reference_cache(tmp_path):
    artifacts = ReusableReportArtifacts(FileArtifacts(tmp_path), TENANT, IDENT)
    artifacts.put(TENANT, IDENT, 'resources', {'items': []})
    artifacts.delete_job(TENANT, IDENT)
    assert not artifacts.entries
    reference = artifacts.put(TENANT, IDENT, 'resources', {'items': []})
    assert artifacts.get(TENANT, reference) == {'items': []}
    artifacts.delete_workspace(TENANT)
    assert not artifacts.entries


def test_raw_checkpoint_and_private_evidence_never_enter_reuse_cache(tmp_path):
    backend = MeasuredFiles(tmp_path)
    artifacts = ReusableReportArtifacts(backend, TENANT, IDENT)
    first = artifacts.put(TENANT, IDENT, 'snapshot', {'native': 'fixture'})
    assert artifacts.put(TENANT, IDENT, 'snapshot', {'native': 'fixture'}) != first
    artifacts.put_secret_evidence(TENANT, IDENT, {'encrypted': 'first'})
    artifacts.put_secret_evidence(TENANT, IDENT, {'encrypted': 'second'})
    assert backend.writes == 4 and not artifacts.entries


def test_concurrent_identical_publication_commits_once(tmp_path):
    backend = MeasuredFiles(tmp_path)
    artifacts = ReusableReportArtifacts(backend, TENANT, IDENT)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        refs = list(pool.map(lambda _: artifacts.put(TENANT, IDENT, 'findings', {'items': [1]}), range(32)))
    assert len(set(refs)) == 1 and backend.writes == 1


def test_custom_adapter_put_override_is_preserved(tmp_path):
    class Custom(FileArtifacts):
        def put(self, tenant, ident, kind, value):
            return super().put(tenant, ident, kind, {'filtered': True})
    artifacts = ReusableReportArtifacts(Custom(tmp_path), TENANT, IDENT)
    reference = artifacts.put(TENANT, IDENT, 'report', {'native': 'not-accepted-by-custom-adapter'})
    assert artifacts.get(TENANT, reference) == {'filtered': True} and not artifacts.entries


@pytest.mark.parametrize('kms', [None, 'fixture-kms-key'])
def test_s3_reuse_retains_existing_encryption_and_read_format(kms):
    client = boto3.client('s3', region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')
    backend = S3Artifacts('fixture-private-bucket', client, kms_key=kms)
    artifacts = ReusableReportArtifacts(backend, TENANT, IDENT)
    from botocore.stub import ANY
    expected = {'Bucket': 'fixture-private-bucket', 'Key': ANY,
        'Body': json.dumps({'label': 'café'}, separators=(',', ':'), ensure_ascii=False).encode(),
        'ContentType': 'application/json', 'ServerSideEncryption': 'aws:kms' if kms else 'AES256'}
    if kms:
        expected['SSEKMSKeyId'] = kms
    with Stubber(client) as stub:
        stub.add_response('put_object', {}, expected)
        first = artifacts.put(TENANT, IDENT, 'findings', {'label': 'café'})
        assert artifacts.put(TENANT, IDENT, 'findings', {'label': 'café'}) == first
        stub.assert_no_pending_responses()


def test_s3_large_artifact_retains_gzip_metadata_and_failed_put_retries():
    import gzip
    from botocore.stub import ANY
    client = boto3.client('s3', region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')
    artifacts = ReusableReportArtifacts(S3Artifacts('private-bucket', client), TENANT, IDENT)
    value = {'items': ['synthetic-normalized-public-evidence']*10000}
    raw = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
    expected = {'Bucket': 'private-bucket', 'Key': ANY,
        'Body': gzip.compress(raw, compresslevel=1, mtime=0), 'ContentType': 'application/json',
        'ServerSideEncryption': 'AES256', 'ContentEncoding': 'gzip',
        'Metadata': {'peaso-uncompressed-bytes': str(len(raw))}}
    with Stubber(client) as stub:
        stub.add_client_error('put_object', service_error_code='ServiceUnavailable',
            expected_params=expected)
        stub.add_response('put_object', {}, expected)
        from botocore.exceptions import ClientError
        with pytest.raises(ClientError):
            artifacts.put(TENANT, IDENT, 'coverage', value)
        assert not artifacts.entries
        reference = artifacts.put(TENANT, IDENT, 'coverage', value)
        assert artifacts.put(TENANT, IDENT, 'coverage', value) == reference
        stub.assert_no_pending_responses()


def test_full_published_bundle_matches_every_stored_payload(tmp_path):
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    from peaso.storage.reports import publish_report
    from peaso.worker import redact_report
    from peaso.storage.artifacts import check_reference
    snapshot = make_snapshot('aws', ['123456789012/us-east-1'], [{
        'type': 'bucket', 'scope': '123456789012/us-east-1', 'status': 'collected',
        'items': [{'Name': 'fixture-bucket'}]}])
    report = redact_report(evaluate_snapshot(snapshot, categories=['hardening'],
        checks=['aws.s3.default_encryption'], include_not_applicable=False))
    plain, backend = MeasuredFiles(tmp_path/'plain'), MeasuredFiles(tmp_path/'reused')
    reused = ReusableReportArtifacts(backend, TENANT, IDENT)
    def expand(value, artifacts):
        if isinstance(value, dict): return {key: expand(child, artifacts) for key, child in value.items()}
        if isinstance(value, list): return [expand(child, artifacts) for child in value]
        if isinstance(value, str):
            try: check_reference(TENANT, value)
            except ValueError: return value
            if value.endswith('.md'): return artifacts.get_text(TENANT, value)
            return expand(artifacts.get(TENANT, value), artifacts)
        return value
    for sequence in (1, 2):
        report['publication'] = {'state': 'partial', 'phase': 'collecting', 'sequence': sequence}
        if sequence == 2:
            report['findings'][0]['evidence']['synthetic_revision'] = 'new evidence'
        original = publish_report(plain, TENANT, IDENT, report, snapshot)
        candidate = publish_report(reused, TENANT, IDENT, report, snapshot)
        assert expand(plain.get(TENANT, original), plain) == expand(reused.get(TENANT, candidate), reused)
    assert backend.writes < plain.writes
