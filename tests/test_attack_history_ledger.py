"""Immutable ledger blobs for large, replayable CloudTrail partitions."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from peaso.attack_detection.history_s3 import CloudTrailObject, DayManifest
from peaso.storage.attack_history_ledger import LocalAttackHistoryLedger
from peaso.auth.secrets import CredentialCipher
from peaso.storage.attack_history_sqlite import AttackHistoryError, SQLiteAttackHistoryStore


def manifest() -> DayManifest:
    return DayManifest("logs-bucket", "AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/18/",
                       "123456789012", "us-east-1", "2026-10-18",
                       (CloudTrailObject("AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/18/a.json.gz",
                                         '"etag-a"', 100),), 1,
                       datetime.now(timezone.utc).isoformat())


def finding(index: int) -> dict:
    return {"rule_id": "rule-1", "title": "Observed change", "severity": "medium",
            "technique_id": "aws-observed-change", "event_id": f"event-{index}",
            "event_time": "2026-10-18T12:00:00Z", "account_id": "123456789012",
            "actor_id": "arn:aws:iam::123456789012:user/reviewer", "target_id": "trail/reviewed",
            "evidence": {"event.source": "cloudtrail.amazonaws.com", "event.name": "StopLogging",
                         "request.stop_logging_observed": True},
            "description": "A completed StopLogging API call was observed.",
            "legitimate_context": ["Reviewed maintenance may cause this event."]}


def test_manifest_content_address_and_tenant_job_binding(tmp_path: Path) -> None:
    ledger = LocalAttackHistoryLedger(tmp_path)
    selected = manifest()
    pointer = ledger.put_manifest("tenant-a", "job-a", selected)
    assert ledger.put_manifest("tenant-a", "job-a", selected) == pointer
    assert ledger.get_manifest("tenant-a", "job-a", pointer.ref, pointer.sha256) == selected
    with pytest.raises(ValueError):
        ledger.get_manifest("tenant-b", "job-a", pointer.ref, pointer.sha256)
    with pytest.raises(ValueError):
        ledger.get_manifest("tenant-a", "job-b", pointer.ref, pointer.sha256)
    path = ledger._path("tenant-a", "job-a", "manifest", pointer.ref, pointer.sha256)
    path.write_text("{}")
    with pytest.raises(ValueError, match="digest mismatch"):
        ledger.get_manifest("tenant-a", "job-a", pointer.ref, pointer.sha256)


def test_more_than_ten_thousand_findings_chunk_without_truncation(tmp_path: Path) -> None:
    ledger = LocalAttackHistoryLedger(tmp_path)
    chunks = ledger.put_finding_chunks("tenant-a", "job-a", (finding(i) for i in range(17_001)))
    assert len(chunks) > 10
    assert sum(item["count"] for item in chunks) == 17_001
    assert all(item["count"] <= 1000 for item in chunks)
    assert sum(len(ledger.get_finding_chunk("tenant-a", "job-a", item)) for item in chunks) == 17_001
    with pytest.raises(ValueError):
        ledger.get_finding_chunk("tenant-b", "job-a", chunks[0])


def test_raw_evidence_and_corrupted_chunk_fail_closed(tmp_path: Path) -> None:
    ledger = LocalAttackHistoryLedger(tmp_path)
    bad = finding(1)
    bad["evidence"]["rawEvent"] = {"secret": "not allowed"}
    with pytest.raises(ValueError):
        ledger.put_finding_chunks("tenant-a", "job-a", [bad])
    good = ledger.put_finding_chunks("tenant-a", "job-a", [finding(1)])
    wrong = dict(good[0], count=2)
    with pytest.raises(ValueError, match="count mismatch"):
        ledger.get_finding_chunk("tenant-a", "job-a", wrong)


def history_store(tmp_path: Path) -> SQLiteAttackHistoryStore:
    return SQLiteAttackHistoryStore(tmp_path, CredentialCipher(tmp_path / "identity"))


def history_source() -> dict:
    return {"kind": "aws_cloudtrail_s3", "bucket": "logs-bucket",
            "prefix": "AWSLogs/123456789012/CloudTrail/",
            "account_id": "123456789012", "region": "us-east-1", "day": "2026-10-18"}


def history_job(db: SQLiteAttackHistoryStore) -> str:
    connector = {"data": {"provider": "aws"}, "auth": {"method": "role", "role_arn": "example"}}
    digest = hashlib.sha256(json.dumps(connector, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return db.create_job("tenant-a", "connector-1", history_source(), "a" * 64,
                         digest, connector, source_version="cloudtrail-s3-v1",
                         rule_version="pinned-rules-v1", normalizer_version="aws-v1")["id"]


def fixed_manifest(*, late: bool = False, listed: str = "2026-10-20T00:00:00+00:00") -> DayManifest:
    original = manifest()
    objects = original.objects + ((CloudTrailObject(original.prefix + "late.json.gz", '"late"', 100),) if late else ())
    return DayManifest(original.bucket, original.prefix, original.account, original.region,
                       original.day, objects, 1, listed)


def stage_and_commit(db: SQLiteAttackHistoryStore, job: str, generation: int,
                     *, finding_total: int = 1) -> None:
    first = fixed_manifest(listed="2026-10-19T00:00:00+00:00")
    db.register_cloudtrail_first_manifest("tenant-a", job, "worker-a", generation,
                                          "main", first, now=1792454400)
    hashes = [(f"event-{index}", hashlib.sha256(f"payload-{index}".encode()).hexdigest())
              for index in range(finding_total)]
    chunks = db.ledger.put_finding_chunks("tenant-a", job,
                                           (finding(index) for index in range(finding_total)))
    checkpoint = db.ledger.put_object_checkpoint("tenant-a", job, "main",
        first.objects[0], "c" * 64, hashes, chunks)
    db.commit_cloudtrail_object("tenant-a", job, "worker-a", generation,
                                "main", first.objects[0], "c" * 64, hashes,
                                checkpoint, now=1792454401)


def test_aws_partition_attestation_completes_only_reconciled_ledger(tmp_path: Path) -> None:
    db = history_store(tmp_path)
    job = history_job(db)
    generation = db.claim_job("tenant-a", job, "worker-a", lease_seconds=3600, now=1792454399)
    stage_and_commit(db, job, generation)
    state = db.finalize_cloudtrail_partition("tenant-a", job, "worker-a", generation,
        "main", fixed_manifest(), grace_seconds=3600, now=1792454500)
    assert state == "complete_as_of"
    ref, digest = db.build_cloudtrail_result("tenant-a", job, "worker-a", generation,
                                            "main", now=1792454501)
    db.complete_job("tenant-a", job, "worker-a", generation, ref, digest, now=1792454502)
    result = db.read_result("tenant-a", job)
    assert result["schema_version"] == 2
    assert result["summary"]["event_count"] == 1
    assert result["summary"]["detection_count"] == 1
    assert result["summary"]["complete_as_of"] == "2026-10-20T00:00:00+00:00"
    assert len(result["chunks"]) == 1


def test_late_object_and_missing_checkpoint_cannot_attest(tmp_path: Path) -> None:
    db = history_store(tmp_path)
    job = history_job(db)
    generation = db.claim_job("tenant-a", job, "worker-a", lease_seconds=3600, now=1792454399)
    first = fixed_manifest(listed="2026-10-19T00:00:00+00:00")
    db.register_cloudtrail_first_manifest("tenant-a", job, "worker-a", generation,
                                          "main", first, now=1792454400)
    assert db.finalize_cloudtrail_partition("tenant-a", job, "worker-a", generation,
        "main", fixed_manifest(), grace_seconds=3600, now=1792454500) == "provisional"
    stage_and_commit(db, job, generation)
    assert db.finalize_cloudtrail_partition("tenant-a", job, "worker-a", generation,
        "main", fixed_manifest(late=True), grace_seconds=3600, now=1792454500) == "provisional"
    assert db.get_job("tenant-a", job)["status"] == "running"
    with pytest.raises(AttackHistoryError):
        db.build_cloudtrail_result("tenant-a", job, "worker-a", generation,
                                   "main", now=1792454501)


def test_grace_window_is_computed_from_selected_day(tmp_path: Path) -> None:
    db = history_store(tmp_path)
    job = history_job(db)
    generation = db.claim_job("tenant-a", job, "worker-a", lease_seconds=3600, now=1792454399)
    stage_and_commit(db, job, generation)
    assert db.finalize_cloudtrail_partition("tenant-a", job, "worker-a", generation,
        "main", fixed_manifest(), grace_seconds=7 * 86400, now=1792454500) == "provisional"
    assert db.get_job("tenant-a", job)["status"] == "running"


def test_second_list_must_follow_first_list(tmp_path: Path) -> None:
    db = history_store(tmp_path)
    job = history_job(db)
    generation = db.claim_job("tenant-a", job, "worker-a", lease_seconds=3600, now=1792454399)
    stage_and_commit(db, job, generation)
    older = fixed_manifest(listed="2026-10-18T23:59:00+00:00")
    assert db.finalize_cloudtrail_partition("tenant-a", job, "worker-a", generation,
        "main", older, grace_seconds=3600, now=1792454500) == "provisional"


def test_large_finding_index_is_complete_without_inline_truncation(tmp_path: Path) -> None:
    db = history_store(tmp_path)
    job = history_job(db)
    generation = db.claim_job("tenant-a", job, "worker-a", lease_seconds=3600, now=1792454399)
    stage_and_commit(db, job, generation, finding_total=10_001)
    assert db.finalize_cloudtrail_partition("tenant-a", job, "worker-a", generation,
        "main", fixed_manifest(), grace_seconds=3600, now=1792454500) == "complete_as_of"
    ref, digest = db.build_cloudtrail_result("tenant-a", job, "worker-a", generation,
                                            "main", now=1792454501)
    db.complete_job("tenant-a", job, "worker-a", generation, ref, digest, now=1792454502)
    result = db.read_result("tenant-a", job)
    assert result["summary"]["detection_count"] == 10_001
    assert len(result["chunks"]) > 10
    assert sum(len(db.ledger.get_finding_chunk("tenant-a", job, item))
               for item in result["chunks"]) == 10_001


def test_crash_replay_reclaims_lease_without_double_counting(tmp_path: Path) -> None:
    db = history_store(tmp_path)
    job = history_job(db)
    generation1 = db.claim_job("tenant-a", job, "worker-a", lease_seconds=10, now=1792454399)
    stage_and_commit(db, job, generation1, finding_total=2)
    reopened = history_store(tmp_path)
    generation2 = reopened.claim_job("tenant-a", job, "worker-a", lease_seconds=3600, now=1792454420)
    assert generation2 == generation1 + 1
    stage_and_commit(reopened, job, generation2, finding_total=2)
    assert reopened.finalize_cloudtrail_partition("tenant-a", job, "worker-a", generation2,
        "main", fixed_manifest(), grace_seconds=3600, now=1792454500) == "complete_as_of"
    ref, digest = reopened.build_cloudtrail_result("tenant-a", job, "worker-a", generation2,
                                                   "main", now=1792454501)
    reopened.complete_job("tenant-a", job, "worker-a", generation2, ref, digest, now=1792454502)
    assert reopened.read_result("tenant-a", job)["summary"] == {
        "source_count": 1, "event_count": 2, "detection_count": 2,
        "partial": False, "complete_as_of": "2026-10-20T00:00:00+00:00"}
    with pytest.raises(AttackHistoryError):
        db.complete_job("tenant-a", job, "worker-a", generation1, ref, digest,
                        now=1792454502)


def test_tampered_chunk_or_attestation_blocks_completed_state(tmp_path: Path) -> None:
    db = history_store(tmp_path)
    job = history_job(db)
    generation = db.claim_job("tenant-a", job, "worker-a", lease_seconds=3600, now=1792454399)
    stage_and_commit(db, job, generation)
    assert db.finalize_cloudtrail_partition("tenant-a", job, "worker-a", generation,
        "main", fixed_manifest(), grace_seconds=3600, now=1792454500) == "complete_as_of"
    ref, digest = db.build_cloudtrail_result("tenant-a", job, "worker-a", generation,
                                            "main", now=1792454501)
    index = db.artifacts.get_result("tenant-a", job, ref, digest)
    chunk = index["chunks"][0]
    path = db.ledger._path("tenant-a", job, "findings", chunk["ref"], chunk["sha256"])
    original = path.read_bytes()
    path.write_bytes(b"{}")
    with pytest.raises(AttackHistoryError, match="proof is invalid"):
        db.complete_job("tenant-a", job, "worker-a", generation, ref, digest,
                        now=1792454502)
    assert db.get_job("tenant-a", job)["status"] == "running"
    path.write_bytes(original)
    proof = index["attestation"]
    path = db.ledger._path("tenant-a", job, "attestation", proof["ref"], proof["sha256"])
    path.write_bytes(b"{}")
    with pytest.raises(AttackHistoryError, match="proof is invalid"):
        db.complete_job("tenant-a", job, "worker-a", generation, ref, digest,
                        now=1792454502)
