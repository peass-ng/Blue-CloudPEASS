"""Focused state-machine tests for isolated historical attack jobs."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from peaso.storage.attack_history_sqlite import AttackHistoryError, SQLiteAttackHistoryStore
from peaso.auth.secrets import CredentialCipher


RULE = "a" * 64
PRIVATE_CONNECTOR = {"data": {"provider": "aws", "name": "frozen"},
                     "auth": {"access_key_id": "TEST_PRIVATE_ACCESS_KEY", "secret_access_key": "TEST_PRIVATE_SECRET"}}
CONNECTOR = hashlib.sha256(json.dumps(PRIVATE_CONNECTOR, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
CHECKPOINT = "c" * 64
RESULT = "d" * 64
SOURCE = {"kind": "aws_cloudtrail_s3", "bucket": "customer-audit", "prefix": "AWSLogs/123/", "region": "us-east-1", "days": 30}
EMPTY_RESULT = {"schema_version": 1, "summary": {"source_count": 1, "event_count": 0,
                "detection_count": 0, "partial": False}, "detections": []}


def store(tmp_path: Path, *, active: int = 10, total: int = 1000) -> SQLiteAttackHistoryStore:
    return SQLiteAttackHistoryStore(tmp_path, CredentialCipher(tmp_path / "identity"),
                                    max_active_jobs=active, max_jobs_per_tenant=total)


def create(db: SQLiteAttackHistoryStore, tenant: str = "tenant-a", **kw):
    return db.create_job(tenant, "connector-1", SOURCE, RULE, CONNECTOR, PRIVATE_CONNECTOR,
                         source_version="source-v1", rule_version="rules-v1",
                         normalizer_version="normalizer-v1", **kw)


def raises(code: int, action):
    with pytest.raises(AttackHistoryError) as exc:
        action()
    assert exc.value.status == code


def test_tenant_scoped_history_and_minimal_projection(tmp_path: Path) -> None:
    db = store(tmp_path)
    first = create(db)
    other = create(db, "tenant-b")
    assert [r["id"] for r in db.list_jobs("tenant-a")] == [first["id"]]
    assert [r["id"] for r in db.list_jobs("tenant-b")] == [other["id"]]
    raises(404, lambda: db.get_job("tenant-b", first["id"]))
    raises(404, lambda: db.cancel_job("tenant-b", first["id"]))
    raises(404, lambda: db.list_partitions("tenant-b", first["id"]))
    assert first["source"] == SOURCE
    assert set(first) == {"id", "connector_id", "source", "source_fingerprint", "rule_fingerprint",
                          "connector_fingerprint", "status", "result_available", "created_at", "updated_at", "error_code"}
    assert first["result_available"] is False
    assert len(first["source_fingerprint"]) == 64
    assert db.path.name == "attack_history.sqlite3"
    assert (tmp_path / "peaso.sqlite3").exists() is False


def test_source_allowlist_and_fingerprint_snapshot(tmp_path: Path) -> None:
    db = store(tmp_path)
    first = create(db)
    reordered = {"days": 30, "region": "us-east-1", "prefix": "AWSLogs/123/", "bucket": "customer-audit", "kind": "aws_cloudtrail_s3"}
    again = db.create_job("tenant-a", "connector-1", reordered, RULE, CONNECTOR, PRIVATE_CONNECTOR,
                          source_version="source-v1", rule_version="rules-v1", normalizer_version="normalizer-v1")
    assert first["source_fingerprint"] == again["source_fingerprint"]
    raises(400, lambda: db.create_job("tenant-a", "connector-1", dict(SOURCE, access_key="secret"), RULE, CONNECTOR,
                                      PRIVATE_CONNECTOR, source_version="source-v1", rule_version="rules-v1",
                                      normalizer_version="normalizer-v1"))
    raises(400, lambda: db.create_job("tenant-a", "connector-1", dict(SOURCE, kind=[]), RULE, CONNECTOR,
                                      PRIVATE_CONNECTOR, source_version="source-v1", rule_version="rules-v1",
                                      normalizer_version="normalizer-v1"))
    raises(400, lambda: db.create_job("tenant-a", "connector-1", SOURCE, "not-a-hash", CONNECTOR,
                                      PRIVATE_CONNECTOR, source_version="source-v1", rule_version="rules-v1",
                                      normalizer_version="normalizer-v1"))
    with sqlite3.connect(db.path) as sql:
        columns = {r[1] for r in sql.execute("PRAGMA table_info(attack_jobs)")}
    assert "auth" not in columns and "raw_logs" not in columns
    assert "connector_ciphertext" in columns
    assert b"TEST_PRIVATE_SECRET" not in db.path.read_bytes()
    assert "TEST_PRIVATE_SECRET" not in str(db.get_job("tenant-a", first["id"]))


def test_idempotency_is_per_tenant_and_exact_request(tmp_path: Path) -> None:
    db = store(tmp_path, active=1)
    first = create(db, idempotency_key="idem-1", now=10)
    assert create(db, idempotency_key="idem-1", now=20)["id"] == first["id"]
    raises(409, lambda: db.create_job("tenant-a", "connector-1", dict(SOURCE, days=31), RULE, CONNECTOR,
                                      PRIVATE_CONNECTOR, source_version="source-v1", rule_version="rules-v1",
                                      normalizer_version="normalizer-v1", idempotency_key="idem-1"))
    assert create(db, "tenant-b", idempotency_key="idem-1")["id"] != first["id"]
    raises(429, lambda: create(db, idempotency_key="idem-2"))


def test_atomic_capacity_under_competing_creators(tmp_path: Path) -> None:
    db = store(tmp_path, active=1)

    def attempt(i: int):
        try:
            return create(db, idempotency_key=f"request-{i}")["id"]
        except AttackHistoryError as exc:
            return exc.status

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))
    assert len([value for value in outcomes if isinstance(value, str)]) == 1
    assert outcomes.count(429) == 7
    assert len(db.list_jobs("tenant-a")) == 1


def test_crash_reclaim_replay_and_transactional_checkpoint(tmp_path: Path) -> None:
    db = store(tmp_path)
    job = create(db, now=0, expected_partitions=("part-1",))["id"]
    gen1 = db.claim_job("tenant-a", job, "worker-a", lease_seconds=10, now=1)
    assert gen1 == 1
    db.checkpoint_partition("tenant-a", job, "worker-a", gen1, "part-1", 1,
                            "attack-checkpoint/part-1/1", CHECKPOINT, now=2)
    db.checkpoint_partition("tenant-a", job, "worker-a", gen1, "part-1", 1,
                            "attack-checkpoint/part-1/1", CHECKPOINT, now=3)
    raises(409, lambda: db.checkpoint_partition("tenant-a", job, "worker-a", gen1, "part-1", 1,
                                                "attack-checkpoint/changed", CHECKPOINT, now=4))
    raises(409, lambda: db.checkpoint_partition("tenant-a", job, "worker-a", gen1, "part-1", 0,
                                                "attack-checkpoint/old", CHECKPOINT, now=4))
    raises(409, lambda: db.claim_job("tenant-a", job, "worker-b", now=5))
    gen2 = db.claim_job("tenant-a", job, "worker-b", lease_seconds=20, now=12)
    assert gen2 == 2
    raises(409, lambda: db.checkpoint_partition("tenant-a", job, "worker-a", gen1, "part-1", 2,
                                                "attack-checkpoint/stale", CHECKPOINT, now=13))
    assert db.list_partitions("tenant-a", job)[0]["sequence"] == 1
    db.checkpoint_partition("tenant-a", job, "worker-b", gen2, "part-1", 2,
                            "attack-checkpoint/part-1/2", CHECKPOINT, finalized=True, now=14)
    assert db.list_partitions("tenant-a", job)[0]["sequence"] == 2
    reopened = store(tmp_path)
    assert reopened.list_partitions("tenant-a", job)[0]["checkpoint_ref"] == "attack-checkpoint/part-1/2"
    ref, digest = reopened.write_result("tenant-a", job, "worker-b", gen2, EMPTY_RESULT, now=15)
    reopened.complete_job("tenant-a", job, "worker-b", gen2, ref, digest, now=15)
    assert reopened.get_job("tenant-a", job)["status"] == "completed"
    assert reopened.result_pointer("tenant-a", job) == {"ref": ref, "sha256": digest}
    assert reopened.read_result("tenant-a", job)["summary"]["event_count"] == 0
    raises(409, lambda: reopened.checkpoint_partition("tenant-a", job, "worker-b", gen2, "part-1", 3,
                                                      "attack-checkpoint/late", CHECKPOINT, now=16))


def test_cancel_invalidates_worker_and_frees_separate_capacity(tmp_path: Path) -> None:
    db = store(tmp_path, active=1, total=2)
    job = create(db)["id"]
    gen = db.claim_job("tenant-a", job, "worker-a", now=10)
    assert db.cancel_job("tenant-a", job, now=11)["status"] == "cancelled"
    assert db.cancel_job("tenant-a", job, now=12)["status"] == "cancelled"
    raises(409, lambda: db.checkpoint_partition("tenant-a", job, "worker-a", gen, "part-1", 1,
                                                "attack-checkpoint/late", CHECKPOINT, now=12))
    raises(409, lambda: db.complete_job("tenant-a", job, "worker-a", gen,
                                       f"attack-results/{job}/{RESULT}", RESULT, now=12))
    raises(409, lambda: db.write_result("tenant-a", job, "worker-a", gen, EMPTY_RESULT, now=12))
    raises(409, lambda: db.claim_job("tenant-a", job, "worker-b", now=12))
    second = create(db)
    assert second["status"] == "queued"
    raises(429, lambda: create(db))


def test_failure_codes_and_expired_lease_are_closed(tmp_path: Path) -> None:
    db = store(tmp_path)
    job = create(db)["id"]
    gen = db.claim_job("tenant-a", job, "worker-a", lease_seconds=5, now=10)
    raises(400, lambda: db.fail_job("tenant-a", job, "worker-a", gen, "raw cloud error", now=11))
    raises(409, lambda: db.fail_job("tenant-a", job, "worker-a", gen, "access_denied", now=15))
    db.renew_lease("tenant-a", job, "worker-a", gen, lease_seconds=10, now=14)
    db.fail_job("tenant-a", job, "worker-a", gen, "access_denied", now=16)
    assert db.get_job("tenant-a", job)["error_code"] == "access_denied"
    raises(409, lambda: db.cancel_job("tenant-a", job))


def test_completion_requires_every_planned_partition_final_and_bound_result(tmp_path: Path) -> None:
    db = store(tmp_path)
    job = create(db, expected_partitions=("first", "second"))["id"]
    gen = db.claim_job("tenant-a", job, "worker-a", now=10)
    result_ref = f"attack-results/{job}/{RESULT}"
    raises(409, lambda: db.complete_job("tenant-a", job, "worker-a", gen,
                                        result_ref, RESULT, now=11))  # empty
    db.checkpoint_partition("tenant-a", job, "worker-a", gen, "first", 1,
                            "attack-checkpoint/first", CHECKPOINT, finalized=True, now=12)
    raises(409, lambda: db.complete_job("tenant-a", job, "worker-a", gen,
                                        result_ref, RESULT, now=13))  # missing second
    raises(400, lambda: db.checkpoint_partition("tenant-a", job, "worker-a", gen, "unplanned", 1,
                                                "attack-checkpoint/unplanned", CHECKPOINT, finalized=True, now=13))
    db.checkpoint_partition("tenant-a", job, "worker-a", gen, "second", 1,
                            "attack-checkpoint/second", CHECKPOINT, now=14)
    raises(409, lambda: db.complete_job("tenant-a", job, "worker-a", gen,
                                        result_ref, RESULT, now=15))  # second not final
    db.checkpoint_partition("tenant-a", job, "worker-a", gen, "second", 1,
                            "attack-checkpoint/second", CHECKPOINT, finalized=True, now=16)
    raises(400, lambda: db.complete_job("tenant-a", job, "worker-a", gen,
                                        f"attack-results/{job}/wrong", RESULT, now=17))
    raises(409, lambda: db.checkpoint_partition("tenant-a", job, "worker-a", gen, "first", 2,
                                                "attack-checkpoint/changed", CHECKPOINT, finalized=True, now=17))
    partial = {**EMPTY_RESULT, "summary": {**EMPTY_RESULT["summary"], "partial": True}}
    partial_ref, partial_digest = db.write_result("tenant-a", job, "worker-a", gen, partial, now=17)
    raises(409, lambda: db.complete_job("tenant-a", job, "worker-a", gen,
                                        partial_ref, partial_digest, now=17))
    no_coverage = {**EMPTY_RESULT, "summary": {**EMPTY_RESULT["summary"], "source_count": 0}}
    empty_ref, empty_digest = db.write_result("tenant-a", job, "worker-a", gen, no_coverage, now=17)
    raises(409, lambda: db.complete_job("tenant-a", job, "worker-a", gen,
                                        empty_ref, empty_digest, now=17))
    real_ref, real_digest = db.write_result("tenant-a", job, "worker-a", gen, EMPTY_RESULT, now=17)
    db.complete_job("tenant-a", job, "worker-a", gen, real_ref, real_digest, now=18)
    assert db.get_job("tenant-a", job)["result_available"] is True
    assert db.result_pointer("tenant-a", job) == {"ref": real_ref, "sha256": real_digest}


def test_encrypted_replay_snapshot_is_private_and_stable(tmp_path: Path) -> None:
    db = store(tmp_path)
    original = json.loads(json.dumps(PRIVATE_CONNECTOR))
    job = create(db)["id"]
    generation = db.claim_job("tenant-a", job, "worker-a", now=10)
    PRIVATE_CONNECTOR["auth"]["secret_access_key"] = "CHANGED_AFTER_CREATION"
    try:
        replay = db.worker_snapshot("tenant-a", job, "worker-a", generation, now=11)
        assert replay["connector"] == original
        assert replay["source_version"] == "source-v1"
        assert replay["rule_version"] == "rules-v1"
        assert replay["normalizer_version"] == "normalizer-v1"
        assert replay["expected_partitions"] == ["main"]
        assert "TEST_PRIVATE_SECRET" not in str(db.get_job("tenant-a", job))
        assert "source_version" not in db.get_job("tenant-a", job)
        assert "connector_ciphertext" not in db.list_jobs("tenant-a")[0]
        assert "auth" not in db.list_jobs("tenant-a")[0]
        raises(409, lambda: db.worker_snapshot("tenant-a", job, "worker-b", generation, now=11))
        raises(404, lambda: db.worker_snapshot("tenant-b", job, "worker-a", generation, now=11))
        assert b"TEST_PRIVATE_SECRET" not in db.path.read_bytes()
        reopened = store(tmp_path)
        assert reopened.worker_snapshot("tenant-a", job, "worker-a", generation, now=12)["connector"] == original
    finally:
        PRIVATE_CONNECTOR["auth"]["secret_access_key"] = original["auth"]["secret_access_key"]


def test_fingerprint_and_versions_participate_in_idempotency(tmp_path: Path) -> None:
    db = store(tmp_path)
    first = create(db, idempotency_key="stable")["id"]
    assert create(db, idempotency_key="stable")["id"] == first
    raises(409, lambda: db.create_job("tenant-a", "connector-1", SOURCE, RULE, CONNECTOR,
                                      PRIVATE_CONNECTOR, source_version="source-v2",
                                      rule_version="rules-v1", normalizer_version="normalizer-v1",
                                      idempotency_key="stable"))
    raises(409, lambda: db.create_job("tenant-a", "connector-1", SOURCE, RULE, "e" * 64,
                                      PRIVATE_CONNECTOR, source_version="source-v1",
                                      rule_version="rules-v1", normalizer_version="normalizer-v1"))


def test_result_file_must_exist_and_match_hash_before_completion(tmp_path: Path) -> None:
    db = store(tmp_path)
    job = create(db)["id"]
    gen = db.claim_job("tenant-a", job, "worker-a", now=10)
    db.checkpoint_partition("tenant-a", job, "worker-a", gen, "main", 1,
                            "attack-checkpoint/main", CHECKPOINT, finalized=True, now=11)
    raises(409, lambda: db.complete_job("tenant-a", job, "worker-a", gen,
                                        f"attack-results/{job}/{RESULT}", RESULT, now=12))
    assert db.get_job("tenant-a", job)["status"] == "running"
    ref, digest = db.write_result("tenant-a", job, "worker-a", gen, EMPTY_RESULT, now=13)
    path = db.artifacts._path("tenant-a", job, ref, digest)
    assert path.read_bytes().startswith(b'{"detections":')
    path.write_bytes(b'{"tampered":true}')
    raises(409, lambda: db.complete_job("tenant-a", job, "worker-a", gen, ref, digest, now=14))
    assert db.get_job("tenant-a", job)["status"] == "running"
    assert db.artifacts.verify_result("tenant-a", job, ref, digest) is False
    ref, digest = db.write_result("tenant-a", job, "worker-a", gen, EMPTY_RESULT, now=15)
    db.complete_job("tenant-a", job, "worker-a", gen, ref, digest, now=16)
    assert db.read_result("tenant-a", job)["job_id"] == job
    path.write_bytes(b'{"tampered":true}')
    raises(409, lambda: db.read_result("tenant-a", job))


def test_result_read_is_bound_to_tenant_and_job(tmp_path: Path) -> None:
    db = store(tmp_path)
    job_a = create(db, "tenant-a")["id"]
    job_b = create(db, "tenant-b")["id"]
    gen = db.claim_job("tenant-a", job_a, "worker-a", now=10)
    ref, digest = db.write_result("tenant-a", job_a, "worker-a", gen, EMPTY_RESULT, now=11)
    assert db.artifacts.verify_result("tenant-a", job_a, ref, digest)
    assert db.artifacts.verify_result("tenant-b", job_a, ref, digest) is False
    assert db.artifacts.verify_result("tenant-a", job_b, ref, digest) is False
    raises(404, lambda: db.read_result("tenant-b", job_a))
    raises(404, lambda: db.write_result("tenant-b", job_a, "worker-a", gen, EMPTY_RESULT, now=11))


def test_artifact_writer_rejects_raw_logs_and_secrets(tmp_path: Path) -> None:
    db = store(tmp_path)
    job = create(db)["id"]
    gen = db.claim_job("tenant-a", job, "worker-a", now=10)
    raises(400, lambda: db.write_result("tenant-a", job, "worker-a", gen,
                                        dict(EMPTY_RESULT, CloudTrailEvent={"raw": True}), now=11))
    finding = {
        "rule_id": "rule-1", "title": "Observed event", "severity": "medium",
        "technique_id": "test", "event_id": "event-1", "event_time": "2026-10-18T00:00:00Z",
        "account_id": "123456789012", "actor_id": "arn:aws:iam::123456789012:user/example",
        "target_id": "arn:aws:iam::123456789012:user/target",
        "evidence": {"rawEvent": "raw log contents"}, "description": "Observed event",
        "legitimate_context": [],
    }
    bad = {"schema_version": 1, "summary": {"source_count": 1, "event_count": 1,
           "detection_count": 1, "partial": False}, "detections": [finding]}
    raises(400, lambda: db.write_result("tenant-a", job, "worker-a", gen, bad, now=11))
    finding["evidence"] = {"event.source": "iam.amazonaws.com", "request.other_user_keyspaces_credential_created": True}
    ref, digest = db.write_result("tenant-a", job, "worker-a", gen, bad, now=11)
    assert db.artifacts.get_result("tenant-a", job, ref, digest)["detections"][0]["evidence"]["event.source"] == "iam.amazonaws.com"
