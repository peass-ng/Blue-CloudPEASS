"""Tenant-scoped, replay-safe state for historical attack-log analysis.

This database is deliberately separate from assessment jobs and weekly scan
quota. It stores source coordinates, fingerprints, and an encrypted connector
snapshot, never raw log events or checkpoint payloads.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid
from collections.abc import Mapping

from peaso.auth.secrets import CredentialCipher
from .attack_history_artifacts import LocalAttackHistoryArtifacts


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_POINTER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,511}\Z")
_SOURCE_FIELDS = frozenset({
    "kind", "bucket", "prefix", "region", "project_id", "cluster_id",
    "subscription_id", "tenant_id", "role_arn", "day", "workspace_id",
    "log_group", "days",
})
_SOURCE_KINDS = frozenset({
    "aws_event_history", "aws_cloudtrail_s3", "gcp_audit", "gke_audit",
    "azure_activity_log", "entra_directory_audit",
})
_TERMINAL = frozenset({"completed", "failed", "cancelled"})


class AttackHistoryError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def _required_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not _IDENT.fullmatch(value):
        raise AttackHistoryError(400, f"Invalid {label}")
    return value


def _fingerprint(value: str, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise AttackHistoryError(400, f"Invalid {label} fingerprint")
    return value


def _source_snapshot(source: Mapping[str, object]) -> tuple[str, str]:
    if not isinstance(source, Mapping) or not source or set(source) - _SOURCE_FIELDS:
        raise AttackHistoryError(400, "Invalid source coordinates")
    if not isinstance(source.get("kind"), str) or source.get("kind") not in _SOURCE_KINDS:
        raise AttackHistoryError(400, "Invalid source kind")
    for key, value in source.items():
        if key == "days":
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 366:
                raise AttackHistoryError(400, "Invalid source days")
        elif not isinstance(value, str) or (not value and key != "prefix") or len(value) > 1024 or any(ord(ch) < 32 for ch in value):
            raise AttackHistoryError(400, f"Invalid source {key}")
    # A strict allowlist prevents caller-supplied credentials or raw events from
    # entering the database, even as extra JSON fields.
    serialized = json.dumps(dict(source), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return serialized, hashlib.sha256(serialized.encode()).hexdigest()


class SQLiteAttackHistoryStore:
    def __init__(self, state_dir: Path, cipher: CredentialCipher, *,
                 max_active_jobs: int = 10, max_jobs_per_tenant: int = 1000):
        if max_active_jobs < 1 or max_jobs_per_tenant < 1:
            raise ValueError("Attack history capacity must be positive")
        self.max_active_jobs = max_active_jobs
        self.max_jobs_per_tenant = max_jobs_per_tenant
        self.cipher = cipher
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.artifacts = LocalAttackHistoryArtifacts(state_dir / "attack_history_artifacts")
        self.path = state_dir / "attack_history.sqlite3"
        with self._connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS attack_jobs (
                    id TEXT PRIMARY KEY,
                    tenant TEXT NOT NULL,
                    connector_id TEXT NOT NULL,
                    source_json TEXT NOT NULL,
                    source_fingerprint TEXT NOT NULL,
                    rule_fingerprint TEXT NOT NULL,
                    connector_fingerprint TEXT NOT NULL,
                    connector_ciphertext TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    rule_version TEXT NOT NULL,
                    normalizer_version TEXT NOT NULL,
                    expected_partitions TEXT NOT NULL,
                    request_fingerprint TEXT NOT NULL,
                    idempotency_key TEXT,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    lease_owner TEXT,
                    lease_until REAL,
                    lease_generation INTEGER NOT NULL DEFAULT 0,
                    error_code TEXT,
                    result_ref TEXT,
                    result_digest TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS attack_jobs_idem
                    ON attack_jobs(tenant,idempotency_key) WHERE idempotency_key IS NOT NULL;
                CREATE INDEX IF NOT EXISTS attack_jobs_tenant
                    ON attack_jobs(tenant,created_at,id);
                CREATE INDEX IF NOT EXISTS attack_jobs_queue
                    ON attack_jobs(status,lease_until);
                CREATE TABLE IF NOT EXISTS attack_partitions (
                    job_id TEXT NOT NULL REFERENCES attack_jobs(id),
                    partition_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    checkpoint_ref TEXT NOT NULL,
                    checkpoint_digest TEXT NOT NULL,
                    finalized INTEGER NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(job_id,partition_id)
                );
            """)
        os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None, factory=_ClosingConnection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @contextmanager
    def _transaction(self):
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _public(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "connector_id": row["connector_id"],
            "source": json.loads(row["source_json"]),
            "source_fingerprint": row["source_fingerprint"],
            "rule_fingerprint": row["rule_fingerprint"],
            "connector_fingerprint": row["connector_fingerprint"],
            "status": row["status"], "result_available": row["result_ref"] is not None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"], "error_code": row["error_code"],
        }

    @staticmethod
    def _row(db: sqlite3.Connection, tenant: str, job_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM attack_jobs WHERE tenant=? AND id=?", (tenant, job_id)).fetchone()
        if row is None:
            raise AttackHistoryError(404, "Attack analysis job not found")
        return row

    def create_job(self, tenant: str, connector_id: str, source: Mapping[str, object],
                   rule_fingerprint: str, connector_fingerprint: str,
                   connector_snapshot: Mapping[str, object], *, source_version: str,
                   rule_version: str, normalizer_version: str,
                   expected_partitions: tuple[str, ...] = ("main",),
                   idempotency_key: str | None = None, now: float | None = None) -> dict:
        tenant = _required_id(tenant, "tenant")
        connector_id = _required_id(connector_id, "connector")
        if idempotency_key is not None:
            _required_id(idempotency_key, "idempotency key")
        source_json, source_hash = _source_snapshot(source)
        rule_hash = _fingerprint(rule_fingerprint, "rule")
        connector_hash = _fingerprint(connector_fingerprint, "connector")
        if not isinstance(connector_snapshot, Mapping):
            raise AttackHistoryError(400, "Invalid connector snapshot")
        try:
            connector_json = json.dumps(dict(connector_snapshot), sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            raise AttackHistoryError(400, "Invalid connector snapshot") from None
        if hashlib.sha256(connector_json.encode()).hexdigest() != connector_hash:
            raise AttackHistoryError(409, "Connector snapshot fingerprint mismatch")
        versions = tuple(_required_id(value, label) for value, label in (
            (source_version, "source version"), (rule_version, "rule version"),
            (normalizer_version, "normalizer version")))
        if (not isinstance(expected_partitions, (tuple, list)) or not expected_partitions
                or len(expected_partitions) > 1000):
            raise AttackHistoryError(400, "Invalid partition plan")
        partitions = tuple(_required_id(value, "partition") for value in expected_partitions)
        if len(set(partitions)) != len(partitions):
            raise AttackHistoryError(400, "Duplicate partition")
        partition_json = json.dumps(partitions, separators=(",", ":"))
        payload = json.dumps([connector_id, source_hash, rule_hash, connector_hash, versions,
                              partitions], separators=(",", ":"))
        request_hash = hashlib.sha256(payload.encode()).hexdigest()
        now = time.time() if now is None else float(now)
        with self._transaction() as db:
            if idempotency_key is not None:
                prior = db.execute("SELECT * FROM attack_jobs WHERE tenant=? AND idempotency_key=?",
                                   (tenant, idempotency_key)).fetchone()
                if prior is not None:
                    if prior["request_fingerprint"] != request_hash:
                        raise AttackHistoryError(409, "Idempotency key belongs to another request")
                    return self._public(prior)
            active = db.execute("SELECT COUNT(*) FROM attack_jobs WHERE tenant=? AND status IN ('queued','running')",
                                (tenant,)).fetchone()[0]
            total = db.execute("SELECT COUNT(*) FROM attack_jobs WHERE tenant=?", (tenant,)).fetchone()[0]
            if active >= self.max_active_jobs or total >= self.max_jobs_per_tenant:
                raise AttackHistoryError(429, "Attack analysis capacity reached")
            job_id = "ah_" + uuid.uuid4().hex
            encrypted_connector = self.cipher.encrypt(dict(connector_snapshot))
            db.execute("""INSERT INTO attack_jobs
                (id,tenant,connector_id,source_json,source_fingerprint,rule_fingerprint,
                 connector_fingerprint,connector_ciphertext,source_version,rule_version,
                 normalizer_version,expected_partitions,request_fingerprint,idempotency_key,
                 status,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'queued',?,?)""",
                (job_id, tenant, connector_id, source_json, source_hash, rule_hash,
                 connector_hash, encrypted_connector, *versions, partition_json,
                 request_hash, idempotency_key, now, now))
            return self._public(self._row(db, tenant, job_id))

    def get_job(self, tenant: str, job_id: str) -> dict:
        with self._connect() as db:
            return self._public(self._row(db, _required_id(tenant, "tenant"), _required_id(job_id, "job")))

    def list_jobs(self, tenant: str, *, limit: int = 50, before: float | None = None) -> list[dict]:
        tenant = _required_id(tenant, "tenant")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise AttackHistoryError(400, "Invalid limit")
        with self._connect() as db:
            if before is None:
                rows = db.execute("SELECT * FROM attack_jobs WHERE tenant=? ORDER BY created_at DESC,id DESC LIMIT ?",
                                  (tenant, limit)).fetchall()
            else:
                rows = db.execute("SELECT * FROM attack_jobs WHERE tenant=? AND created_at<? ORDER BY created_at DESC,id DESC LIMIT ?",
                                  (tenant, float(before), limit)).fetchall()
        return [self._public(row) for row in rows]

    def claim_job(self, tenant: str, job_id: str, owner: str, *, lease_seconds: int = 60,
                  now: float | None = None) -> int:
        tenant, job_id, owner = (_required_id(tenant, "tenant"), _required_id(job_id, "job"),
                                  _required_id(owner, "lease owner"))
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 1 <= lease_seconds <= 3600:
            raise AttackHistoryError(400, "Invalid lease duration")
        now = time.time() if now is None else float(now)
        with self._transaction() as db:
            row = self._row(db, tenant, job_id)
            if row["status"] != "queued" and not (row["status"] == "running" and row["lease_until"] <= now):
                raise AttackHistoryError(409, "Attack analysis job is not claimable")
            generation = row["lease_generation"] + 1
            db.execute("""UPDATE attack_jobs SET status='running',lease_owner=?,lease_until=?,
                         lease_generation=?,updated_at=? WHERE tenant=? AND id=?""",
                       (owner, now + lease_seconds, generation, now, tenant, job_id))
            return generation

    def _fenced(self, db: sqlite3.Connection, tenant: str, job_id: str,
                owner: str, generation: int, now: float) -> sqlite3.Row:
        row = self._row(db, tenant, job_id)
        if (row["status"] != "running" or row["lease_owner"] != owner
                or row["lease_generation"] != generation or row["lease_until"] <= now):
            raise AttackHistoryError(409, "Attack analysis lease is no longer valid")
        return row

    def renew_lease(self, tenant: str, job_id: str, owner: str, generation: int,
                    *, lease_seconds: int = 60, now: float | None = None) -> None:
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 1 <= lease_seconds <= 3600:
            raise AttackHistoryError(400, "Invalid lease duration")
        now = time.time() if now is None else float(now)
        with self._transaction() as db:
            self._fenced(db, tenant, job_id, owner, generation, now)
            db.execute("UPDATE attack_jobs SET lease_until=?,updated_at=? WHERE tenant=? AND id=?",
                       (now + lease_seconds, now, tenant, job_id))

    def worker_snapshot(self, tenant: str, job_id: str, owner: str, generation: int,
                        *, now: float | None = None) -> dict:
        """Return private replay inputs only to the current fenced worker."""
        now = time.time() if now is None else float(now)
        with self._connect() as db:
            row = self._fenced(db, tenant, job_id, owner, generation, now)
            connector = self.cipher.decrypt(row["connector_ciphertext"])
            encoded = json.dumps(connector, sort_keys=True, separators=(",", ":"))
            if hashlib.sha256(encoded.encode()).hexdigest() != row["connector_fingerprint"]:
                raise AttackHistoryError(409, "Connector snapshot fingerprint mismatch")
            return {
                "source": json.loads(row["source_json"]),
                "connector": connector,
                "source_fingerprint": row["source_fingerprint"],
                "rule_fingerprint": row["rule_fingerprint"],
                "connector_fingerprint": row["connector_fingerprint"],
                "source_version": row["source_version"],
                "rule_version": row["rule_version"],
                "normalizer_version": row["normalizer_version"],
                "expected_partitions": json.loads(row["expected_partitions"]),
            }

    def checkpoint_partition(self, tenant: str, job_id: str, owner: str, generation: int,
                             partition_id: str, sequence: int, checkpoint_ref: str,
                             checkpoint_digest: str, *, finalized: bool = False,
                             now: float | None = None) -> None:
        partition_id = _required_id(partition_id, "partition")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise AttackHistoryError(400, "Invalid checkpoint sequence")
        if not isinstance(checkpoint_ref, str) or not _POINTER.fullmatch(checkpoint_ref) or ".." in checkpoint_ref:
            raise AttackHistoryError(400, "Invalid checkpoint pointer")
        checkpoint_digest = _fingerprint(checkpoint_digest, "checkpoint")
        if not isinstance(finalized, bool):
            raise AttackHistoryError(400, "Invalid partition finality")
        now = time.time() if now is None else float(now)
        with self._transaction() as db:
            job = self._fenced(db, tenant, job_id, owner, generation, now)
            if partition_id not in json.loads(job["expected_partitions"]):
                raise AttackHistoryError(400, "Partition is not in the job plan")
            prior = db.execute("SELECT * FROM attack_partitions WHERE job_id=? AND partition_id=?",
                               (job_id, partition_id)).fetchone()
            if prior is not None:
                if prior["finalized"] and (sequence != prior["sequence"] or not finalized):
                    raise AttackHistoryError(409, "Finalized partition cannot be changed")
                if sequence < prior["sequence"] or (sequence == prior["sequence"] and
                        (checkpoint_ref != prior["checkpoint_ref"] or checkpoint_digest != prior["checkpoint_digest"])):
                    raise AttackHistoryError(409, "Checkpoint replay conflict")
                if sequence == prior["sequence"] and prior["finalized"] == int(finalized):
                    return
            db.execute("""INSERT INTO attack_partitions
                (job_id,partition_id,sequence,checkpoint_ref,checkpoint_digest,finalized,updated_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(job_id,partition_id) DO UPDATE SET
                sequence=excluded.sequence,checkpoint_ref=excluded.checkpoint_ref,
                checkpoint_digest=excluded.checkpoint_digest,finalized=excluded.finalized,
                updated_at=excluded.updated_at""",
                (job_id, partition_id, sequence, checkpoint_ref, checkpoint_digest, int(finalized), now))
            db.execute("UPDATE attack_jobs SET updated_at=? WHERE tenant=? AND id=?", (now, tenant, job_id))

    def list_partitions(self, tenant: str, job_id: str) -> list[dict]:
        with self._connect() as db:
            self._row(db, _required_id(tenant, "tenant"), _required_id(job_id, "job"))
            rows = db.execute("""SELECT partition_id,sequence,checkpoint_ref,checkpoint_digest,finalized,updated_at
                                 FROM attack_partitions WHERE job_id=? ORDER BY partition_id""", (job_id,)).fetchall()
        return [dict(row) for row in rows]

    def complete_job(self, tenant: str, job_id: str, owner: str, generation: int,
                     result_ref: str, result_digest: str, *, now: float | None = None) -> None:
        result_digest = _fingerprint(result_digest, "result")
        if result_ref != f"attack-results/{job_id}/{result_digest}":
            raise AttackHistoryError(400, "Invalid content-addressed result reference")
        now = time.time() if now is None else float(now)
        with self._transaction() as db:
            job = self._fenced(db, tenant, job_id, owner, generation, now)
            expected = set(json.loads(job["expected_partitions"]))
            finalized = {row["partition_id"] for row in db.execute(
                "SELECT partition_id FROM attack_partitions WHERE job_id=? AND finalized=1", (job_id,))}
            if not expected or finalized != expected:
                raise AttackHistoryError(409, "Attack analysis partition coverage is incomplete")
            try:
                result = self.artifacts.get_result(tenant, job_id, result_ref, result_digest)
            except ValueError:
                raise AttackHistoryError(409, "Attack analysis result artifact is unavailable or invalid")
            if result["summary"]["partial"] or result["summary"]["source_count"] < 1:
                raise AttackHistoryError(409, "Attack analysis result coverage is incomplete")
            db.execute("""UPDATE attack_jobs SET status='completed',lease_owner=NULL,lease_until=NULL,
                         result_ref=?,result_digest=?,updated_at=? WHERE tenant=? AND id=?""",
                       (result_ref, result_digest, now, tenant, job_id))

    def result_pointer(self, tenant: str, job_id: str) -> dict:
        """Private artifact locator; API must authorize before using it."""
        with self._connect() as db:
            row = self._row(db, _required_id(tenant, "tenant"), _required_id(job_id, "job"))
            if row["status"] != "completed":
                raise AttackHistoryError(409, "Attack analysis result is unavailable")
            return {"ref": row["result_ref"], "sha256": row["result_digest"]}

    def write_result(self, tenant: str, job_id: str, owner: str, generation: int,
                     value: Mapping[str, object], *, now: float | None = None) -> tuple[str, str]:
        """Write an immutable sanitized result for the current worker."""
        now = time.time() if now is None else float(now)
        with self._connect() as db:
            self._fenced(db, tenant, job_id, owner, generation, now)
        try:
            return self.artifacts.put_result(tenant, job_id, value)
        except ValueError:
            raise AttackHistoryError(400, "Invalid attack analysis result") from None

    def read_result(self, tenant: str, job_id: str) -> dict:
        """Read a completed result with tenant and digest verification."""
        pointer = self.result_pointer(tenant, job_id)
        try:
            return self.artifacts.get_result(tenant, job_id, pointer["ref"], pointer["sha256"])
        except ValueError:
            raise AttackHistoryError(409, "Attack analysis result artifact is unavailable or invalid") from None

    def fail_job(self, tenant: str, job_id: str, owner: str, generation: int,
                 error_code: str, *, now: float | None = None) -> None:
        if error_code not in {"source_unavailable", "access_denied", "checkpoint_failed", "processing_failed"}:
            raise AttackHistoryError(400, "Invalid failure code")
        now = time.time() if now is None else float(now)
        with self._transaction() as db:
            self._fenced(db, tenant, job_id, owner, generation, now)
            db.execute("""UPDATE attack_jobs SET status='failed',lease_owner=NULL,lease_until=NULL,
                         error_code=?,updated_at=? WHERE tenant=? AND id=?""",
                       (error_code, now, tenant, job_id))

    def cancel_job(self, tenant: str, job_id: str, *, now: float | None = None) -> dict:
        now = time.time() if now is None else float(now)
        with self._transaction() as db:
            row = self._row(db, _required_id(tenant, "tenant"), _required_id(job_id, "job"))
            if row["status"] in _TERMINAL:
                if row["status"] != "cancelled":
                    raise AttackHistoryError(409, "Attack analysis job already finished")
                return self._public(row)
            db.execute("""UPDATE attack_jobs SET status='cancelled',lease_owner=NULL,lease_until=NULL,
                         lease_generation=lease_generation+1,updated_at=? WHERE tenant=? AND id=?""",
                       (now, tenant, job_id))
            return self._public(self._row(db, tenant, job_id))
