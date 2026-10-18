"""Local, content-addressed JSON results for historical attack analysis.

Only a bounded detection projection is accepted. Cloud log records, connector
authentication, and arbitrary response fields cannot be written here.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from collections.abc import Mapping


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_EVIDENCE_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,79}\Z")
_SECRET_KEY = re.compile(r"(?i)(?:secret|password|credential|token|private.?key|authorization|raw|log.?entry|record|payload)")
_SECRET_VALUE = re.compile(r"(?i)(?:-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._~+/-]{12,}|AKIA[0-9A-Z]{16})")
_FINDING_FIELDS = frozenset({
    "rule_id", "title", "severity", "technique_id", "event_id", "event_time",
    "account_id", "actor_id", "target_id", "evidence", "description", "legitimate_context",
})
_SUMMARY_FIELDS = frozenset({"source_count", "event_count", "detection_count", "partial"})
_MAX_BYTES = 4 * 1024 * 1024


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid attack result identity")
    return value


def _text(value: object, *, maximum: int = 2048) -> str:
    if not isinstance(value, str) or len(value) > maximum or _SECRET_VALUE.search(value):
        raise ValueError("Unsafe attack result text")
    return value


def _evidence(value: object) -> dict:
    if not isinstance(value, Mapping) or len(value) > 32:
        raise ValueError("Invalid attack result evidence")
    selected = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _EVIDENCE_KEY.fullmatch(key):
            raise ValueError("Unsafe attack result evidence field")
        if _SECRET_KEY.search(key) and not isinstance(item, bool):
            raise ValueError("Unsafe attack result evidence field")
        if key == "correlation" and isinstance(item, Mapping):
            selected[key] = _evidence(item)
        elif isinstance(item, str):
            selected[key] = _text(item, maximum=512)
        elif isinstance(item, bool) or isinstance(item, int) and abs(item) <= 2**53:
            selected[key] = item
        else:
            # No nested CloudTrail/LogEntry payloads or arbitrary arrays.
            raise ValueError("Unsafe attack result evidence value")
    return selected


def sanitized_result(job_id: str, value: Mapping[str, object]) -> dict:
    """Project a small, useful report without accepting raw log objects."""
    _identifier(job_id)
    if isinstance(value, Mapping) and value.get("schema_version") == 2:
        if set(value) != {"schema_version", "summary", "chunks", "attestation"}:
            raise ValueError("Invalid chunked attack result shape")
        summary, chunks, attestation = value["summary"], value["chunks"], value["attestation"]
        if (not isinstance(summary, Mapping) or set(summary) != _SUMMARY_FIELDS | {"complete_as_of"}
                or any(type(summary[key]) is not int or not 0 <= summary[key] <= 10**12
                       for key in ("source_count", "event_count", "detection_count"))
                or summary["partial"] is not False or summary["source_count"] < 1
                or not isinstance(summary["complete_as_of"], str)
                or len(summary["complete_as_of"]) > 64):
            raise ValueError("Invalid chunked attack result summary")
        if not isinstance(chunks, list) or len(chunks) > 10000:
            raise ValueError("Invalid attack result chunks")
        clean_chunks = []
        for item in chunks:
            if (not isinstance(item, Mapping) or set(item) != {"ref", "sha256", "count"}
                    or type(item["count"]) is not int or not 1 <= item["count"] <= 1000
                    or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                    or item["ref"] != f"attack-ledger/{job_id}/findings/{item['sha256']}"):
                raise ValueError("Invalid attack result chunk reference")
            clean_chunks.append(dict(item))
        if sum(item["count"] for item in clean_chunks) != summary["detection_count"]:
            raise ValueError("Attack result chunk count mismatch")
        if (not isinstance(attestation, Mapping) or set(attestation) != {"ref", "sha256"}
                or not isinstance(attestation["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", attestation["sha256"])
                or attestation["ref"] != f"attack-ledger/{job_id}/attestation/{attestation['sha256']}"):
            raise ValueError("Invalid attack result attestation reference")
        return {"schema_version": 2, "job_id": job_id, "summary": dict(summary),
                "chunks": clean_chunks, "attestation": dict(attestation)}
    if not isinstance(value, Mapping) or set(value) != {"schema_version", "summary", "detections"}:
        raise ValueError("Invalid attack result shape")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Invalid attack result version")
    summary = value["summary"]
    detections = value["detections"]
    if not isinstance(summary, Mapping) or set(summary) != _SUMMARY_FIELDS:
        raise ValueError("Invalid attack result summary")
    if (any(type(summary[key]) is not int or not 0 <= summary[key] <= 10**12
            for key in ("source_count", "event_count", "detection_count"))
            or type(summary["partial"]) is not bool):
        raise ValueError("Invalid attack result counts")
    if not isinstance(detections, list) or len(detections) > 10000 or summary["detection_count"] != len(detections):
        raise ValueError("Invalid attack result detections")
    clean = []
    for item in detections:
        if not isinstance(item, Mapping) or set(item) != _FINDING_FIELDS:
            raise ValueError("Invalid attack result detection")
        row = {}
        for key in _FINDING_FIELDS - {"evidence", "legitimate_context"}:
            field = item[key]
            if field is not None:
                row[key] = _text(field, maximum=4096 if key == "description" else 512)
            else:
                row[key] = None
        row["evidence"] = _evidence(item["evidence"])
        context = item["legitimate_context"]
        if not isinstance(context, (list, tuple)) or len(context) > 10:
            raise ValueError("Invalid attack result context")
        row["legitimate_context"] = [_text(entry, maximum=500) for entry in context]
        clean.append(row)
    return {"schema_version": 1, "job_id": job_id, "summary": dict(summary), "detections": clean}


class LocalAttackHistoryArtifacts:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    @staticmethod
    def reference(job_id: str, digest: str) -> str:
        _identifier(job_id)
        if not isinstance(digest, str) or not _HASH.fullmatch(digest):
            raise ValueError("Invalid attack result digest")
        return f"attack-results/{job_id}/{digest}"

    def _path(self, tenant: str, job_id: str, reference: str, digest: str) -> Path:
        _identifier(tenant)
        if reference != self.reference(job_id, digest):
            raise ValueError("Attack result identity mismatch")
        tenant_hash = hashlib.sha256(tenant.encode()).hexdigest()
        return self.root / tenant_hash / job_id / f"{digest}.json"

    def put_result(self, tenant: str, job_id: str, value: Mapping[str, object]) -> tuple[str, str]:
        projection = sanitized_result(job_id, value)
        body = json.dumps(projection, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode()
        if len(body) > _MAX_BYTES:
            raise ValueError("Attack result is too large")
        digest = hashlib.sha256(body).hexdigest()
        reference = self.reference(job_id, digest)
        path = self._path(tenant, job_id, reference, digest)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return reference, digest

    def get_result(self, tenant: str, job_id: str, reference: str, digest: str) -> dict:
        path = self._path(tenant, job_id, reference, digest)
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                size = os.fstat(stream.fileno())
                if not stat.S_ISREG(size.st_mode) or size.st_size > _MAX_BYTES:
                    raise ValueError("Attack result artifact is invalid")
                body = stream.read(_MAX_BYTES + 1)
        except (FileNotFoundError, IsADirectoryError, OSError):
            raise ValueError("Attack result artifact is unavailable") from None
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError("Attack result digest mismatch")
        try:
            decoded = json.loads(body)
            if not isinstance(decoded, dict) or set(decoded) not in (
                    {"schema_version", "job_id", "summary", "detections"},
                    {"schema_version", "job_id", "summary", "chunks", "attestation"}):
                raise ValueError("Attack result shape mismatch")
            if decoded.get("job_id") != job_id:
                raise ValueError("Attack result identity mismatch")
            if sanitized_result(job_id, {key: value for key, value in decoded.items() if key != "job_id"}) != decoded:
                raise ValueError("Attack result projection mismatch")
        except (KeyError, TypeError, ValueError, UnicodeDecodeError):
            raise ValueError("Attack result artifact is invalid") from None
        return decoded

    def verify_result(self, tenant: str, job_id: str, reference: str, digest: str) -> bool:
        try:
            self.get_result(tenant, job_id, reference, digest)
        except ValueError:
            return False
        return True
