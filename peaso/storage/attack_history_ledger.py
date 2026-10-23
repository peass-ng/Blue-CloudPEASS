"""Immutable local ledger blobs for CloudTrail historical partitions.

The database must fence references to these blobs before they are authoritative.
Writing a blob alone never completes a job or asserts source coverage.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import uuid
from collections.abc import Iterable, Mapping
from collections import OrderedDict

from peaso.attack_detection.history_s3 import CloudTrailObject, DayManifest
from .attack_history_artifacts import sanitized_result


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_KINDS = frozenset({"manifest", "object", "findings", "attestation"})
_MAX_BLOB = {"manifest": 64 * 1024 * 1024, "object": 1024 * 1024,
             "findings": 4 * 1024 * 1024, "attestation": 1024 * 1024}


@dataclass(frozen=True)
class LedgerRef:
    ref: str
    sha256: str


def _id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid attack ledger identity")
    return value


def _sha(value: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError("Invalid attack ledger hash")
    return value


def _canonical(value: Mapping) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def event_fingerprint(rows: Iterable[tuple[str, str]]) -> tuple[str, int]:
    """Hash exact event ID/payload-hash pairs without persisting raw events."""
    selected = []
    for event_id, digest in rows:
        if not isinstance(event_id, str) or not 0 < len(event_id) <= 256:
            raise ValueError("Invalid CloudTrail event ID")
        selected.append((event_id, _sha(digest)))
    if len(selected) > 20_000 or len({event_id for event_id, _ in selected}) != len(selected):
        raise ValueError("Invalid CloudTrail event set")
    selected.sort()
    return hashlib.sha256(_canonical({"events": selected})).hexdigest(), len(selected)


class LocalAttackHistoryLedger:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._manifest_cache = None
        self._manifest_lock = threading.Lock()
        self._finding_events = OrderedDict()
        self._finding_event_bytes = 0

    def _path(self, tenant: str, job_id: str, kind: str, reference: str, digest: str) -> Path:
        _id(tenant)
        _id(job_id)
        _sha(digest)
        if kind not in _KINDS or reference != f"attack-ledger/{job_id}/{kind}/{digest}":
            raise ValueError("Attack ledger reference mismatch")
        tenant_hash = hashlib.sha256(tenant.encode()).hexdigest()
        return self.root / tenant_hash / job_id / kind / f"{digest}.json"

    def put(self, tenant: str, job_id: str, kind: str, value: Mapping) -> LedgerRef:
        if not isinstance(value, Mapping) or kind not in _KINDS:
            raise ValueError("Invalid attack ledger payload")
        body = _canonical(value)
        if len(body) > _MAX_BLOB[kind]:
            raise ValueError("Attack ledger blob too large")
        digest = hashlib.sha256(body).hexdigest()
        reference = f"attack-ledger/{job_id}/{kind}/{digest}"
        path = self._path(tenant, job_id, kind, reference, digest)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            # Content addressing makes an identical retry idempotent. A
            # pre-existing corrupted blob is repaired before DB commit.
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return LedgerRef(reference, digest)

    def _verified_body(self, tenant: str, job_id: str, kind: str, reference: str, digest: str) -> bytes:
        path = self._path(tenant, job_id, kind, reference, digest)
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_BLOB[kind]:
                    raise ValueError("Attack ledger blob invalid")
                # Buffered read(size) can reserve the entire 64 MiB ceiling
                # even for a small manifest. One byte beyond the observed
                # size still detects growth without that allocation.
                body = stream.read(metadata.st_size + 1)
        except (FileNotFoundError, IsADirectoryError, OSError):
            raise ValueError("Attack ledger blob unavailable") from None
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError("Attack ledger digest mismatch")
        return body

    @staticmethod
    def _decoded_body(body: bytes) -> dict:
        try:
            decoded = json.loads(body)
        except (TypeError, ValueError, UnicodeDecodeError):
            raise ValueError("Attack ledger JSON invalid") from None
        if not isinstance(decoded, dict) or _canonical(decoded) != body:
            raise ValueError("Attack ledger JSON noncanonical")
        return decoded

    def get(self, tenant: str, job_id: str, kind: str, reference: str, digest: str) -> dict:
        return self._decoded_body(self._verified_body(tenant, job_id, kind, reference, digest))

    def put_manifest(self, tenant: str, job_id: str, manifest: DayManifest) -> LedgerRef:
        if not isinstance(manifest, DayManifest) or len(manifest.objects) > 100_000:
            raise ValueError("Invalid CloudTrail manifest")
        if len({item.key for item in manifest.objects}) != len(manifest.objects):
            raise ValueError("Duplicate CloudTrail manifest object")
        if (type(manifest.pages) is not int or not 1 <= manifest.pages <= 100
                or tuple(sorted(manifest.objects, key=lambda item: item.key)) != manifest.objects
                or any(not isinstance(item.key, str) or not item.key.startswith(manifest.prefix)
                       or not item.key.endswith(".json.gz") or not isinstance(item.etag, str)
                       or not item.etag or type(item.size) is not int or item.size < 1
                       for item in manifest.objects)):
            raise ValueError("Invalid CloudTrail manifest objects")
        value = {"schema_version": 1, "bucket": manifest.bucket, "prefix": manifest.prefix,
                 "account": manifest.account, "region": manifest.region, "day": manifest.day,
                 "listed_at": manifest.listed_at, "pages": manifest.pages,
                 "objects": [[item.key, item.etag, item.size] for item in manifest.objects]}
        return self.put(tenant, job_id, "manifest", value)

    def get_manifest(self, tenant: str, job_id: str, reference: str, digest: str) -> DayManifest:
        # Always verify the live file, including type/size/symlink checks. A
        # digest match permits reuse of its immutable parsed representation.
        body = self._verified_body(tenant, job_id, "manifest", reference, digest)
        key = tenant, job_id, reference, digest
        with self._manifest_lock:
            cached = self._manifest_cache
            if cached is not None and cached[0] == key:
                return cached[1]
        value = self._decoded_body(body)
        if set(value) != {"schema_version", "bucket", "prefix", "account", "region", "day",
                          "listed_at", "pages", "objects"} or value["schema_version"] != 1:
            raise ValueError("CloudTrail manifest shape invalid")
        try:
            datetime.fromisoformat(value["listed_at"].replace("Z", "+00:00"))
            objects = tuple(CloudTrailObject(*item) for item in value["objects"])
            manifest = DayManifest(value["bucket"], value["prefix"], value["account"],
                                   value["region"], value["day"], objects,
                                   value["pages"], value["listed_at"])
            if (len(objects) > 100_000 or type(manifest.pages) is not int
                    or not 1 <= manifest.pages <= 100
                    or tuple(sorted(objects, key=lambda item: item.key)) != objects
                    or any(not isinstance(item.key, str) or not item.key.startswith(manifest.prefix)
                           or not item.key.endswith(".json.gz") or not isinstance(item.etag, str)
                           or not item.etag or type(item.size) is not int or item.size < 1
                           for item in objects)):
                raise ValueError("CloudTrail manifest order invalid")
            # One entry and a conservative object-memory budget. Oversized
            # manifests still use the complete existing validation path.
            size = sys.getsizeof(manifest) + sys.getsizeof(objects)
            size += sum(sys.getsizeof(item) + sys.getsizeof(vars(item))
                        + sys.getsizeof(item.key) + sys.getsizeof(item.etag)
                        + sys.getsizeof(item.size) for item in objects)
            size += sum(sys.getsizeof(getattr(manifest, field)) for field in
                        ('bucket', 'prefix', 'account', 'region', 'day', 'pages', 'listed_at'))
            with self._manifest_lock:
                immutable = all(type(getattr(manifest, field)) is str for field in
                                ('bucket', 'prefix', 'account', 'region', 'day', 'listed_at'))
                self._manifest_cache = (key, manifest) if immutable and size <= 4 * 1024 * 1024 else None
            return manifest
        except (TypeError, ValueError, AttributeError):
            raise ValueError("CloudTrail manifest invalid") from None

    def put_finding_chunks(self, tenant: str, job_id: str,
                           findings: Iterable[Mapping | object]) -> tuple[dict, ...]:
        """Stream sanitized findings into bounded, content-addressed chunks."""
        descriptors: list[dict] = []
        current: list[dict] = []
        current_bytes = 0

        def flush() -> None:
            nonlocal current, current_bytes
            if not current:
                return
            document = {"schema_version": 1, "job_id": job_id,
                        "summary": {"source_count": 1, "event_count": 0,
                                    "detection_count": len(current), "partial": False},
                        "detections": current}
            pointer = self.put(tenant, job_id, "findings", document)
            descriptors.append({"ref": pointer.ref, "sha256": pointer.sha256,
                                "count": len(current)})
            current, current_bytes = [], 0

        for item in findings:
            value = asdict(item) if is_dataclass(item) else dict(item)
            clean = sanitized_result(job_id, {"schema_version": 1,
                "summary": {"source_count": 1, "event_count": 0,
                            "detection_count": 1, "partial": False},
                "detections": [value]})["detections"][0]
            size = len(_canonical(clean))
            if size > 2_000_000:
                raise ValueError("Individual finding too large")
            if current and (len(current) >= 1000 or current_bytes + size > 3_000_000):
                flush()
            current.append(clean)
            current_bytes += size
        flush()
        return tuple(descriptors)

    def get_finding_chunk(self, tenant: str, job_id: str, descriptor: Mapping) -> list[dict]:
        if set(descriptor) != {"ref", "sha256", "count"} or type(descriptor["count"]) is not int:
            raise ValueError("Invalid finding chunk descriptor")
        value = self.get(tenant, job_id, "findings", descriptor["ref"], descriptor["sha256"])
        if value.get("job_id") != job_id or value.get("schema_version") != 1:
            raise ValueError("Finding chunk identity mismatch")
        selected = sanitized_result(job_id, {key: value[key] for key in
                                              ("schema_version", "summary", "detections")})
        if selected != value or len(value["detections"]) != descriptor["count"]:
            raise ValueError("Finding chunk count mismatch")
        identifiers = tuple(item['event_id'] for item in value['detections'])
        key = tenant, job_id, descriptor['ref'], descriptor['sha256'], descriptor['count']
        weight = (sys.getsizeof(identifiers) + sum(sys.getsizeof(item) for item in identifiers)
                  + sys.getsizeof(key) + sum(sys.getsizeof(item) for item in key) + 512)
        if weight <= 1024 * 1024:
            with self._manifest_lock:
                previous = self._finding_events.pop(key, None)
                if previous is not None:
                    self._finding_event_bytes -= previous[1]
                self._finding_events[key] = identifiers, weight
                self._finding_event_bytes += weight
                while self._finding_event_bytes > 1024 * 1024:
                    _, (_, removed) = self._finding_events.popitem(last=False)
                    self._finding_event_bytes -= removed
        return value["detections"]

    def get_finding_event_ids(self, tenant: str, job_id: str, descriptor: Mapping) -> tuple[str, ...]:
        """Reuse validation prepared before commit, after rechecking live bytes.

        Only immutable event identities are retained, never finding dictionaries.
        On a cold/missing receipt the complete normal validator remains in use.
        """
        if set(descriptor) != {'ref', 'sha256', 'count'} or type(descriptor['count']) is not int:
            raise ValueError('Invalid finding chunk descriptor')
        self._verified_body(tenant, job_id, 'findings', descriptor['ref'], descriptor['sha256'])
        key = tenant, job_id, descriptor['ref'], descriptor['sha256'], descriptor['count']
        with self._manifest_lock:
            cached = self._finding_events.get(key)
            if cached is not None:
                self._finding_events.move_to_end(key)
                return cached[0]
        return tuple(item['event_id'] for item in self.get_finding_chunk(tenant, job_id, descriptor))

    def put_object_checkpoint(self, tenant: str, job_id: str, partition_id: str,
                              obj: CloudTrailObject, object_sha256: str,
                              event_hashes: Iterable[tuple[str, str]],
                              finding_chunks: Iterable[Mapping]) -> LedgerRef:
        _id(partition_id)
        if not isinstance(obj, CloudTrailObject) or not isinstance(obj.key, str) or not isinstance(obj.etag, str):
            raise ValueError("Invalid CloudTrail object")
        events_digest, event_count = event_fingerprint(event_hashes)
        chunks = tuple(dict(item) for item in finding_chunks)
        if len(chunks) > 100 or any(set(item) != {"ref", "sha256", "count"} or
                                  type(item["count"]) is not int or item["count"] < 1
                                  for item in chunks):
            raise ValueError("Invalid finding chunks")
        for item in chunks:
            self.get_finding_chunk(tenant, job_id, item)
        document = {"schema_version": 1, "job_id": job_id, "partition_id": partition_id,
                    "object": {"key": obj.key, "etag": obj.etag, "size": obj.size,
                               "sha256": _sha(object_sha256)},
                    "events_digest": events_digest, "event_count": event_count,
                    "finding_count": sum(item["count"] for item in chunks),
                    "finding_chunks": chunks}
        return self.put(tenant, job_id, "object", document)

    def get_object_checkpoint(self, tenant: str, job_id: str, partition_id: str,
                              reference: str, digest: str) -> dict:
        value = self.get(tenant, job_id, "object", reference, digest)
        if (set(value) != {"schema_version", "job_id", "partition_id", "object", "events_digest",
                            "event_count", "finding_count", "finding_chunks"}
                or value["schema_version"] != 1 or value["job_id"] != job_id
                or value["partition_id"] != partition_id or set(value["object"]) !=
                {"key", "etag", "size", "sha256"}):
            raise ValueError("CloudTrail object checkpoint invalid")
        _sha(value["object"]["sha256"])
        _sha(value["events_digest"])
        if type(value["event_count"]) is not int or type(value["finding_count"]) is not int:
            raise ValueError("CloudTrail object checkpoint count invalid")
        if sum(len(self.get_finding_event_ids(tenant, job_id, item))
               for item in value["finding_chunks"]) != value["finding_count"]:
            raise ValueError("CloudTrail object finding count mismatch")
        return value

    def put_attestation(self, tenant: str, job_id: str, partition_id: str,
                        generation: int, first: LedgerRef, second: LedgerRef,
                        processed_digest: str, chunk_index_digest: str,
                        as_of: str, grace_seconds: int) -> LedgerRef:
        _id(partition_id)
        if type(generation) is not int or generation < 1:
            raise ValueError("Invalid lease generation")
        if type(grace_seconds) is not int or not 3600 <= grace_seconds <= 7 * 86400:
            raise ValueError("Invalid CloudTrail grace")
        self.get_manifest(tenant, job_id, first.ref, first.sha256)
        self.get_manifest(tenant, job_id, second.ref, second.sha256)
        value = {"schema_version": 1, "job_id": job_id, "partition_id": partition_id,
                 "lease_generation": generation, "first": asdict(first),
                 "second": asdict(second), "processed_digest": _sha(processed_digest),
                 "chunk_index_digest": _sha(chunk_index_digest), "state": "complete_as_of",
                 "as_of": as_of, "grace_seconds": grace_seconds}
        return self.put(tenant, job_id, "attestation", value)
