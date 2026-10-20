"""Synthetic S3 end-to-end contracts for one fenced historical day."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
from datetime import datetime, timedelta, timezone
from itertools import count
from pathlib import Path
from uuid import UUID

from peaso.attack_detection.history_worker_s3 import _process
from peaso.attack_detection.history_s3 import HistorySourceGap
from peaso.attack_detection.rules import (
    DEFAULT_RULE_PACK_SHA256, DEFAULT_RULE_REF, Rule,
)
from peaso.auth.secrets import CredentialCipher
from peaso.storage.attack_history_sqlite import SQLiteAttackHistoryStore
from peaso.storage.attack_history_sqlite import AttackHistoryError
import pytest


ACCOUNT = "123456789012"
REGION = "us-east-1"
DAY = "2026-10-15"
BASE = f"AWSLogs/{ACCOUNT}/CloudTrail/"
PREFIX = f"{BASE}{REGION}/2026/10/15/"
CLOCK = 1792454500.0  # after selected day plus grace
RULE = Rule("reviewed-stop", "StopLogging observed", "medium",
            "A successful StopLogging call was observed.",
            "aws-cloudtrail-stop-logging", "aws",
            {"event.source": "cloudtrail.amazonaws.com",
             "event.name": "StopLogging", "event.outcome": "success",
             "request.stop_logging_observed": True})


@pytest.fixture(autouse=True)
def listing_clock_matches_worker_clock(monkeypatch):
    # The worker uses CLOCK below. Its two native listing receipts must use
    # that same timeline, with the second strictly later than the first.
    ticks = count()

    class ListingDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = datetime.fromtimestamp(CLOCK - 1, timezone.utc) + timedelta(microseconds=next(ticks))
            return value.astimezone(tz) if tz else value.replace(tzinfo=None)

    monkeypatch.setattr("peaso.attack_detection.history_s3.datetime", ListingDateTime)


def event(event_id: str) -> dict:
    return {"eventID": event_id, "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging",
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "eventTime": "2026-10-15T12:00:00Z",
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer"},
            "requestParameters": {"name": "reviewed-trail"}, "responseElements": None}


def compressed(*records: dict) -> bytes:
    return gzip.compress(json.dumps({"Records": records}).encode(), mtime=0)


class FakeS3:
    def __init__(self, first: dict[str, bytes], second: dict[str, bytes] | None = None):
        self.first = first
        self.second = first if second is None else second
        self.list_calls = 0
        self.get_calls = 0

    def list_objects_v2(self, **kwargs):
        self.list_calls += 1
        chosen = self.first if self.list_calls == 1 else self.second
        if isinstance(chosen, Exception):
            raise chosen
        return {"IsTruncated": False, "Prefix": kwargs["Prefix"],
                "Contents": [{"Key": key, "ETag": f'"{hashlib.md5(value).hexdigest()}"',
                              "Size": len(value)} for key, value in chosen.items()]}

    def get_object(self, **kwargs):
        self.get_calls += 1
        raw = self.first[kwargs["Key"]]
        return {"ETag": kwargs["IfMatch"], "ContentLength": len(raw),
                "Body": io.BytesIO(raw)}


def prepared(tmp_path: Path):
    store = SQLiteAttackHistoryStore(tmp_path, CredentialCipher(tmp_path / "identity"))
    connector = {"data": {"provider": "aws"}, "auth": {"method": "role", "role_arn": "example"}}
    digest = hashlib.sha256(json.dumps(connector, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    source = {"kind": "aws_cloudtrail_s3", "bucket": "logs-bucket", "prefix": BASE,
              "account_id": ACCOUNT, "region": REGION, "day": DAY}
    job = store.create_job("tenant-a", "connector-1", source, DEFAULT_RULE_PACK_SHA256,
                           digest, connector, source_version="cloudtrail-s3-v1",
                           rule_version=DEFAULT_RULE_REF,
                           normalizer_version="aws-v1")["id"]
    generation = store.claim_job("tenant-a", job, "worker-a", lease_seconds=3600, now=CLOCK - 1)
    return store, job, generation


def test_worker_closes_one_stable_partition_with_pinned_snapshot(tmp_path: Path) -> None:
    store, job, generation = prepared(tmp_path)
    key = PREFIX + "one.json.gz"
    row = event("fee0d559-62a8-43b4-8824-2250a7a2203f")
    s3 = FakeS3({key: compressed(row)})
    receipt = _process(store, "tenant-a", job, "worker-a", generation, s3,
                       (RULE,), grace_seconds=3600, clock=lambda: CLOCK)
    assert receipt["state"] == "complete_as_of"
    assert s3.list_calls == 2 and s3.get_calls == 1
    assert store.get_job("tenant-a", job)["status"] == "completed"
    result = store.read_result("tenant-a", job)
    assert (result["summary"]["event_count"], result["summary"]["detection_count"]) == (1, 1)
    assert store.ledger.get_finding_chunk("tenant-a", job, result["chunks"][0])[0]["event_id"] == row["eventID"]


def test_worker_late_object_remains_provisional(tmp_path: Path) -> None:
    store, job, generation = prepared(tmp_path)
    one = PREFIX + "one.json.gz"
    late = PREFIX + "late.json.gz"
    first = {one: compressed(event("fee0d559-62a8-43b4-8824-2250a7a2203f"))}
    second = dict(first, **{late: compressed(event("92592a11-d065-4b17-a15b-0b1144e453d9"))})
    receipt = _process(store, "tenant-a", job, "worker-a", generation,
                       FakeS3(first, second), (RULE,), grace_seconds=3600,
                       clock=lambda: CLOCK)
    assert receipt == {"state": "provisional", "complete_as_of": None}
    assert store.get_job("tenant-a", job)["status"] == "running"


def test_worker_rejects_rule_snapshot_drift_before_s3_access(tmp_path: Path) -> None:
    store = SQLiteAttackHistoryStore(tmp_path, CredentialCipher(tmp_path / "identity"))
    connector = {"data": {"provider": "aws"}, "auth": {"method": "role"}}
    digest = hashlib.sha256(json.dumps(connector, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    source = {"kind": "aws_cloudtrail_s3", "bucket": "logs-bucket", "prefix": BASE,
              "account_id": ACCOUNT, "region": REGION, "day": DAY}
    job = store.create_job("tenant-a", "connector-1", source, DEFAULT_RULE_PACK_SHA256,
                           digest, connector, source_version="cloudtrail-s3-v1",
                           rule_version="stale-rules", normalizer_version="aws-v1")["id"]
    generation = store.claim_job("tenant-a", job, "worker-a", now=CLOCK - 1)
    client = FakeS3({})
    with pytest.raises(AttackHistoryError, match="pinned rule snapshot mismatch"):
        _process(store, "tenant-a", job, "worker-a", generation,
                 client, (RULE,), clock=lambda: CLOCK)
    assert client.list_calls == 0


def test_worker_crash_after_object_commit_replays_without_duplicate_findings(tmp_path: Path) -> None:
    store, job, generation1 = prepared(tmp_path)
    key = PREFIX + "one.json.gz"
    data = {key: compressed(event("fee0d559-62a8-43b4-8824-2250a7a2203f"))}
    with pytest.raises(HistorySourceGap, match="cloudtrail_list_failed"):
        _process(store, "tenant-a", job, "worker-a", generation1,
                 FakeS3(data, RuntimeError("provider detail")), (RULE,),
                 grace_seconds=3600, clock=lambda: CLOCK)
    assert store.get_job("tenant-a", job)["status"] == "running"
    reopened = SQLiteAttackHistoryStore(tmp_path, CredentialCipher(tmp_path / "identity"))
    generation2 = reopened.claim_job("tenant-a", job, "worker-b", lease_seconds=3600,
                                     now=CLOCK + 3601)
    client = FakeS3(data)
    receipt = _process(reopened, "tenant-a", job, "worker-b", generation2,
                       client, (RULE,), grace_seconds=3600,
                       clock=lambda: CLOCK + 3602)
    assert receipt["state"] == "complete_as_of"
    assert reopened.read_result("tenant-a", job)["summary"]["detection_count"] == 1
    assert client.get_calls == 1


def test_worker_deduplicates_same_event_across_objects(tmp_path: Path) -> None:
    store, job, generation = prepared(tmp_path)
    row = event("fee0d559-62a8-43b4-8824-2250a7a2203f")
    data = {PREFIX + "one.json.gz": compressed(row),
            PREFIX + "two.json.gz": compressed(row)}
    receipt = _process(store, "tenant-a", job, "worker-a", generation,
                       FakeS3(data), (RULE,), grace_seconds=3600,
                       clock=lambda: CLOCK)
    assert receipt["state"] == "complete_as_of"
    result = store.read_result("tenant-a", job)
    assert result["summary"]["event_count"] == 1
    assert result["summary"]["detection_count"] == 1


def test_worker_deduplicates_across_multiple_sqlite_lookup_batches(tmp_path: Path) -> None:
    store, job, generation = prepared(tmp_path)
    first = [event(str(UUID(int=index + 1))) for index in range(1000)]
    second = [event(str(UUID(int=index + 1))) for index in range(500, 1500)]
    data = {PREFIX + "one.json.gz": compressed(*first),
            PREFIX + "two.json.gz": compressed(*second)}
    receipt = _process(store, "tenant-a", job, "worker-a", generation,
                       FakeS3(data), (RULE,), grace_seconds=3600,
                       clock=lambda: CLOCK)
    assert receipt["state"] == "complete_as_of"
    result = store.read_result("tenant-a", job)
    assert result["summary"]["event_count"] == 1500
    assert result["summary"]["detection_count"] == 1500
