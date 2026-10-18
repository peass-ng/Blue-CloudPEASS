"""One fenced CloudTrail S3 account/Region/day historical partition.

The worker never treats a stable S3 prefix as proof that CloudTrail delivered
all account events. A successful result is explicitly complete *as of* the
second exhausted listing after the configured grace interval.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time

from peaso.attack_detection.github_source import fetch_rules
from peaso.attack_detection.history_s3 import HistorySourceGap, inventory_day, read_cloudtrail_object
from peaso.attack_detection.rules import (
    DEFAULT_RULE_PACK_SHA256, DEFAULT_RULE_REF, DEFAULT_RULE_REPO,
    Rule, detect_aws_events, load_rules,
)
from peaso.storage.attack_history_sqlite import AttackHistoryError, SQLiteAttackHistoryStore

HISTORY_SOURCE_VERSION = "cloudtrail-s3-v1"
AWS_NORMALIZER_VERSION = "aws-v1"


def load_exact_pinned_aws_rules() -> tuple[Rule, ...]:
    texts = fetch_rules(DEFAULT_RULE_REPO, DEFAULT_RULE_REF, DEFAULT_RULE_PACK_SHA256)
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        for name, source in texts.items():
            (root / name).write_text(source, encoding="utf-8")
        return load_rules(root, product="aws")


def _record_hash(record: dict) -> str:
    try:
        body = json.dumps(record, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode()
    except (TypeError, ValueError):
        raise HistorySourceGap("invalid_cloudtrail_record") from None
    return hashlib.sha256(body).hexdigest()


def _process(store: SQLiteAttackHistoryStore, tenant: str, job_id: str, owner: str,
             generation: int, s3_client, rules: tuple[Rule, ...], *,
             grace_seconds: int = 86400, clock=time.time) -> dict:
    """Internal testable executor; caller has resolved the immutable rule pack."""
    snapshot = store.worker_snapshot(tenant, job_id, owner, generation, now=clock())
    source = snapshot["source"]
    if (source.get("kind") != "aws_cloudtrail_s3"
            or snapshot["rule_version"] != DEFAULT_RULE_REF
            or snapshot["rule_fingerprint"] != DEFAULT_RULE_PACK_SHA256
            or snapshot["source_version"] != HISTORY_SOURCE_VERSION
            or snapshot["normalizer_version"] != AWS_NORMALIZER_VERSION):
        raise AttackHistoryError(409, "CloudTrail source or pinned rule snapshot mismatch")
    if not rules or any(item.product != "aws" for item in rules):
        raise AttackHistoryError(409, "Pinned AWS rule pack is unavailable")
    try:
        first = inventory_day(s3_client, source["bucket"], source["prefix"],
                              source["account_id"], source["region"], source["day"])
    except KeyError:
        raise AttackHistoryError(400, "CloudTrail source scope is incomplete") from None
    partition_id = snapshot["expected_partitions"][0]
    if len(snapshot["expected_partitions"]) != 1:
        raise AttackHistoryError(409, "CloudTrail worker requires one partition")
    store.renew_lease(tenant, job_id, owner, generation,
                      lease_seconds=3600, now=clock())
    store.register_cloudtrail_first_manifest(tenant, job_id, owner, generation,
                                               partition_id, first, now=clock())
    for obj in first.objects:
        store.renew_lease(tenant, job_id, owner, generation,
                          lease_seconds=3600, now=clock())
        read = read_cloudtrail_object(s3_client, first, obj)
        existing = store.cloudtrail_committed_object(tenant, job_id, owner,
            generation, partition_id, obj.key, now=clock())
        if existing is not None:
            if existing != {"etag": obj.etag, "size": obj.size, "sha256": read.sha256}:
                raise HistorySourceGap("checkpoint_object_changed")
            continue
        event_hashes = [(row["eventID"], _record_hash(row)) for row in read.records]
        new_ids = store.cloudtrail_new_event_ids(tenant, job_id, owner,
            generation, event_hashes, now=clock())
        selected = [row for row in read.records if row["eventID"] in new_ids]
        findings = detect_aws_events(selected, rules)
        try:
            chunks = store.ledger.put_finding_chunks(tenant, job_id, findings)
            checkpoint = store.ledger.put_object_checkpoint(tenant, job_id,
                partition_id, obj, read.sha256, event_hashes, chunks)
        except ValueError:
            raise AttackHistoryError(409, "CloudTrail object findings exceed safe artifact limits") from None
        store.commit_cloudtrail_object(tenant, job_id, owner, generation,
            partition_id, obj, read.sha256, event_hashes, checkpoint, now=clock())
    second = inventory_day(s3_client, source["bucket"], source["prefix"],
                           source["account_id"], source["region"], source["day"])
    state = store.finalize_cloudtrail_partition(tenant, job_id, owner, generation,
        partition_id, second, grace_seconds=grace_seconds, now=clock())
    if state != "complete_as_of":
        return {"state": state, "complete_as_of": None}
    ref, digest = store.build_cloudtrail_result(tenant, job_id, owner,
                                                 generation, partition_id, now=clock())
    store.complete_job(tenant, job_id, owner, generation, ref, digest, now=clock())
    return {"state": "complete_as_of", "complete_as_of": second.listed_at,
            "job_id": job_id}


def process_aws_cloudtrail_day(store: SQLiteAttackHistoryStore, tenant: str,
                               job_id: str, owner: str, generation: int,
                               s3_client, *, grace_seconds: int = 86400) -> dict:
    """Run with the exact public rule commit/hash, ignoring environment overrides."""
    return _process(store, tenant, job_id, owner, generation, s3_client,
                    load_exact_pinned_aws_rules(), grace_seconds=grace_seconds)
