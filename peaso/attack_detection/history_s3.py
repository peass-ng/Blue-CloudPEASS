"""Bounded CloudTrail S3 day inventory and object reading for historical jobs.

An exhausted inventory proves traversal of one selected prefix *as of* that
listing. It does not prove CloudTrail delivery, trail configuration, immutable
objects, or the absence of files arriving later. Callers own durable leases,
checkpoints, and finding storage; this module performs no cloud mutations.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from .gzip_input import ExpansionLimitError, read_gzip


MAX_LIST_PAGES = 100
MAX_LIST_OBJECTS = 100_000
MAX_COMPRESSED_BYTES = 10_000_000
MAX_EXPANDED_BYTES = 50_000_000
MAX_RECORDS = 20_000
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+(?:-[a-z]+)?-[0-9]\Z")
_BASE = re.compile(r"(?:[^/]+/)*AWSLogs/(?:o-[a-z0-9]+/)?(?P<account>[0-9]{12})/CloudTrail/\Z")


class HistorySourceGap(ValueError):
    """Stable code only; never retain SDK messages, object data, or credentials."""


@dataclass(frozen=True)
class CloudTrailObject:
    key: str
    etag: str
    size: int


@dataclass(frozen=True)
class DayManifest:
    bucket: str
    prefix: str
    account: str
    region: str
    day: str
    objects: tuple[CloudTrailObject, ...]
    pages: int
    listed_at: str

    def contains(self, target: CloudTrailObject) -> bool:
        """Find a selected object in the key-sorted manifest in O(log n)."""
        low, high = 0, len(self.objects)
        while low < high:
            mid = (low + high) // 2
            if self.objects[mid].key < target.key:
                low = mid + 1
            else:
                high = mid
        return low < len(self.objects) and self.objects[low] == target


@dataclass(frozen=True)
class CloudTrailObjectData:
    sha256: str
    records: tuple[Mapping[str, Any], ...] = field(repr=False)


@dataclass(frozen=True)
class InventoryAssessment:
    state: str  # provisional, partial, complete_as_of
    added: tuple[str, ...]
    changed: tuple[str, ...]
    removed: tuple[str, ...]
    pending: tuple[str, ...]
    as_of: str | None


def day_prefix(base_prefix: str, account: str, region: str, day: str) -> str:
    """Bind a selected account, Region, and calendar day to a CloudTrail key prefix."""
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(base_prefix, str)):
        raise HistorySourceGap("invalid_cloudtrail_scope")
    base = _BASE.fullmatch(base_prefix)
    if base is None or base.group("account") != account:
        raise HistorySourceGap("invalid_cloudtrail_scope")
    if not isinstance(day, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", day):
        raise HistorySourceGap("invalid_cloudtrail_day")
    try:
        selected = date.fromisoformat(day)
    except ValueError:
        raise HistorySourceGap("invalid_cloudtrail_day") from None
    return f"{base_prefix}{region}/{selected:%Y/%m/%d}/"


def inventory_day(
    client: Any, bucket: str, base_prefix: str, account: str, region: str, day: str,
    *, max_pages: int = MAX_LIST_PAGES, max_objects: int = MAX_LIST_OBJECTS,
) -> DayManifest:
    """Return only an exhausted, bounded ListObjectsV2 inventory.

    A raised gap means no complete manifest was produced. `Contents` may be
    absent on an empty response; continuation tokens are opaque and transient.
    """
    prefix = day_prefix(base_prefix, account, region, day)
    if (not isinstance(bucket, str) or not 3 <= len(bucket) <= 63
            or not isinstance(max_pages, int) or isinstance(max_pages, bool)
            or not 1 <= max_pages <= MAX_LIST_PAGES
            or not isinstance(max_objects, int) or isinstance(max_objects, bool)
            or not 1 <= max_objects <= MAX_LIST_OBJECTS):
        raise HistorySourceGap("invalid_inventory_limit")
    objects: dict[str, CloudTrailObject] = {}
    seen_tokens: set[str] = set()
    token: str | None = None
    for page_number in range(1, max_pages + 1):
        params: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": 1000}
        if token is not None:
            params["ContinuationToken"] = token
        try:
            page = client.list_objects_v2(**params)
        except Exception:
            raise HistorySourceGap("cloudtrail_list_failed") from None
        if not isinstance(page, Mapping) or type(page.get("IsTruncated")) is not bool:
            raise HistorySourceGap("invalid_listing_page")
        if "Prefix" in page and page["Prefix"] != prefix:
            raise HistorySourceGap("listing_prefix_mismatch")
        contents = page.get("Contents", [])
        if not isinstance(contents, list) or len(contents) > 1000:
            raise HistorySourceGap("invalid_listing_contents")
        for item in contents:
            if not isinstance(item, Mapping) or not isinstance(item.get("Key"), str):
                raise HistorySourceGap("invalid_object_summary")
            key = item["Key"]
            if not key.startswith(prefix):
                raise HistorySourceGap("foreign_object_key")
            if not key.endswith(".json.gz"):
                continue
            size, etag = item.get("Size"), item.get("ETag")
            if type(size) is not int or size < 1 or not isinstance(etag, str) or not etag:
                raise HistorySourceGap("invalid_object_identity")
            obj = CloudTrailObject(key, etag, size)
            prior = objects.get(key)
            if prior is not None and prior != obj:
                raise HistorySourceGap("object_changed_during_listing")
            objects[key] = obj
            if len(objects) > max_objects:
                raise HistorySourceGap("object_budget_exceeded")
        next_token = page.get("NextContinuationToken")
        if not page["IsTruncated"]:
            if next_token not in (None, ""):
                raise HistorySourceGap("unexpected_final_token")
            return DayManifest(bucket, prefix, account, region, day,
                               tuple(objects[key] for key in sorted(objects)),
                               page_number, datetime.now(timezone.utc).isoformat())
        if (not isinstance(next_token, str) or not 0 < len(next_token) <= 8192
                or next_token in seen_tokens):
            raise HistorySourceGap("invalid_continuation_token")
        seen_tokens.add(next_token)
        token = next_token
    raise HistorySourceGap("page_budget_exceeded")


def read_cloudtrail_object(
    client: Any, manifest: DayManifest, obj: CloudTrailObject,
    *, max_compressed: int = MAX_COMPRESSED_BYTES, max_expanded: int = MAX_EXPANDED_BYTES,
    max_records: int = MAX_RECORDS,
) -> CloudTrailObjectData:
    """Conditionally read one selected object and fail closed on foreign rows.

    ETag is an HTTP precondition, not a content digest. `sha256` hashes the
    bytes actually read; callers must persist it with their checkpoint.
    """
    if not manifest.contains(obj) or not obj.key.startswith(manifest.prefix):
        raise HistorySourceGap("object_outside_manifest")
    if (type(max_compressed) is not int or not 1 <= max_compressed <= MAX_COMPRESSED_BYTES
            or type(max_expanded) is not int or not 1 <= max_expanded <= MAX_EXPANDED_BYTES
            or type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS):
        raise HistorySourceGap("invalid_object_limit")
    if obj.size > max_compressed:
        raise HistorySourceGap("compressed_object_too_large")
    try:
        response = client.get_object(Bucket=manifest.bucket, Key=obj.key, IfMatch=obj.etag)
    except Exception:
        raise HistorySourceGap("conditional_object_read_failed") from None
    body = response.get("Body") if isinstance(response, Mapping) else None
    try:
        if (not isinstance(response, Mapping) or response.get("ETag") != obj.etag
                or type(response.get("ContentLength")) is not int
                or response["ContentLength"] != obj.size or body is None):
            raise HistorySourceGap("object_identity_changed")
        try:
            compressed = body.read(obj.size + 1)
        except Exception:
            raise HistorySourceGap("object_body_read_failed") from None
        if not isinstance(compressed, bytes) or len(compressed) != obj.size:
            raise HistorySourceGap("object_size_changed")
        digest = hashlib.sha256(compressed).hexdigest()
        try:
            expanded = read_gzip(compressed, max_expanded)
            document = json.loads(expanded)
        except ExpansionLimitError:
            raise HistorySourceGap("expanded_object_too_large") from None
        except HistorySourceGap:
            raise
        except (OSError, ValueError, TypeError, EOFError):
            raise HistorySourceGap("invalid_cloudtrail_object") from None
        records = document.get("Records") if isinstance(document, Mapping) else None
        if not isinstance(records, list) or len(records) > max_records:
            raise HistorySourceGap("invalid_cloudtrail_records")
        ids: set[str] = set()
        for record in records:
            if not isinstance(record, Mapping):
                raise HistorySourceGap("invalid_cloudtrail_record")
            if record.get("recipientAccountId") != manifest.account or record.get("awsRegion") != manifest.region:
                raise HistorySourceGap("foreign_cloudtrail_record")
            event_id = record.get("eventID")
            if not isinstance(event_id, str) or not 0 < len(event_id) <= 256:
                raise HistorySourceGap("invalid_cloudtrail_event_id")
            if event_id in ids:
                raise HistorySourceGap("duplicate_event_id_in_object")
            ids.add(event_id)
        return CloudTrailObjectData(digest, tuple(records))
    finally:
        if body is not None:
            try:
                body.close()
            except Exception:
                pass


def assess_reconciliation(
    first: DayManifest, second: DayManifest,
    processed: Mapping[str, CloudTrailObject], *, grace_elapsed: bool,
) -> InventoryAssessment:
    """Compare two exhausted inventories and committed object identities.

    `processed` must come from durable, fenced checkpoints. A stable manifest
    is only complete as of the second listing, with no trail-delivery claim.
    """
    if (not isinstance(first, DayManifest) or not isinstance(second, DayManifest)
            or not isinstance(processed, Mapping) or type(grace_elapsed) is not bool
            or (first.bucket, first.prefix, first.account, first.region, first.day)
            != (second.bucket, second.prefix, second.account, second.region, second.day)):
        raise HistorySourceGap("incompatible_manifests")
    before = {obj.key: obj for obj in first.objects}
    after = {obj.key: obj for obj in second.objects}
    added = tuple(sorted(after.keys() - before.keys()))
    removed = tuple(sorted(before.keys() - after.keys()))
    changed = tuple(sorted(key for key in before.keys() & after.keys() if before[key] != after[key]))
    pending = tuple(sorted(key for key, obj in after.items() if processed.get(key) != obj))
    state = ("partial" if removed else "complete_as_of"
             if grace_elapsed and not (added or changed or pending) else "provisional")
    return InventoryAssessment(state, added, changed, removed, pending,
                               second.listed_at if state == "complete_as_of" else None)
