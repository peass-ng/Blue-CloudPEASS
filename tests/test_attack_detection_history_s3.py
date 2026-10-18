"""Mock-only contracts for bounded CloudTrail S3 historical partitions."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
from copy import deepcopy

import pytest

from peaso.attack_detection.history_s3 import (
    CloudTrailObject, HistorySourceGap, assess_reconciliation, day_prefix,
    inventory_day, read_cloudtrail_object,
)
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "123456789012"
REGION = "us-east-1"
DAY = "2026-10-18"
BASE = f"AWSLogs/{ACCOUNT}/CloudTrail/"
PREFIX = f"{BASE}{REGION}/2026/10/18/"


def entry(name="one", *, etag='"etag-one"', size=100):
    return {"Key": PREFIX + name + ".json.gz", "ETag": etag, "Size": size}


def record(event_id="synthetic", *, account=ACCOUNT, region=REGION):
    return {"eventID": event_id, "recipientAccountId": account, "awsRegion": region}


def compressed(*records):
    return gzip.compress(json.dumps({"Records": records}).encode())


class ListingClient:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def list_objects_v2(self, **kwargs):
        self.calls.append(kwargs)
        page = self.pages[len(self.calls) - 1]
        if isinstance(page, Exception):
            raise page
        return deepcopy(page)


class ObjectClient:
    def __init__(self, raw, *, etag=None, length=None, error=None):
        self.raw, self.etag, self.length, self.error = raw, etag, length, error
        self.calls = []
        self.body = None

    def get_object(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        self.body = io.BytesIO(self.raw)
        return {"ETag": self.etag or kwargs["IfMatch"],
                "ContentLength": len(self.raw) if self.length is None else self.length,
                "Body": self.body}


def manifest(*entries):
    page = {"IsTruncated": False, "Prefix": PREFIX, "Contents": list(entries)}
    return inventory_day(ListingClient([page]), "logs-bucket", BASE, ACCOUNT, REGION, DAY)


def object_manifest(raw, name="one", etag='"etag-one"'):
    day = manifest(entry(name, etag=etag, size=len(raw)))
    return day, day.objects[0]


@pytest.mark.parametrize("base,account,region,day,code", [
    ("AWSLogs/999999999999/CloudTrail/", ACCOUNT, REGION, DAY, "invalid_cloudtrail_scope"),
    (BASE + "extra/", ACCOUNT, REGION, DAY, "invalid_cloudtrail_scope"),
    (BASE, ACCOUNT, "bad/region", DAY, "invalid_cloudtrail_scope"),
    (BASE, ACCOUNT, REGION, "2026-02-30", "invalid_cloudtrail_day"),
    (BASE, ACCOUNT, REGION, "2026-10-18/extra", "invalid_cloudtrail_day"),
])
def test_exact_account_region_day_binding(base, account, region, day, code):
    with pytest.raises(HistorySourceGap, match=code):
        day_prefix(base, account, region, day)


def test_organization_trail_and_gov_region_prefix():
    base = f"central/AWSLogs/o-example/{ACCOUNT}/CloudTrail/"
    assert day_prefix(base, ACCOUNT, "us-gov-west-1", DAY) == base + "us-gov-west-1/2026/10/18/"


def test_exhaustive_listing_including_empty_page_and_sorted_unique_manifest():
    pages = [
        {"IsTruncated": True, "NextContinuationToken": "p2", "Prefix": PREFIX,
         "Contents": [entry("two"), entry("one")]},
        {"IsTruncated": False, "Prefix": PREFIX,
         "Contents": [entry("one"), {"Key": PREFIX + "digest.json", "Size": 12}]},
    ]
    client = ListingClient(pages)
    result = inventory_day(client, "logs-bucket", BASE, ACCOUNT, REGION, DAY)
    assert result.pages == 2 and [item.key for item in result.objects] == [entry("one")["Key"], entry("two")["Key"]]
    assert client.calls[0] == {"Bucket": "logs-bucket", "Prefix": PREFIX, "MaxKeys": 1000}
    assert client.calls[1]["ContinuationToken"] == "p2"
    assert result.contains(result.objects[0])
    assert not result.contains(CloudTrailObject(result.objects[0].key, '"other"', 100))


def test_inventory_exhausts_more_than_preview_object_limit_across_pages():
    pages = []
    for start, stop in ((0, 1000), (1000, 2000), (2000, 2500)):
        page = {"IsTruncated": stop < 2500,
                "Contents": [entry(f"log-{index:04d}") for index in range(start, stop)]}
        if stop < 2500:
            page["NextContinuationToken"] = f"after-{stop}"
        pages.append(page)
    client = ListingClient(pages)
    result = inventory_day(client, "logs-bucket", BASE, ACCOUNT, REGION, DAY)
    assert result.pages == 3 and len(result.objects) == 2500
    assert result.objects[0].key.endswith("log-0000.json.gz")
    assert result.objects[-1].key.endswith("log-2499.json.gz")
    assert [call.get("ContinuationToken") for call in client.calls] == [None, "after-1000", "after-2000"]


@pytest.mark.parametrize("pages,code", [
    ([{"IsTruncated": True}], "invalid_continuation_token"),
    ([{"IsTruncated": True, "NextContinuationToken": "p2"},
      {"IsTruncated": True, "NextContinuationToken": "p2"}], "invalid_continuation_token"),
    ([{"IsTruncated": False, "NextContinuationToken": "p2"}], "unexpected_final_token"),
    ([{"IsTruncated": False, "Prefix": "foreign"}], "listing_prefix_mismatch"),
    ([{"IsTruncated": False, "Contents": [{"Key": "foreign.json.gz", "ETag": "x", "Size": 1}]}], "foreign_object_key"),
    ([{"IsTruncated": False, "Contents": [entry(size=0)]}], "invalid_object_identity"),
    ([{"IsTruncated": False, "Contents": [entry(size=True)]}], "invalid_object_identity"),
    ([{"IsTruncated": "false"}], "invalid_listing_page"),
    ([RuntimeError("provider secret")], "cloudtrail_list_failed"),
])
def test_listing_gaps_are_stable_and_never_expose_provider_text(pages, code):
    with pytest.raises(HistorySourceGap) as exc:
        inventory_day(ListingClient(pages), "logs-bucket", BASE, ACCOUNT, REGION, DAY)
    assert str(exc.value) == code


def test_list_limits_and_changed_duplicate_are_gaps():
    pages = [{"IsTruncated": True, "NextContinuationToken": "p2", "Contents": [entry()]},
             {"IsTruncated": False, "Contents": [entry("two")]}]
    with pytest.raises(HistorySourceGap, match="page_budget_exceeded"):
        inventory_day(ListingClient(pages), "logs-bucket", BASE, ACCOUNT, REGION, DAY, max_pages=1)
    with pytest.raises(HistorySourceGap, match="object_budget_exceeded"):
        inventory_day(ListingClient(pages), "logs-bucket", BASE, ACCOUNT, REGION, DAY, max_objects=1)
    pages[1]["Contents"] = [entry(etag='"changed"')]
    with pytest.raises(HistorySourceGap, match="object_changed_during_listing"):
        inventory_day(ListingClient(pages), "logs-bucket", BASE, ACCOUNT, REGION, DAY)


def test_conditional_read_hashes_exact_bytes_and_closes_body():
    raw = compressed(record("one"), record("two"))
    day, obj = object_manifest(raw)
    client = ObjectClient(raw)
    result = read_cloudtrail_object(client, day, obj)
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert [item["eventID"] for item in result.records] == ["one", "two"]
    assert client.calls == [{"Bucket": day.bucket, "Key": obj.key, "IfMatch": obj.etag}]
    assert client.body.closed
    assert "recipientAccountId" not in repr(result)


@pytest.mark.parametrize("change,code", [
    ({"etag": '"other"'}, "object_identity_changed"),
    ({"length": 999}, "object_identity_changed"),
    ({"error": RuntimeError("provider secret")}, "conditional_object_read_failed"),
])
def test_changed_object_or_get_failure_is_named_gap(change, code):
    raw = compressed(record())
    day, obj = object_manifest(raw)
    with pytest.raises(HistorySourceGap) as exc:
        read_cloudtrail_object(ObjectClient(raw, **change), day, obj)
    assert str(exc.value) == code


@pytest.mark.parametrize("records,code", [
    ([record(account="999999999999")], "foreign_cloudtrail_record"),
    ([record(region="us-west-2")], "foreign_cloudtrail_record"),
    ([{"recipientAccountId": ACCOUNT, "awsRegion": REGION}], "invalid_cloudtrail_event_id"),
    (["malformed"], "invalid_cloudtrail_record"),
    ([record("duplicate"), record("duplicate")], "duplicate_event_id_in_object"),
])
def test_scope_and_event_identity_are_fail_closed(records, code):
    raw = compressed(*records)
    day, obj = object_manifest(raw)
    with pytest.raises(HistorySourceGap, match=code):
        read_cloudtrail_object(ObjectClient(raw), day, obj)


def test_object_limits_malformed_gzip_and_manifest_membership():
    raw = compressed(record())
    day, obj = object_manifest(raw)
    with pytest.raises(HistorySourceGap, match="compressed_object_too_large"):
        read_cloudtrail_object(ObjectClient(raw), day, obj, max_compressed=len(raw) - 1)
    with pytest.raises(HistorySourceGap, match="expanded_object_too_large"):
        read_cloudtrail_object(ObjectClient(raw), day, obj, max_expanded=10)
    with pytest.raises(HistorySourceGap, match="invalid_cloudtrail_object"):
        broken = b"not-gzip"
        broken_day, broken_obj = object_manifest(broken)
        read_cloudtrail_object(ObjectClient(broken), broken_day, broken_obj)
    with pytest.raises(HistorySourceGap, match="object_outside_manifest"):
        read_cloudtrail_object(ObjectClient(raw), day, CloudTrailObject(obj.key, '"changed"', obj.size))


def test_late_changed_removed_and_committed_checkpoint_assessment():
    original = manifest(entry("one"))
    stable = manifest(entry("one"))
    committed = {original.objects[0].key: original.objects[0]}
    assert assess_reconciliation(original, stable, committed, grace_elapsed=False).state == "provisional"
    complete = assess_reconciliation(original, stable, committed, grace_elapsed=True)
    assert complete.state == "complete_as_of" and complete.as_of == stable.listed_at
    late = manifest(entry("one"), entry("late"))
    state = assess_reconciliation(original, late, committed, grace_elapsed=True)
    assert state.state == "provisional" and state.added == (entry("late")["Key"],)
    assert state.pending == (entry("late")["Key"],)
    changed = manifest(entry("one", etag='"new"'))
    state = assess_reconciliation(original, changed, committed, grace_elapsed=True)
    assert state.state == "provisional" and state.changed == (entry("one")["Key"],)
    removed = manifest()
    state = assess_reconciliation(original, removed, committed, grace_elapsed=True)
    assert state.state == "partial" and state.removed == (entry("one")["Key"],)
    assert assess_reconciliation(original, stable, {}, grace_elapsed=True).state == "provisional"


def test_incompatible_manifest_cannot_be_reconciled():
    original = manifest()
    other = inventory_day(ListingClient([{"IsTruncated": False}]), "other-bucket", BASE, ACCOUNT, REGION, DAY)
    with pytest.raises(HistorySourceGap, match="incompatible_manifests"):
        assess_reconciliation(original, other, {}, grace_elapsed=True)


def test_selected_history_object_reaches_reviewed_cloudtrail_rule() -> None:
    row = {
        **record("fee0d559-62a8-43b4-8824-2250a7a2203f"),
        "eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventTime": "2026-10-18T12:00:00Z",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer"},
        "requestParameters": {"name": "reviewed-trail"}, "responseElements": None,
    }
    raw = compressed(row)
    day, obj = object_manifest(raw)
    chosen = read_cloudtrail_object(ObjectClient(raw), day, obj)
    rule = Rule(
        id="reviewed-stop", title="StopLogging observed", level="medium",
        description="A successful StopLogging call was observed.",
        technique_id="aws-cloudtrail-stop-logging", product="aws",
        selection={"event.source": "cloudtrail.amazonaws.com",
                   "event.name": "StopLogging", "event.outcome": "success",
                   "request.stop_logging_observed": True},
    )
    hits = detect_aws_events(chosen.records, [rule])
    assert [(hit.rule_id, hit.event_id, hit.account_id) for hit in hits] == [
        ("reviewed-stop", row["eventID"], ACCOUNT)
    ]
