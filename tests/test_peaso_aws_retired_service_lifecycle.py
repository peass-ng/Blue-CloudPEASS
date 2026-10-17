"""Exact AWS service retirement without losing historical snapshot evidence."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from peaso.aws_service_lifecycle import RETIRED_SERVICES, SUPPORT_ENDED_SERVICES, retired_collection_error, retirement_state
from peaso.checks import CHECKS
from peaso.collectors import aws
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


CID = "aws.cb.mediastore.container_policy_not_public"
SCOPE = "123456789012/us-east-1"
PRIVATE = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "mediastore:GetObject", "Resource": "*"}]}
PUBLIC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "mediastore:GetObject", "Resource": "*"}]}


def check():
    return next(row for row in CHECKS if row.id == CID)


def item(policy):
    return {"ARN": "arn:aws:mediastore:us-east-1:123456789012:container/example", "Policy": {"Policy": json.dumps(policy)}}


def context(stamp):
    return {"context": {"created_at": stamp, "scope": SCOPE, "Account": "123456789012", "provider": "aws"}}


@pytest.mark.parametrize("stamp,state", [
    ("2025-11-11T23:59:59+00:00", "historical"),
    ("2025-11-12T00:00:00+00:00", "transition"),
    ("2025-11-13T23:59:59+00:00", "transition"),
    ("2025-11-14T00:00:00+00:00", "retired"),
])
def test_exact_lifecycle_dates(stamp, state):
    assert retirement_state("media_store_container", datetime.fromisoformat(stamp)) == state
    assert retirement_state("wafv2_web_acl", datetime.fromisoformat(stamp)) == "unknown"


def test_historical_media_store_predicate_and_current_applicability():
    old = context("2025-11-11T00:00:00+00:00")
    assert check().evaluate(item(PRIVATE), old)[0] == "PASS"
    assert check().evaluate(item(PUBLIC), old)[0] == "FAIL"
    assert check().evaluate(item(PUBLIC), context("2025-11-14T00:00:00+00:00"))[0] == "NOT_APPLICABLE"
    assert check().evaluate(item(PUBLIC), context("2025-11-12T00:00:00+00:00"))[0] == "UNKNOWN"
    assert check().evaluate(item(PUBLIC), context("not-a-date"))[0] == "UNKNOWN"
    assert check().evaluate(item(PUBLIC), context("2026-10-12T00:00:00"))[0] == "UNKNOWN"
    assert check().evaluate(item(PUBLIC), {})[0] == "UNKNOWN"


def test_media_store_collector_does_not_call_retired_sdk(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    session = boto3.Session(aws_access_key_id="fixture", aws_secret_access_key="fixture", region_name="us-east-1")
    sts = session.client("sts", region_name="us-east-1")
    stub = Stubber(sts)
    stub.add_response("get_caller_identity", {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test", "UserId": "AIDATEST"}, {})
    stub.activate()
    calls = []

    def client(self, _session, service, region):
        calls.append(service)
        assert service != "mediastore"
        return sts

    original_init = aws.Requests.__init__

    def init(self, options):
        original_init(self, options)
        self.observed_at = datetime(2026, 10, 12, tzinfo=timezone.utc)

    monkeypatch.setattr(aws.Requests, "__init__", init)
    monkeypatch.setattr(aws.Requests, "client", client)
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "fixture"))
    try:
        snapshot = aws.collect({"provider": "aws", "scopes": [SCOPE], "options": {"service_concurrency": 1}}, ["media_store_container"])
    finally:
        stub.assert_no_pending_responses()
        stub.deactivate()
    media = next(row for row in snapshot["collections"] if row["type"] == "media_store_container")
    assert media["status"] == "empty" and media["error"]["code"] == "retired_service"
    assert snapshot["created_at"] == "2026-10-12T00:00:00+00:00"
    assert calls == ["sts"]
    assert snapshot["metadata"]["calls"] == 1
    assert snapshot["metadata"]["max_calls"] is None


def test_retired_inventory_reports_explicit_not_applicable_and_exact_guard():
    retired = {"type": "media_store_container", "scope": SCOPE, "service": "mediastore", "status": "empty", "items": [],
        "error": {"code": "retired_service"}}
    snapshot = make_snapshot("aws", [SCOPE], [retired], created_at="2026-10-12T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, checks=[CID], include_not_applicable=True)
    collection = next(row for row in report["coverage"] if row["level"] == "collection" and row["type"] == "media_store_container")
    control = next(row for row in report["coverage"] if row["level"] == "check" and row["check_id"] == CID)
    finding = next(row for row in report["findings"] if row["check_id"] == CID)
    assert collection["status"] == "empty" and "full shutdown" in collection["reason"]
    assert control["by_status"] == {"NOT_APPLICABLE": 1} and "full shutdown" in control["reason"]
    assert finding["status"] == "NOT_APPLICABLE"
    assert finding["evidence"]["source"] == RETIRED_SERVICES["mediastore"]["primary_url"]

    for stamp in ("bad-date", "2025-11-11T00:00:00+00:00"):
        conflicting = make_snapshot("aws", [SCOPE], [retired], created_at=stamp)
        outcome = evaluate_snapshot(conflicting, checks=[CID], include_not_applicable=True)
        assert next(row for row in outcome["findings"] if row["check_id"] == CID)["status"] == "UNKNOWN"

    fake = {**retired, "type": "vpc", "service": "ec2"}
    vpc = make_snapshot("aws", [SCOPE], [fake], created_at="2026-10-12T00:00:00+00:00")
    coverage = next(row for row in evaluate_snapshot(vpc, checks=[CID])["coverage"] if row["level"] == "collection" and row["type"] == "vpc")
    assert coverage["status"] == "empty" and coverage["reason"] == "" and "error_code" not in coverage


def test_exact_collected_service_ids_and_support_ended_classic_not_disabled():
    assert aws.SPECS["media_store_container"][0] == "mediastore"
    for service, metadata in SUPPORT_ENDED_SERVICES.items():
        assert metadata["live_api_retirement_proven"] is False
        assert all(aws.SPECS[kind][0] == service for kind in metadata["applies_to_service_kinds"])
    assert aws.SPECS["wafv2_web_acl"][0] == "wafv2"
    now = datetime(2026, 10, 12, tzinfo=timezone.utc)
    assert retired_collection_error("media_store_container", now)["code"] == "retired_service"
    for active_kind in ("waf_web_acl", "wafregional_web_acl", "wafv2_web_acl", "inspector2_coverage"):
        assert retired_collection_error(active_kind, now) is None
    assert all(service not in {"inspector", "kinesisanalytics"} for service, _, _ in aws.SPECS.values())
    assert any(service == "inspector2" for service, _, _ in aws.SPECS.values())
