"""Snapshot-date behavior for the reviewed SageMaker notebook platform policy."""

from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks.claude_aws_b_common import CONTEXT


CHECK = next(check for check in CHECKS if check.id == "aws.cb.sagemaker.notebook_supported_platform")
BASE = {"NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:111111111111:notebook-instance/n"}


def evaluate(platform, captured_at="2026-10-12T00:00:00+00:00", *, provenance=None):
    item = {**BASE, "PlatformIdentifier": platform}
    if provenance is not None:
        item["_provenance"] = provenance
    index = {"context": {**CONTEXT, "created_at": captured_at}}
    original = deepcopy((item, index))
    answer = CHECK.evaluate(item, index)
    assert (item, index) == original
    return answer


@pytest.mark.parametrize("platform,captured_at,expected", [
    ("notebook-al2023-v1", "2025-10-08T23:59:59+00:00", "UNKNOWN"),
    ("notebook-al2023-v1", "2025-10-09T00:00:00+00:00", "PASS"),
    ("notebook-al2023-v1", "2026-05-14T00:00:00+00:00", "PASS"),
    ("notebook-al2023-v1", "2026-05-15T00:00:00+00:00", "PASS"),
    ("notebook-al2023-v1", "2026-10-12T00:00:00+00:00", "PASS"),
    ("notebook-al2023-v1", "2027-04-10T00:00:00+00:00", "PASS"),
    ("notebook-al2023-v1", "2027-04-11T00:00:00+00:00", "UNKNOWN"),
    ("notebook-al2-v3", "2026-05-15T00:00:00+00:00", "PASS"),
    ("notebook-al2-v3", "2026-06-29T23:59:59+00:00", "PASS"),
    ("notebook-al2-v3", "2026-06-30T00:00:00+00:00", "FAIL"),
    ("notebook-al2-v3", "2026-10-12T00:00:00+00:00", "FAIL"),
    ("notebook-al2-v3", "2028-01-01T00:00:00+00:00", "FAIL"),
    ("notebook-al2-v1", "2025-06-29T00:00:00+00:00", "PASS"),
    ("notebook-al2-v1", "2025-06-30T00:00:00+00:00", "FAIL"),
    ("notebook-al2-v2", "2025-06-29T00:00:00+00:00", "PASS"),
    ("notebook-al2-v2", "2025-06-30T00:00:00+00:00", "FAIL"),
    ("notebook-al1-v1", "2024-03-30T00:00:00+00:00", "PASS"),
    ("notebook-al1-v1", "2024-03-31T00:00:00+00:00", "FAIL"),
    ("notebook-al2024-v1", "2026-10-12T00:00:00+00:00", "UNKNOWN"),
])
def test_documented_platform_lifecycle(platform, captured_at, expected):
    status, evidence = evaluate(platform, captured_at)
    assert status == expected
    if status in {"PASS", "FAIL"}:
        assert evidence["platform_identifier"] == platform
        assert evidence["assessed_at"] == captured_at[:10]


def test_item_provenance_precedes_index_clock():
    status, evidence = evaluate("notebook-al2-v3", provenance={"collected_at": "2026-06-29T23:00:00+00:00"})
    assert status == "PASS" and evidence["assessed_at"] == "2026-06-29"


def test_offset_capture_time_uses_utc_date():
    status, evidence = evaluate("notebook-al2-v3", "2026-06-30T01:00:00+02:00")
    assert status == "PASS" and evidence["assessed_at"] == "2026-06-29"


@pytest.mark.parametrize("item", [
    BASE,
    {**BASE, "PlatformIdentifier": None},
    {**BASE, "PlatformIdentifier": 123},
    {**BASE, "PlatformIdentifier": ""},
    {**BASE, "PlatformIdentifier": "notebook-al2023-v2"},
    {**BASE, "PlatformIdentifier": "notebook-al2023-v1", "_coverage": {"PlatformIdentifier": {"status": "denied"}}},
    {"collection_status": "denied"},
])
def test_unavailable_platform_evidence_is_unknown(item):
    assert CHECK.evaluate(item, {"context": dict(CONTEXT)})[0] == "UNKNOWN"


def test_missing_or_invalid_capture_time_is_unknown():
    item = {**BASE, "PlatformIdentifier": "notebook-al2-v3"}
    assert CHECK.evaluate(item, {})[0] == "UNKNOWN"
    assert CHECK.evaluate(item, {"context": {"created_at": "not-a-time"}})[0] == "UNKNOWN"
