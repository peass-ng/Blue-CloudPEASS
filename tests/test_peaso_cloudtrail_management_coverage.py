"""CloudTrail management-source coverage through registered product checks."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import aws_gap_core  # register the actual product checks
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGION = "aws.gap.cloudtrail.region_logging_management_events"
MULTI = "aws.gap.cloudtrail.multi_region_read_write_management"
SCOPE = "123456789012/us-east-1"


def basic(mode="All", excludes=None):
    return {"ReadWriteType": mode, "IncludeManagementEvents": True,
            "ExcludeManagementEventSources": [] if excludes is None else excludes}


def advanced(read_only=None, excludes=None):
    fields = [{"Field": "eventCategory", "Equals": ["Management"]}]
    if read_only is not None:
        fields.append({"Field": "readOnly", "Equals": read_only})
    if excludes is not None:
        fields.append({"Field": "eventSource", "NotEquals": excludes})
    return {"FieldSelectors": fields}


def trail(name, *, basic_rows=None, advanced_rows=None, logging=True, multi=True):
    item = {
        "Name": name,
        "TrailARN": f"arn:aws:cloudtrail:us-east-1:123456789012:trail/{name}",
        "HomeRegion": "us-east-1",
        "IsMultiRegionTrail": multi,
        "IsOrganizationTrail": False,
        "IncludeGlobalServiceEvents": True,
        "LogFileValidationEnabled": True,
        "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/k1",
        "Status": {"collection_status": "collected", "IsLogging": logging},
    }
    item["EventSelectors"] = {"collection_status": "collected",
                              **({"AdvancedEventSelectors": advanced_rows} if advanced_rows is not None else
                                 {"EventSelectors": basic_rows if basic_rows is not None else [basic()]})}
    return item


def observed(check_id, trails, status=None):
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "cloudtrail", "scope": SCOPE, "service": "cloudtrail",
        "status": status or ("collected" if trails else "empty"), "items": trails}],
        metadata={"region_discovery": [{"account_id": "123456789012", "status": "collected", "regions": ["us-east-1"]}]})
    before = copy.deepcopy(snapshot)
    report = evaluate_snapshot(snapshot, checks=[check_id])
    assert snapshot == before
    rows = [row for row in report["findings"] if row["check_id"] == check_id]
    assert len(rows) == 1
    return rows[0]["status"]


SELECTOR_CASES = [
    ("basic_full", {"basic_rows": [basic()]}, "PASS"),
    ("basic_kms_only_excluded", {"basic_rows": [basic(excludes=["kms.amazonaws.com"])]}, "FAIL"),
    ("basic_rds_only_excluded", {"basic_rows": [basic(excludes=["rdsdata.amazonaws.com"])]}, "FAIL"),
    ("basic_excluded_plus_unrestricted", {"basic_rows": [basic(excludes=["kms.amazonaws.com"]), basic()]}, "PASS"),
    ("basic_read_unrestricted_write_restricted", {"basic_rows": [basic("ReadOnly"), basic("WriteOnly", ["kms.amazonaws.com"])]}, "FAIL"),
    ("basic_read_restricted_write_unrestricted", {"basic_rows": [basic("ReadOnly", ["kms.amazonaws.com"]), basic("WriteOnly")]}, "FAIL"),
    ("basic_split_complementary", {"basic_rows": [basic("ReadOnly"), basic("WriteOnly")]}, "PASS"),
    ("advanced_full", {"advanced_rows": [advanced()]}, "PASS"),
    ("advanced_kms_only_excluded", {"advanced_rows": [advanced(excludes=["kms.amazonaws.com"])]}, "FAIL"),
    ("advanced_excluded_plus_unrestricted", {"advanced_rows": [advanced(excludes=["rdsdata.amazonaws.com"]), advanced()]}, "PASS"),
    ("advanced_read_unrestricted_write_restricted", {"advanced_rows": [advanced(["true"]), advanced(["false"], ["rdsdata.amazonaws.com"])]}, "FAIL"),
    ("advanced_split_complementary", {"advanced_rows": [advanced(["true"]), advanced(["false"])]}, "PASS"),
    ("advanced_unsupported_source_filter", {"advanced_rows": [{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Management"]},
        {"Field": "eventSource", "Equals": ["iam.amazonaws.com"]}]}]}, "UNKNOWN"),
    ("advanced_unrestricted_plus_unknown", {"advanced_rows": [advanced(), {"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Management"]},
        {"Field": "eventSource", "Equals": ["iam.amazonaws.com"]}]}]}, "PASS"),
    ("advanced_restricted_plus_unknown", {"advanced_rows": [advanced(excludes=["kms.amazonaws.com"]), {"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Management"]},
        {"Field": "eventSource", "Equals": ["iam.amazonaws.com"]}]}]}, "UNKNOWN"),
    ("advanced_malformed_read_filter", {"advanced_rows": [{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Management"]},
        {"Field": "readOnly", "Equals": ["maybe"]}]}]}, "UNKNOWN"),
    ("basic_omitted_defaults", {"basic_rows": [{}]}, "PASS"),
    ("basic_explicit_null_mode", {"basic_rows": [{"IncludeManagementEvents": True, "ReadWriteType": None}]}, "UNKNOWN"),
    ("data_only", {"advanced_rows": [{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}]}]}, "FAIL"),
]


@pytest.mark.parametrize("check_id", [REGION, MULTI], ids=["region", "multi_region"])
@pytest.mark.parametrize("label,selector,wanted", SELECTOR_CASES, ids=[row[0] for row in SELECTOR_CASES])
def test_source_domain_coverage(check_id, label, selector, wanted):
    assert observed(check_id, [trail("audit", **selector)]) == wanted, label


@pytest.mark.parametrize("check_id", [REGION, MULTI], ids=["region", "multi_region"])
def test_valid_covering_trail_dominates_unreadable_sibling(check_id):
    unreadable = trail("unreadable")
    unreadable["Status"] = {"collection_status": "denied"}
    assert observed(check_id, [unreadable, trail("good")]) == "PASS"


@pytest.mark.parametrize("check_id", [REGION, MULTI], ids=["region", "multi_region"])
def test_selector_body_omitted_status_uses_existing_convention(check_id):
    item = trail("omitted-status")
    del item["EventSelectors"]["collection_status"]
    assert observed(check_id, [item]) == "PASS"


@pytest.mark.parametrize("check_id", [REGION, MULTI], ids=["region", "multi_region"])
def test_denied_selector_detail_unknown(check_id):
    item = trail("denied-selectors")
    item["EventSelectors"] = {"collection_status": "denied"}
    assert observed(check_id, [item]) == "UNKNOWN"


@pytest.mark.parametrize("check_id", [REGION, MULTI], ids=["region", "multi_region"])
@pytest.mark.parametrize("condition,wanted", [("empty", "FAIL"), ("partial", "UNKNOWN"), ("denied_status", "UNKNOWN")])
def test_inventory_and_status_truth(check_id, condition, wanted):
    if condition == "empty":
        actual = observed(check_id, [])
    elif condition == "partial":
        actual = observed(check_id, [trail("incomplete")], status="partial")
    else:
        item = trail("unknown")
        item["Status"] = {"collection_status": "denied"}
        actual = observed(check_id, [item])
    assert actual == wanted
