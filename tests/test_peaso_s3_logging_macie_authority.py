"""Selected S3 logging/Macie facts through inert registered snapshots."""
from copy import deepcopy
import pytest
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot
from peaso.checks.claude_aws_a_s3 import B, TRAIL, MACIE_JOB, ACCOUNT
from peaso.checks.claude_aws_a_security import ACCT_CFG

SCOPE = ACCOUNT + "/global"
LOG = "aws.claude_a.s3.object_level_logging"
MACIE = "aws.claude_a.s3.protected_by_macie"

def deny(row, key):
    row.setdefault("_coverage", {})[key] = {"status": "denied"}

def verdict(cid, kind, rows):
    snap = make_snapshot("aws", [SCOPE], [
        {"type": "bucket", "scope": SCOPE, "global": True, "account_id": ACCOUNT, "status": "collected", "items": [deepcopy(B)]},
        {"type": kind, "scope": SCOPE, "global": True, "account_id": ACCOUNT,
         "status": "collected" if rows else "empty", "items": deepcopy(rows)},
        {"type": "aws_account_configuration", "scope": SCOPE, "global": True, "account_id": ACCOUNT,
         "status": "collected", "items": [deepcopy(ACCT_CFG)]},
    ], created_at="2026-10-17T00:00:00Z")
    before = deepcopy(snap)
    found = [f for f in evaluate_snapshot(snap, checks=[cid])["findings"] if f["check_id"] == cid]
    assert snap == before and len(found) == 1
    return found[0]["status"]

def macie_row(jobs=None):
    return {"id": "macie-jobs/" + ACCOUNT + "/us-east-1", "SourceRegion": "us-east-1",
            "ServiceState": "available", "Jobs": {"collection_status": "collected", "items": deepcopy([] if jobs is None else jobs)}}

@pytest.mark.parametrize("field", ["Type", "Values"])
def test_logging_selected_resource_denial_is_unknown(field):
    trail = deepcopy(TRAIL)
    resource = trail["EventSelectors"]["EventSelectors"][0]["DataResources"][0]
    deny(resource, field)
    assert verdict(LOG, "cloudtrail_account_inventory", [trail]) == "UNKNOWN"

def test_logging_known_matching_home_region_does_not_require_multi_region_term():
    # Existing eligibility is IsMultiRegionTrail OR HomeRegion == bucket home.
    trail = deepcopy(TRAIL); deny(trail, "IsMultiRegionTrail")
    assert verdict(LOG, "cloudtrail_account_inventory", [trail]) == "PASS"

def test_logging_known_trail_survives_unreadable_peer():
    bad = deepcopy(TRAIL); bad["TrailARN"] = "arn:aws:cloudtrail:us-east-1:" + ACCOUNT + ":trail/bad"
    good = deepcopy(TRAIL); good["TrailARN"] = "arn:aws:cloudtrail:us-east-1:" + ACCOUNT + ":trail/good"
    bad["id"] = bad["TrailARN"]; good["id"] = good["TrailARN"]
    deny(bad["EventSelectors"]["EventSelectors"][0]["DataResources"][0], "Values")
    for trails in ([bad, good], [good, bad]):
        assert verdict(LOG, "cloudtrail_account_inventory", trails) == "PASS"

@pytest.mark.parametrize("field", ["SourceRegion", "ServiceState", "Jobs.items", "bucketDefinitions", "buckets"])
def test_macie_selected_fact_denial_is_unknown(field):
    row = macie_row([MACIE_JOB])
    if field == "Jobs.items": deny(row["Jobs"], "items")
    elif field == "bucketDefinitions": deny(row["Jobs"]["items"][0]["s3JobDefinition"], "bucketDefinitions")
    elif field == "buckets": deny(row["Jobs"]["items"][0]["s3JobDefinition"]["bucketDefinitions"][0], "buckets")
    else: deny(row, field)
    assert verdict(MACIE, "macie2_account_classification_job_inventory", [row]) == "UNKNOWN"

def test_macie_known_job_survives_unreadable_peer():
    bad = deepcopy(MACIE_JOB); deny(bad["s3JobDefinition"], "bucketDefinitions")
    for jobs in ([bad, deepcopy(MACIE_JOB)], [deepcopy(MACIE_JOB), bad]):
        assert verdict(MACIE, "macie2_account_classification_job_inventory", [macie_row(jobs)]) == "PASS"

def test_macie_complete_absence_is_fail_and_known_job_passes():
    assert verdict(MACIE, "macie2_account_classification_job_inventory", [macie_row([])]) == "FAIL"
    assert verdict(MACIE, "macie2_account_classification_job_inventory", [macie_row([MACIE_JOB])]) == "PASS"


def test_logging_optional_trail_label_does_not_hide_known_selector():
    trail = deepcopy(TRAIL)
    trail["TrailARN"] = "arn:aws:cloudtrail:us-east-1:" + ACCOUNT + ":trail/t"
    trail["id"] = trail["TrailARN"]
    deny(trail, "TrailARN")
    assert verdict(LOG, "cloudtrail_account_inventory", [trail]) == "PASS"

def test_macie_unknown_region_peer_does_not_hide_known_job_but_blocks_absence():
    unknown = macie_row([]); unknown["id"] += "-unresolved"; deny(unknown, "SourceRegion")
    known = macie_row([MACIE_JOB])
    for rows in ([unknown, known], [known, unknown]):
        assert verdict(MACIE, "macie2_account_classification_job_inventory", rows) == "PASS"
    assert verdict(MACIE, "macie2_account_classification_job_inventory", [unknown, macie_row([])]) == "UNKNOWN"

@pytest.mark.parametrize("field,value", [("SourceRegion", 3), ("ServiceState", 4), ("Jobs.items", {}), ("buckets", "b1")])
def test_macie_malformed_selected_native_types_are_unknown(field, value):
    row = macie_row([MACIE_JOB])
    if field == "Jobs.items": row["Jobs"]["items"] = value
    elif field == "buckets": row["Jobs"]["items"][0]["s3JobDefinition"]["bucketDefinitions"][0]["buckets"] = value
    else: row[field] = value
    assert verdict(MACIE, "macie2_account_classification_job_inventory", [row]) == "UNKNOWN"


def regional_macie(envelope):
    scope = ACCOUNT + "/us-east-1"
    snap = make_snapshot("aws", [scope], [
        {"type": "bucket", "scope": scope, "status": "collected", "items": [deepcopy(B)]},
        deepcopy(envelope),
    ], created_at="2026-10-17T00:00:00Z")
    before = deepcopy(snap)
    rows = [f for f in evaluate_snapshot(snap, checks=[MACIE])["findings"] if f["check_id"] == MACIE]
    assert snap == before and len(rows) == 1
    return rows[0]["status"]

@pytest.mark.parametrize("field", ["status", "error"])
def test_regional_macie_disabled_receipt_authority(field):
    scope = ACCOUNT + "/us-east-1"
    envelope = {"type": "macie2_classification_job", "scope": scope, "status": "empty", "items": [],
                "error": {"code": "service_not_enabled"}}
    deny(envelope, field)
    assert regional_macie(envelope) == "UNKNOWN"
    envelope.pop("_coverage")
    assert regional_macie(envelope) == "NOT_APPLICABLE"

def test_regional_macie_known_job_membership_remains_pass():
    scope = ACCOUNT + "/us-east-1"
    envelope = {"type": "macie2_classification_job", "scope": scope, "status": "collected", "items": [deepcopy(MACIE_JOB)]}
    assert regional_macie(envelope) == "PASS"


def test_empty_coverage_cannot_retain_nonempty_logging_value():
    trail = deepcopy(TRAIL)
    resource = trail["EventSelectors"]["EventSelectors"][0]["DataResources"][0]
    resource.setdefault("_coverage", {})["Values"] = {"status": "empty"}
    assert verdict(LOG, "cloudtrail_account_inventory", [trail]) == "UNKNOWN"

@pytest.mark.parametrize("field", ["SourceRegion", "Jobs.items", "buckets"])
def test_empty_coverage_cannot_retain_nonempty_macie_membership(field):
    row = macie_row([MACIE_JOB])
    if field == "Jobs.items": target, key = row["Jobs"], "items"
    elif field == "buckets": target, key = row["Jobs"]["items"][0]["s3JobDefinition"]["bucketDefinitions"][0], "buckets"
    else: target, key = row, "SourceRegion"
    target.setdefault("_coverage", {})[key] = {"status": "empty"}
    assert verdict(MACIE, "macie2_account_classification_job_inventory", [row]) == "UNKNOWN"

def test_observed_empty_arrays_retain_declared_no_match():
    trail = deepcopy(TRAIL)
    resource = trail["EventSelectors"]["EventSelectors"][0]["DataResources"][0]
    resource["Values"] = []
    resource["_coverage"] = {"Values": {"status": "empty"}}
    assert verdict(LOG, "cloudtrail_account_inventory", [trail]) == "FAIL"
    row = macie_row([])
    row["Jobs"]["_coverage"] = {"items": {"status": "empty"}}
    assert verdict(MACIE, "macie2_account_classification_job_inventory", [row]) == "FAIL"
