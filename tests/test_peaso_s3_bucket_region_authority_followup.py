"""Inert registered S3 region authority for Prowler replication."""
from copy import deepcopy
import pytest
from peaso.checks import claude_aws_a_s3 as s3
from test_peaso_s3_kms_replication_region_authority import CROSS, verdict, denied

@pytest.mark.parametrize("side,constraint", [("source", ""), ("source", "not-a-region"), ("source", "ap-southeast-8"), ("destination", ""), ("destination", "not-a-region")])
def test_invalid_explicit_location_cannot_prove_cross_region(side, constraint):
    item, destination = deepcopy(s3.B), deepcopy(s3.B2)
    (item if side == "source" else destination)["Location"]["LocationConstraint"] = constraint
    assert verdict(CROSS, item, destination) == "UNKNOWN"

def test_documented_null_omission_eu_and_region_literal():
    item, destination = deepcopy(s3.B), deepcopy(s3.B2)
    assert verdict(CROSS, item, destination) == "PASS"
    item["Location"].pop("LocationConstraint")
    assert verdict(CROSS, item, destination) == "PASS"
    item["Location"]["LocationConstraint"] = "EU"
    assert verdict(CROSS, item, destination) == "FAIL"
    item["Location"]["LocationConstraint"] = "ap-southeast-7"
    assert verdict(CROSS, item, destination) == "PASS"

def test_denied_location_remains_unknown_and_unversioned_stays_fail():
    item, destination = deepcopy(s3.B), deepcopy(s3.B2)
    denied(item["Location"], "LocationConstraint")
    assert verdict(CROSS, item, destination) == "UNKNOWN"
    item["Versioning"]["Status"] = "Suspended"
    assert verdict(CROSS, item, destination) == "FAIL"
