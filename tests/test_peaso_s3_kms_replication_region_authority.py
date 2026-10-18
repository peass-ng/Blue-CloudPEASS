"""Selected S3 encryption, replication, and location facts remain source-bound."""
from copy import deepcopy
import pytest
from peaso.checks import claude_aws_a_s3 as s3
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

KMS = "aws.claude_a.s3.default_encryption_kms_key"
REPLICATION = "aws.claude_a.s3.replication_rule_enabled"
CROSS = "aws.claude_a.s3.prowler_cross_region_replication"


def verdict(cid, item, destination=None):
    scope = s3.ACCOUNT + "/us-east-1"
    rows = [deepcopy(item)] + ([] if destination is None else [deepcopy(destination)])
    snap = make_snapshot("aws", [scope], [{"type": "bucket", "scope": scope, "status": "collected", "items": rows}], created_at="2026-10-17T00:00:00Z")
    before = deepcopy(snap)
    found = [f for f in evaluate_snapshot(snap, checks=[cid])["findings"] if f["check_id"] == cid and f.get("native_resource_id") == item["Name"]]
    assert before == snap and len(found) == 1
    return found[0]["status"]


def denied(row, key):
    row.setdefault("_coverage", {})[key] = {"status": "denied"}


def enc_rule(item):
    return item["Encryption"]["ServerSideEncryptionConfiguration"]["Rules"][0]


def rep_rule(item):
    return item["Replication"]["ReplicationConfiguration"]["Rules"][0]


@pytest.mark.parametrize("field", ["ApplyServerSideEncryptionByDefault", "KMSMasterKeyID"])
def test_kms_unreadable_selected_field_is_unknown(field):
    item = deepcopy(s3.B)
    target = enc_rule(item) if field == "ApplyServerSideEncryptionByDefault" else enc_rule(item)["ApplyServerSideEncryptionByDefault"]
    denied(target, field)
    assert verdict(KMS, item) == "UNKNOWN"


def test_kms_invalid_id_is_unknown_but_any_valid_named_rule_is_sufficient():
    item = deepcopy(s3.B)
    enc_rule(item)["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"] = 42
    assert verdict(KMS, item) == "UNKNOWN"
    item = deepcopy(s3.B)
    unknown = {"ApplyServerSideEncryptionByDefault": {"KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/other", "_coverage": {"KMSMasterKeyID": {"status": "denied"}}}}
    item["Encryption"]["ServerSideEncryptionConfiguration"]["Rules"].insert(0, unknown)
    assert verdict(KMS, item) == "PASS"
    enc_rule(item)["ApplyServerSideEncryptionByDefault"].pop("_coverage")
    assert verdict(KMS, item) == "PASS"


def test_kms_no_algorithm_requirement_and_no_key_failure():
    item = deepcopy(s3.B)
    enc_rule(item)["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] = "AES256"
    assert verdict(KMS, item) == "PASS"
    enc_rule(item)["ApplyServerSideEncryptionByDefault"].pop("KMSMasterKeyID")
    assert verdict(KMS, item) == "FAIL"


@pytest.mark.parametrize("field", ["Status", "Destination"])
def test_replication_rule_selected_and_unused_fields(field):
    item = deepcopy(s3.B)
    denied(rep_rule(item), field)
    assert verdict(REPLICATION, item) == ("UNKNOWN" if field == "Status" else "PASS")


def test_replication_unknown_peer_and_optional_id_do_not_hide_enabled_rule():
    item = deepcopy(s3.B)
    uncertain = {"Status": "Disabled", "_coverage": {"Status": {"status": "denied"}}}
    item["Replication"]["ReplicationConfiguration"]["Rules"].insert(0, uncertain)
    item["Replication"]["ReplicationConfiguration"]["Rules"][1].pop("ID")
    assert verdict(REPLICATION, item) == "PASS"
    item["Replication"]["ReplicationConfiguration"]["Rules"].pop()
    assert verdict(REPLICATION, item) == "UNKNOWN"


@pytest.mark.parametrize("field", ["Status", "Destination", "Bucket"])
def test_cross_region_selected_rule_fields_are_authoritative(field):
    item = deepcopy(s3.B)
    target = rep_rule(item)["Destination"] if field == "Bucket" else rep_rule(item)
    denied(target, field)
    assert verdict(CROSS, item, s3.B2) == "UNKNOWN"


@pytest.mark.parametrize("which", ["source", "destination"])
def test_cross_region_location_constraint_denial_is_unknown(which):
    item, destination = deepcopy(s3.B), deepcopy(s3.B2)
    denied((item if which == "source" else destination)["Location"], "LocationConstraint")
    assert verdict(CROSS, item, destination) == "UNKNOWN"


def test_cross_region_native_location_omission_means_us_east_1():
    item = deepcopy(s3.B)
    item["Location"].pop("LocationConstraint")
    assert verdict(CROSS, item, s3.B2) == "PASS"


def test_conclusive_unversioned_failure_does_not_need_location():
    item = deepcopy(s3.B)
    item["Versioning"]["Status"] = "Suspended"
    denied(item["Location"], "LocationConstraint")
    assert verdict(CROSS, item, s3.B2) == "FAIL"


def test_known_cross_region_rule_survives_unknown_peer_in_either_order():
    for reverse in (False, True):
        item = deepcopy(s3.B)
        uncertain = {"Status": "Enabled", "Destination": {"Bucket": "arn:aws:s3:::b2"}, "_coverage": {"Status": {"status": "denied"}}}
        rules = item["Replication"]["ReplicationConfiguration"]["Rules"]
        rules.insert(len(rules) if reverse else 0, uncertain)
        assert verdict(CROSS, item, s3.B2) == "PASS"
