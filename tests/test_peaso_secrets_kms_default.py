"""Identity-bound DescribeSecret omission semantics for the two native secret KMS checks."""
import copy

import pytest

from peaso.engine import evaluate_snapshot
from peaso.collectors import aws
from test_peaso_remaining_aws_gcp_native import _collect_secret, KEY_ARN, ACCOUNT, REGION, SECRET_ARN

PCI = "aws.pci.secretsmanager.kms_encryption_any"
CMK = "aws.cb.secretsmanager.cmk_encryption"


def _finding_status(snapshot, check_id):
    report = evaluate_snapshot(snapshot, checks=[check_id])
    findings = [row for row in report["findings"] if row["check_id"] == check_id
                and row["resource_id"] != "inventory:secret"]
    assert len(findings) == 1
    return findings[0]["status"]


def _statuses(snapshot):
    return _finding_status(snapshot, PCI), _finding_status(snapshot, CMK)


def _secret(snapshot):
    return next(row for row in snapshot["collections"] if row["type"] == "secret")["items"][0]


def test_sdk_describe_secret_omission_proves_aws_managed_default(monkeypatch):
    snapshot = _collect_secret(monkeypatch, key_ref=None)
    secret = _secret(snapshot)
    assert "KmsKeyId" not in secret
    assert secret["_coverage"]["KmsKeyId"] == {
        "status": "empty", "source_operation": "secretsmanager:DescribeSecret",
        "native_member_present": False, "documented_default": "aws/secretsmanager"}
    assert _statuses(snapshot) == ("PASS", "FAIL")


@pytest.mark.parametrize("key_ref,key_state,manager,expected", [
    (KEY_ARN, "Enabled", "CUSTOMER", ("PASS", "PASS")),
    (KEY_ARN, "Disabled", "CUSTOMER", ("FAIL", "PASS")),
    (KEY_ARN, "Enabled", "AWS", ("PASS", "FAIL")),
    (f"arn:aws:kms:us-east-1:{ACCOUNT}:alias/secret", "Enabled", "CUSTOMER", ("UNKNOWN", "UNKNOWN")),
    ("alias/aws/secretsmanager", "Enabled", "CUSTOMER", ("UNKNOWN", "FAIL")),
    (KEY_ARN.replace(ACCOUNT, "999999999999"), "Enabled", "CUSTOMER", ("UNKNOWN", "UNKNOWN")),
])
def test_explicit_key_manager_and_reference_cases(monkeypatch, key_ref, key_state, manager, expected):
    snapshot = _collect_secret(monkeypatch, key_ref=key_ref, key_state=key_state)
    if manager == "AWS":
        key = next(row for row in snapshot["collections"] if row["type"] == "kms_key")["items"][0]
        key["Metadata"]["KeyMetadata"]["KeyManager"] = manager
        snapshot.pop("snapshot_id", None)
    assert _statuses(snapshot) == expected


def test_explicit_empty_member_is_malformed_not_documented_omission(monkeypatch):
    snapshot = _collect_secret(monkeypatch, key_ref="")
    marker = _secret(snapshot)["_coverage"]["KmsKeyId"]
    assert marker["status"] == "malformed" and marker["native_member_present"] is True
    assert _statuses(snapshot) == ("UNKNOWN", "UNKNOWN")


@pytest.mark.parametrize("change", ["no_provenance", "wrong_operation", "member_present",
                                   "wrong_default", "raw_empty", "partial", "foreign"])
def test_omission_fails_closed_without_identity_bound_proof(monkeypatch, change):
    snapshot = _collect_secret(monkeypatch, key_ref=None)
    envelope = next(row for row in snapshot["collections"] if row["type"] == "secret")
    secret = envelope["items"][0]
    marker = secret["_coverage"]["KmsKeyId"]
    if change == "no_provenance":
        del secret["_coverage"]["KmsKeyId"]
    elif change == "wrong_operation":
        marker["source_operation"] = "secretsmanager:ListSecrets"
    elif change == "member_present":
        marker["native_member_present"] = True
    elif change == "wrong_default":
        marker["documented_default"] = "alias/other"
    elif change == "raw_empty":
        secret["KmsKeyId"] = ""
    elif change == "partial":
        envelope["status"] = change
        envelope["error"] = {"code": "incomplete"}
    else:
        secret["ARN"] = secret["ARN"].replace(ACCOUNT, "999999999999")
    snapshot.pop("snapshot_id", None)
    assert _statuses(snapshot) == ("UNKNOWN", "UNKNOWN")


def test_denied_describe_secret_remains_unknown(monkeypatch):
    assert _statuses(_collect_secret(monkeypatch, deny_detail=True)) == ("UNKNOWN", "UNKNOWN")


@pytest.mark.parametrize("change", ["duplicate_identical", "duplicate_conflicting", "malformed_arn",
                                   "foreign_account", "foreign_region", "foreign_partition",
                                   "foreign_envelope_account"])
def test_omitted_key_requires_unique_authoritative_native_secret(monkeypatch, change):
    snapshot = _collect_secret(monkeypatch, key_ref=None)
    envelope = next(row for row in snapshot["collections"] if row["type"] == "secret")
    original = envelope["items"][0]
    if change == "foreign_envelope_account":
        envelope["account_id"] = "999999999999"
    else:
        extra = copy.deepcopy(original)
        if change == "duplicate_conflicting":
            extra["KmsKeyId"] = KEY_ARN
            extra["_coverage"]["KmsKeyId"] = {
                "status": "collected", "source_operation": "secretsmanager:DescribeSecret",
                "native_member_present": True}
        elif change == "malformed_arn":
            extra["ARN"] = "not-an-arn"
        elif change == "foreign_account":
            extra["ARN"] = extra["ARN"].replace(ACCOUNT, "999999999999")
        elif change == "foreign_region":
            extra["ARN"] = extra["ARN"].replace(REGION, "us-west-2")
        elif change == "foreign_partition":
            extra["ARN"] = extra["ARN"].replace("arn:aws:", "arn:aws-cn:")
        envelope["items"].append(extra)
    snapshot.pop("snapshot_id", None)
    for check_id in (PCI, CMK):
        report = evaluate_snapshot(snapshot, checks=[check_id])
        findings = [row for row in report["findings"] if row["check_id"] == check_id
                    and row["resource_id"] != "inventory:secret"]
        assert findings and all(row["status"] == "UNKNOWN" for row in findings), change


def test_collector_explicit_null_kms_member_is_malformed():
    class NativeDetails:
        def detail(self, session, service, region, operation, **kwargs):
            if (service, operation) == ("secretsmanager", "describe_secret"):
                assert kwargs == {"SecretId": SECRET_ARN}
                return {"collection_status": "collected", "ARN": SECRET_ARN,
                        "Name": "db", "KmsKeyId": None}
            if (service, operation) == ("secretsmanager", "get_resource_policy"):
                return {"collection_status": "collected"}
            raise AssertionError((service, operation))

    rows = aws._enrich(NativeDetails(), None, REGION, "secret",
                       [{"ARN": SECRET_ARN, "Name": "db", "KmsKeyId": KEY_ARN}],
                       account=ACCOUNT, partition="aws")
    assert len(rows) == 1
    secret = rows[0]
    assert "KmsKeyId" not in secret
    assert secret["_coverage"]["KmsKeyId"] == {
        "status": "malformed", "source_operation": "secretsmanager:DescribeSecret",
        "native_member_present": True}
