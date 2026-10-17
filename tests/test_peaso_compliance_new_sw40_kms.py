"""Isolated signed KMS sw40 predicates."""
from __future__ import annotations

import copy

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw40 as sw40

ACCOUNT = "123456789012"
SCOPE = ACCOUNT + "/us-east-1"
KEY_ARN = "arn:aws:kms:us-east-1:" + ACCOUNT + ":key/example"
ALICE = "arn:aws:iam::" + ACCOUNT + ":role/Custodian"
BOB = "arn:aws:iam::" + ACCOUNT + ":role/Unapproved"


def teardown_module():
    CHECKS[:] = [c for c in CHECKS if c.id not in sw40.SPECS]


def key(action="kms:DescribeKey", principal=ALICE, **extra):
    return {"KeyId": "example", "Metadata": {"collection_status": "collected", "KeyMetadata": {
        "Arn": KEY_ARN, "KeyManager": "CUSTOMER", "KeyState": "Enabled"}},
        "Policy": {"collection_status": "collected", "Policy": {"Statement": [
            {"Effect": "Allow", "Action": action, "Resource": "*", "Principal": {"AWS": principal}, **extra}]}},
        "Tags": [{"TagKey": "Compromised", "TagValue": "true"}]}


def index(row=None, *, status="collected", approved=True):
    row = key() if row is None else row
    compliance = {"account_id": ACCOUNT, "enclave_key_arns": [KEY_ARN],
        "approved_enclave_measurements": ["approved-sha"],
        "approved_custodian_arns": [ALICE], "approved_key_principal_arns": [ALICE],
        "customer_data_key_arns": [KEY_ARN], "kms_iam_access_complete": True,
        "kms_iam_access_by_key": {KEY_ARN: []}} if approved else {}
    return {"context": {"provider": "aws", "scope": SCOPE, "metadata": {"compliance": compliance}},
        "collections": {kind: [{"type": kind, "scope": SCOPE, "account_id": ACCOUNT,
            "status": status}] for kind in ("kms_key", "kms_grant")},
        "kms_key": [{"data": row}], "kms_grant": []}


def status(cid, row, facts=None):
    return evaluate_check(cid, row, index(row) if facts is None else facts)[0]


def test_enclave_attestation_pass_fail_unknown_not_applicable():
    cid = "aws.pci.kms.enclave_attestation_policy"
    safe = key("kms:Decrypt", Condition={"StringEquals": {
        "kms:RecipientAttestation:ImageSha384": "approved-sha"}})
    assert status(cid, safe) == "PASS"
    unsafe = key("kms:Decrypt")
    assert status(cid, unsafe) == "FAIL"
    facts = index(unsafe)
    facts["context"]["metadata"]["compliance"]["enclave_key_arns"] = []
    assert status(cid, unsafe, facts) == "NOT_APPLICABLE"
    assert status(cid, unsafe, index(unsafe, status="partial")) == "UNKNOWN"
    assert status(cid, unsafe, index(unsafe, approved=False)) == "UNKNOWN"
    malformed = key("kms:Decrypt")
    malformed["Policy"]["Policy"]["Statement"] = ["bad"]
    assert status(cid, malformed) == "UNKNOWN"


def test_custodian_approval_and_grant_inventory():
    cid = "aws.pci.kms.key_custodian_access"
    safe = key("kms:Decrypt", ALICE)
    assert status(cid, safe) == "PASS"
    unsafe = key("kms:Decrypt", BOB)
    assert status(cid, unsafe) == "FAIL"
    facts = index(safe)
    facts["kms_grant"] = [{"data": {"KeyArn": KEY_ARN, "GranteePrincipal": BOB,
        "Operations": ["Decrypt"]}}]
    assert status(cid, safe, facts) == "FAIL"
    facts["collections"]["kms_grant"][0]["status"] = "partial"
    assert status(cid, safe, facts) == "UNKNOWN"
    assert status(cid, safe, index(safe, approved=False)) == "UNKNOWN"
    malformed = key("kms:Decrypt")
    del malformed["Policy"]
    assert status(cid, malformed) == "UNKNOWN"


def test_compromised_key_enabled_allow_disabled_and_unknown():
    cid = "aws_kms_compromised_key_restricted"
    unsafe = key("kms:Encrypt")
    assert status(cid, unsafe) == "FAIL"
    disabled = copy.deepcopy(unsafe)
    disabled["Metadata"]["KeyMetadata"]["KeyState"] = "Disabled"
    assert status(cid, disabled) == "PASS"
    ordinary = copy.deepcopy(unsafe)
    ordinary["Tags"][0]["TagValue"] = "false"
    assert status(cid, ordinary) == "NOT_APPLICABLE"
    assert status(cid, key("kms:DescribeKey")) == "UNKNOWN"
    assert status(cid, unsafe, index(unsafe, status="partial")) == "UNKNOWN"
    malformed = copy.deepcopy(unsafe)
    malformed["Tags"] = [{"TagKey": "Compromised"}]
    assert status(cid, malformed) == "UNKNOWN"


def test_customer_data_key_control_pass_fail_unknown_not_applicable():
    cid = "aws_kms_customer_key_control"
    safe = key("kms:Decrypt", ALICE)
    assert status(cid, safe) == "PASS"
    unsafe = key("kms:Decrypt", BOB)
    assert status(cid, unsafe) == "FAIL"
    unmanaged = copy.deepcopy(safe)
    unmanaged["Metadata"]["KeyMetadata"]["KeyManager"] = "AWS"
    assert status(cid, unmanaged) == "FAIL"
    facts = index(safe)
    facts["context"]["metadata"]["compliance"]["customer_data_key_arns"] = []
    assert status(cid, safe, facts) == "NOT_APPLICABLE"
    assert status(cid, safe, index(safe, approved=False)) == "UNKNOWN"
    assert status(cid, safe, index(safe, status="partial")) == "UNKNOWN"
    malformed = copy.deepcopy(safe)
    malformed["Metadata"]["KeyMetadata"]["Arn"] = "wrong"
    assert status(cid, malformed) == "UNKNOWN"
