"""Endpoint policy account boundary over the exact Principal ARN account field."""
from __future__ import annotations

import copy

from peaso.checks import CHECKS
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


CID = "aws.claude_a.vpc.endpoint_policy_trust_boundary"
SCOPE = "123456789012/us-east-1"
OWN = "123456789012"
OTHER = "210987654321"


def _check():
    return next(check for check in CHECKS if check.id == CID)


def _item(principal="*", condition=None, *, statements=None):
    rows = statements if statements is not None else [{"Effect": "Allow", "Principal": principal,
                                                       "Action": "*", "Resource": "*",
                                                       **({"Condition": condition} if condition is not None else {})}]
    return {"VpcEndpointId": "vpce-1", "PolicyDocument": {"Statement": rows}}


def _status(item):
    return _check().evaluate(item, {"context": {"Account": OWN, "scope": SCOPE}})[0]


def test_account_field_and_positive_account_conditions():
    assert _status(_item({"AWS": f"arn:aws:iam::{OWN}:root"})) == "PASS"
    assert _status(_item({"AWS": [OWN, f"arn:aws:iam::{OWN}:role/team"]})) == "PASS"
    assert _status(_item({"AWS": f"arn:aws:sts::{OWN}:assumed-role/team/session"})) == "PASS"
    assert _status(_item({"AWS": f"arn:aws:sts::{OWN}:federated-user/user"})) == "PASS"
    assert _status(_item("*", {"StringEquals": {"aws:PrincipalAccount": OWN}})) == "PASS"
    assert _status(_item("*", {"ArnLike": {"aws:PrincipalArn": f"arn:aws:iam::{OWN}:role/*"}})) == "PASS"
    assert _status(_item("*", {"ArnLike": {"aws:PrincipalArn": f"arn:aws:iam:*:{OWN}:role/*"}})) == "PASS"
    assert _status(_item("*", {"StringLike": {"aws:PrincipalArn": f"arn:aws:iam::{OWN}:role/*"}})) == "PASS"


def test_role_name_substring_never_proves_account_and_unconditional_foreign_fails():
    false_boundary = f"arn:aws:iam::*:role/team-{OWN}"
    assert _status(_item("*", {"StringLike": {"aws:PrincipalArn": false_boundary}})) == "UNKNOWN"
    assert _status(_item("*", {"StringLike": {"aws:PrincipalArn": f"arn:aws:iam:*:{OWN}:role/*"}})) == "UNKNOWN"
    assert _status(_item("*", {"ArnLike": {"aws:PrincipalArn": [f"arn:aws:iam::{OWN}:role/*", false_boundary]}})) == "UNKNOWN"
    assert _status(_item("*")) == "FAIL"
    assert _status(_item({"AWS": f"arn:aws:iam::{OTHER}:root"})) == "FAIL"
    assert _status(_item({"AWS": [OWN, OTHER]})) == "FAIL"


def test_other_conditions_and_unsupported_principals_remain_unknown():
    assert _status(_item("*", {"StringEquals": {"aws:SourceVpc": "vpc-1"}})) == "UNKNOWN"
    assert _status(_item("*", {"StringEquals": {"aws:PrincipalAccount": [OWN, OTHER]}})) == "UNKNOWN"
    assert _status(_item("*", {"StringLike": {"aws:PrincipalAccount": "*"}})) == "UNKNOWN"
    assert _status(_item({"Service": "ec2.amazonaws.com"})) == "UNKNOWN"
    assert _status(_item({"AWS": []})) == "UNKNOWN"
    for malformed in (
        f"arn:aws:s3::{OWN}:bucket",
        f"arn:aws:iam:us-east-1:{OWN}:role/team",
        f"arn:aws:iam::{OWN}:policy/team",
        f"arn:aws:iam::{OWN}:role/",
        f"arn:aws:iam::{OWN}:role/team:bad",
        f"arn:aws:sts::{OWN}:assumed-role/team",
        f"arn:aws:iam::*:role/team",
    ):
        assert _status(_item({"AWS": malformed})) == "UNKNOWN"
    assert _status(_item("*", {"StringEquals": ["not-an-object"]})) == "UNKNOWN"
    assert _status(_item("*", {"StringEquals": {"aws:PrincipalAccount": [OWN, None]}})) == "UNKNOWN"
    deny = [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Principal": {"AWS": OTHER}, "Action": "*", "Resource": "*"}]
    assert _status(_item(statements=deny)) == "UNKNOWN"


def test_absent_policy_and_unavailable_policy_fact():
    assert _status({"VpcEndpointId": "vpce-1"}) == "NOT_APPLICABLE"
    denied = _item()
    denied["_coverage"] = {"PolicyDocument": {"status": "denied"}}
    assert _status(denied) == "UNKNOWN"
    malformed = _item()
    malformed["PolicyDocument"]["Statement"][0]["Principal"] = 7
    assert _status(malformed) == "UNKNOWN"


def test_production_snapshot_uses_the_registered_check():
    item = _item("*", {"ArnLike": {"aws:PrincipalArn": f"arn:aws:iam::*:role/team-{OWN}"}})
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "vpc_endpoint", "scope": SCOPE,
                                                "service": "ec2", "status": "collected", "items": [copy.deepcopy(item)]}])
    report = evaluate_snapshot(snapshot, checks=[CID])
    findings = [finding for finding in report["findings"] if finding["check_id"] == CID]
    assert len(findings) == 1 and findings[0]["status"] == "UNKNOWN"
