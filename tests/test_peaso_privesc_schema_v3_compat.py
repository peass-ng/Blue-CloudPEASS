"""Accepted v2 contract guards and a legacy-catalog behavior check."""
from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import (ACCOUNT, LAMBDA_TARGET, allow, aws_snap,
                                                  entry, errors_of, reached, role, user)
from tests.test_peaso_privesc_schema_v2 import (AWS_ENTRY, GCP_ENTRY, K8S_ENTRY,
                                               aws_snap as v2_aws_snap, gcp_snap, k8s_related)


def test_aws_join_requires_same_account_and_only_create_policy_version():
    for mutate in (
        lambda e: e["target"].update(scope="any"),
        lambda e: e["requires"]["all_of"].append(
            {"action": "iam:SetDefaultPolicyVersion",
             "resource": "{source.assumable_role_attached_policy_arn}"}),
        lambda e: e["requires"]["all_of"].append(
            {"action": "iam:SetDefaultPolicyVersion", "resource": "*"}),
    ):
        technique = copy.deepcopy(AWS_ENTRY)
        mutate(technique)
        assert errors_of(technique)


def test_legacy_passrole_entry_still_reaches_only_matching_role():
    technique = entry("aws-t-legacy-passrole", "aws", {"all_of": [
        {"action": "iam:PassRole", "resource": "{target.arn}"},
        {"action": "lambda:CreateFunction", "resource": "*"}]}, LAMBDA_TARGET)
    assert errors_of(technique) == []
    source = f"arn:aws:iam::{ACCOUNT}:user/alice"
    result = privesc.analyze(aws_snap(
        [user("alice", allow("iam:PassRole", "*"), allow("lambda:CreateFunction", "*"))],
        [role("fn", "lambda.amazonaws.com"), role("vm", "ec2.amazonaws.com")]), entries=[technique])
    assert reached(result, source) == {f"arn:aws:iam::{ACCOUNT}:role/fn": "derived"}


def test_aws_join_missing_referenced_policy_is_unknown():
    snap = v2_aws_snap()
    policy_collection = next(c for c in snap["collections"] if c["type"] == "iam_policy")
    policy_collection["items"] = []
    out = privesc.analyze(snap, entries=[AWS_ENTRY], include_unknown=True)
    assert f"aws_account_admin:{ACCOUNT}" not in reached(out, f"arn:aws:iam::{ACCOUNT}:user/alice")
    assert any(f["status"] == "UNKNOWN" for f in out["findings"])
    assert not any(f["status"] == "FAIL" for f in out["findings"])


def test_gcp_running_pod_missing_phase_is_unknown():
    related = k8s_related()
    pod = next(c for c in related["collections"] if c["type"] == "pod")["items"][0]
    pod.pop("status")
    out = privesc.analyze(gcp_snap(), entries=[GCP_ENTRY], related_snapshots=[related], include_unknown=True)
    assert "k8s:gke_p1_us-a_c1:sa:a:builder" not in reached(out, "user:alice@x.com")
    assert any(f["status"] == "UNKNOWN" for f in out["findings"])
    assert not any(f["status"] == "FAIL" for f in out["findings"])


def test_k8s_rolebound_placeholder_rejects_mismatched_requirement():
    for field, value in (("resource", "roles"), ("api_group", "other.example"),
                         ("namespace", "a"), ("verb", "get")):
        technique = copy.deepcopy(K8S_ENTRY)
        technique["requires"]["all_of"][0][field] = value
        assert errors_of(technique), (field, value)
