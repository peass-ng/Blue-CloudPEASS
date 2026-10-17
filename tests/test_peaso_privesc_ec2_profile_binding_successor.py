"""Negative current-resource and review-scope binding for the held EC2 claim.

SDK stubs provide inert metadata; an artificial review row is used only to
verify that contradictions suppress a conditional edge, not runtime reach.
"""
import pytest
from test_peaso_aws_bulk_inventory import sdk
from tests import test_peaso_privesc_ec2_profile_branches as t
from peaso import privesc


def _edge_count(snapshot):
    result = privesc.analyze(snapshot)
    return sum(t.TECHNIQUE in edge["techniques"] and edge["source"] == t.SOURCE
               for edge in result["graph"]["edges"])


@pytest.mark.parametrize("case,expect_edge", [
    ("foreign_review_source_account", False),
    ("foreign_review_target_account", False),
    ("foreign_review_region", False),
    ("foreign_review_instance_id", False),
    ("foreign_review_scope", False),
    ("matching_review_bindings", True),
    ("foreign_native_owner", False),
    ("matching_native_owner", True),
    ("foreign_native_arn", False),
    ("matching_native_arn", True),
    ("foreign_collection_account", False),
    ("foreign_collection_region", False),
])
def test_ec2_review_and_native_identity_contradictions(sdk, monkeypatch, case, expect_edge):
    _, _, snapshot = t.capture(sdk, monkeypatch, "associate", "good")
    review = next(c for c in snapshot["collections"]
                  if c["type"] == "aws_privesc_challenge_evidence")["items"][0]
    native = next(c for c in snapshot["collections"] if c["type"] == "instance")["items"][0]
    review.update(SourceAccount=t.ACCOUNT, TargetAccount=t.ACCOUNT,
                  Region=t.REGION, InstanceId=t.IID, EvidenceScope=t.SCOPE)
    native.update(OwnerId=t.ACCOUNT, Arn=t.INSTANCE)
    if case == "foreign_review_source_account":
        review["SourceAccount"] = "999999999999"
    elif case == "foreign_review_target_account":
        review["TargetAccount"] = "999999999999"
    elif case == "foreign_review_region":
        review["Region"] = "us-west-2"
    elif case == "foreign_review_instance_id":
        review["InstanceId"] = "i-fffffffffffffffff"
    elif case == "foreign_review_scope":
        review["EvidenceScope"] = "999999999999/us-east-1"
    elif case == "foreign_native_owner":
        native["OwnerId"] = "999999999999"
    elif case == "foreign_native_arn":
        native["Arn"] = t.INSTANCE.replace(t.ACCOUNT, "999999999999")
    elif case == "foreign_collection_account":
        next(c for c in snapshot["collections"] if c["type"] == "instance")["account_id"] = "999999999999"
    elif case == "foreign_collection_region":
        next(c for c in snapshot["collections"] if c["type"] == "instance")["region"] = "us-west-2"
    assert bool(_edge_count(snapshot)) is expect_edge
