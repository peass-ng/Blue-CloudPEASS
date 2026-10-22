"""Joining a group only yields a new edge when its policies add usable authority."""

from test_peaso_privesc_audit_fixes import ACCOUNT, ALICE, aws, policy, real, reached, user


TECHNIQUE = "aws-iam-addusertogroup"
GROUP = f"arn:aws:iam::{ACCOUNT}:group/editors"


def _snapshot(*, join_resource=GROUP, group_action="iam:PutUserPolicy",
              already_member=False, membership_recorded=True):
    actor = user("alice", {"Effect": "Allow", "Action": "iam:AddUserToGroup",
                           "Resource": join_resource})
    actor["GroupList"] = ["editors"] if already_member else [] if membership_recorded else None
    group = {"GroupName": "editors", "Arn": GROUP, "Path": "/",
             "GroupPolicyList": [{"PolicyName": "self-edit", "PolicyDocument": policy(
                 {"Effect": "Allow", "Action": group_action, "Resource": ALICE})}],
             "AttachedManagedPolicies": []}
    snapshot = aws([actor])
    collection = next(c for c in snapshot["collections"] if c["type"] == "iam_group")
    collection["items"] = [group]
    collection["status"] = "collected"
    return snapshot


def test_new_group_membership_grants_a_new_self_policy_edit():
    result = real(_snapshot(), TECHNIQUE)
    assert reached(result, ALICE) == {GROUP: "conditional"}


def test_group_path_rejects_wrong_join_target_and_existing_membership():
    other = f"arn:aws:iam::{ACCOUNT}:group/other"
    assert reached(real(_snapshot(join_resource=other), TECHNIQUE), ALICE) == {}
    assert reached(real(_snapshot(already_member=True), TECHNIQUE), ALICE) == {}


def test_unrelated_policy_gain_or_missing_membership_does_not_claim_escalation():
    unrelated = real(_snapshot(group_action="s3:GetObject"), TECHNIQUE)
    assert reached(unrelated, ALICE) == {}
    missing = real(_snapshot(membership_recorded=False), TECHNIQUE, include_unknown=True)
    assert GROUP not in reached(missing, ALICE)
    assert any("group_or_source_policies_not_collected" in row.get("reason", "")
               for row in missing["coverage"])
