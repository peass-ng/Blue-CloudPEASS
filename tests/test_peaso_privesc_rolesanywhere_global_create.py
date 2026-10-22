"""A new Roles Anywhere anchor and profile need global create grants."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.effective_permissions.aws import AwsModel
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-rolesanywhere-createtrustanchor-createprofile-passrole"
ENTRY = next(row for row in privesc.load_catalog()["entries"] if row["id"] == ID)
SCOPE = "111111111111/us-east-1"


def _verdicts(anchor_resource="*", profile_resource="*"):
    snap = _snapshot(ENTRY)
    user = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Action": "rolesanywhere:CreateTrustAnchor", "Resource": anchor_resource},
        {"Effect": "Allow", "Action": "rolesanywhere:CreateProfile", "Resource": profile_resource},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role["Arn"],
         "Condition": {"StringEquals": {"iam:PassedToService": "rolesanywhere.amazonaws.com"}}}]
    role["AssumeRolePolicyDocument"] = {"Statement": [{"Effect": "Allow",
        "Principal": {"Service": "rolesanywhere.amazonaws.com"},
        "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]}]}
    for kind in ("rolesanywhere_trust_anchor", "rolesanywhere_profile"):
        snap["collections"].append({"type": kind, "scope": SCOPE, "service": "rolesanywhere",
                                    "status": "empty", "items": [], "error": None})
    model = AwsModel(snap)
    return model.precondition("rolesanywhere_new_anchor_profile_role_ready",
                              {role["Arn"]: model.principals[role["Arn"]]}, model.principals[user["Arn"]])


def test_new_anchor_and_profile_require_global_create_resource():
    assert next(iter(_verdicts().values()))[0] == "conditional"
    assert not _verdicts(anchor_resource="arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/old")
    assert not _verdicts(profile_resource="arn:aws:rolesanywhere:us-east-1:111111111111:profile/old")
