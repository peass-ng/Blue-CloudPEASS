"""Studio role swaps need one existing profile, compatible new app and exact grants."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, REGION, ALICE, aws_snap, col, user, role, allow, real, reached,
)

TECHNIQUE = "aws-sagemaker-updateuserprofile-passrole-createapp"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/studio"
DOMAIN_ID = "d-123456789abc"
DOMAIN_ARN = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:domain/{DOMAIN_ID}"
PROFILE_ARN = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:user-profile/{DOMAIN_ID}/alice"
APP_ARN = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:app/{DOMAIN_ID}/alice/JupyterLab/default"
PROFILE = {"UserProfileArn": PROFILE_ARN, "DomainId": DOMAIN_ID,
           "UserProfileName": "alice", "Status": "InService",
           "ExecutionRole": f"arn:aws:iam::{ACCOUNT}:role/old"}


def _grants(*, profile_arn=PROFILE_ARN, app_arn=APP_ARN, tags=True, pass_service=True):
    passed = allow("iam:PassRole", resource=ROLE_ARN)
    if not pass_service:
        passed = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": ROLE_ARN,
                  "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}}
    grants = [passed, allow("sagemaker:UpdateUserProfile", resource=profile_arn),
              allow("sagemaker:CreatePresignedDomainUrl", resource=profile_arn),
              allow("sagemaker:CreateApp", resource=app_arn)]
    if tags:
        grants.append(allow("sagemaker:AddTags", resource=app_arn))
    return grants


def _evaluate(*, grants=None, profiles=(PROFILE,), profile_status="collected", apps=(),
              app_status="empty", auth="IAM", state="InService", trust="sagemaker.amazonaws.com"):
    domain = {"DomainArn": DOMAIN_ARN, "DomainId": DOMAIN_ID, "Status": state, "AuthMode": auth}
    snap = aws_snap([user("alice", *(grants if grants is not None else _grants()))],
                    [role("studio", trust)], [col("sagemaker_domain", [domain]),
                    col("sagemaker_user_profile", profiles, profile_status),
                    col("sagemaker_app", apps, app_status)])
    return reached(real(snap, TECHNIQUE, include_unknown=True), ALICE, TECHNIQUE)


def test_role_swap_joins_profile_app_url_passrole_and_trust():
    assert _evaluate() == {ROLE_ARN: "conditional"}
    assert ROLE_ARN not in _evaluate(grants=_grants(tags=False))
    assert ROLE_ARN not in _evaluate(grants=_grants(pass_service=False))
    assert ROLE_ARN not in _evaluate(grants=_grants(profile_arn=PROFILE_ARN.replace("alice", "bob")))
    assert ROLE_ARN not in _evaluate(grants=_grants(app_arn=APP_ARN.replace("/alice/", "/bob/")))
    assert ROLE_ARN not in _evaluate(auth="SSO")
    assert ROLE_ARN not in _evaluate(state="Deleting")
    assert ROLE_ARN not in _evaluate(trust="ec2.amazonaws.com")
    assert ROLE_ARN not in _evaluate(profile_status="denied")
    assert ROLE_ARN not in _evaluate(app_status="denied")
    assert ROLE_ARN not in _evaluate(apps=[{"DomainId": DOMAIN_ID,
        "UserProfileName": "alice", "AppType": "JupyterLab", "AppName": "default",
        "Status": "InService"}], app_status="collected")


def test_unusable_profile_does_not_hide_another_profile():
    failed = {**PROFILE, "UserProfileArn": PROFILE_ARN.replace("alice", "first"),
              "UserProfileName": "first", "Status": "Failed"}
    assert _evaluate(profiles=(failed, PROFILE)) == {ROLE_ARN: "conditional"}
