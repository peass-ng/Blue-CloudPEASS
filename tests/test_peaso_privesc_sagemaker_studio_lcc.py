"""Studio profile lifecycle hooks require one creatable configuration and app."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, REGION, SCOPE, ALICE, aws_snap, col, user, role, allow, real, reached,
)

TECHNIQUE = "aws-sagemaker-attach-studio-lifecycle-config-user-profile"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/studio"
PROFILE_ARN = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:user-profile/d-123456789abc/alice"
LCC_PREFIX = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:studio-lifecycle-config/"
APP_PREFIX = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:app/d-123456789abc/alice/"


def _evaluate(*, grants=None, profile_role=ROLE_ARN, profile_status="InService",
              domain_auth="IAM", apps=(), app_inventory="empty", configs=(), config_inventory="empty",
              extra_profiles=()):
    if grants is None:
        grants = (allow("sagemaker:CreateStudioLifecycleConfig", resource=LCC_PREFIX + "alpha-*"),
                  allow("sagemaker:UpdateUserProfile", resource=PROFILE_ARN),
                  allow("sagemaker:CreateApp", resource=APP_PREFIX + "JupyterLab/default"),
                  allow("sagemaker:AddTags", resource=APP_PREFIX + "JupyterLab/default"))
    profile = {"UserProfileArn": PROFILE_ARN, "DomainId": "d-123456789abc",
               "UserProfileName": "alice", "Status": profile_status, "ExecutionRole": profile_role}
    domain = {"DomainArn": f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:domain/d-123456789abc",
              "DomainId": "d-123456789abc", "Status": "InService", "AuthMode": domain_auth}
    snap = aws_snap([user("alice", *grants)], [role("studio", "sagemaker.amazonaws.com")], [
        col("sagemaker_user_profile", [*extra_profiles, profile]), col("sagemaker_domain", [domain]),
        col("sagemaker_app", apps, app_inventory),
        col("sagemaker_studio_lifecycle_config", configs, config_inventory)])
    result = real(snap, TECHNIQUE, include_unknown=True)
    return reached(result, ALICE, TECHNIQUE)


def test_studio_lcc_requires_matching_profile_lcc_app_and_permissions():
    assert _evaluate() == {ROLE_ARN: "conditional"}
    assert ROLE_ARN not in _evaluate(profile_role=f"arn:aws:iam::{ACCOUNT}:role/other")
    assert ROLE_ARN not in _evaluate(profile_status="Failed")
    assert ROLE_ARN not in _evaluate(domain_auth="SSO")
    assert ROLE_ARN not in _evaluate(config_inventory="denied")
    assert ROLE_ARN not in _evaluate(apps=[{"DomainId": "d-123456789abc",
        "UserProfileName": "alice", "AppType": "JupyterLab", "AppName": "default",
        "Status": "InService"}], app_inventory="collected")
    exact = allow("sagemaker:CreateStudioLifecycleConfig", resource=LCC_PREFIX + "alpha-fixed")
    grants = (exact, allow("sagemaker:UpdateUserProfile", resource=PROFILE_ARN),
              allow("sagemaker:CreateApp", resource=APP_PREFIX + "JupyterLab/default"),
              allow("sagemaker:AddTags", resource=APP_PREFIX + "JupyterLab/default"))
    assert ROLE_ARN not in _evaluate(grants=grants, configs=[{
        "StudioLifecycleConfigArn": LCC_PREFIX + "alpha-fixed",
        "StudioLifecycleConfigName": "alpha-fixed", "StudioLifecycleConfigAppType": "JupyterLab"}],
        config_inventory="collected")
    assert ROLE_ARN not in _evaluate(grants=grants[:-1])
    conditioned = {"Effect": "Allow", "Action": "sagemaker:UpdateUserProfile",
                   "Resource": PROFILE_ARN, "Condition": {"StringEquals": {
                       "sagemaker:StudioLifecycleConfigArns": LCC_PREFIX + "wrong"}}}
    assert ROLE_ARN not in _evaluate(grants=(exact, conditioned, *grants[2:]))


def test_unusable_studio_profile_does_not_hide_another_profile():
    failed = {"UserProfileArn": PROFILE_ARN.replace("alice", "first"),
              "DomainId": "d-123456789abc", "UserProfileName": "first",
              "Status": "Failed", "ExecutionRole": ROLE_ARN}
    assert _evaluate(extra_profiles=[failed]) == {ROLE_ARN: "conditional"}

