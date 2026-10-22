"""A new Studio profile route needs one coherent profile, app and role request."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, REGION, ALICE, aws_snap, col, user, role, allow, real, reached,
)

TECHNIQUE = "aws-sagemaker-createuserprofile-passrole-createapp"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/studio"
DOMAIN_ID = "d-123456789abc"
DOMAIN_ARN = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:domain/{DOMAIN_ID}"
PROFILE_PREFIX = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:user-profile/{DOMAIN_ID}/"
APP_PREFIX = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:app/{DOMAIN_ID}/"
NAME = "PeasoProfile"
APP_ARN = APP_PREFIX + NAME + "/JupyterLab/default"


def _grants(*, app_arn=APP_ARN, profile_arn=PROFILE_PREFIX + NAME,
            app_tags=True, passed_service=True):
    passrole = allow("iam:PassRole", resource=ROLE_ARN)
    if not passed_service:
        passrole = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": ROLE_ARN,
                    "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}}
    grants = [passrole, allow("sagemaker:CreateUserProfile", resource=profile_arn),
              allow("sagemaker:CreatePresignedDomainUrl", resource=profile_arn),
              allow("sagemaker:CreateApp", resource=app_arn)]
    if app_tags:
        grants.append(allow("sagemaker:AddTags", resource=app_arn))
    return grants


def _evaluate(*, grants=None, domain_auth="IAM", domain_status="InService",
              domain_id=DOMAIN_ID, profiles=(), profile_inventory="empty",
              trust="sagemaker.amazonaws.com"):
    domain = {"DomainArn": DOMAIN_ARN, "DomainId": domain_id,
              "Status": domain_status, "AuthMode": domain_auth}
    snap = aws_snap([user("alice", *(grants if grants is not None else _grants()))],
                    [role("studio", trust)], [col("sagemaker_domain", [domain]),
                    col("sagemaker_user_profile", profiles, profile_inventory)])
    return reached(real(snap, TECHNIQUE, include_unknown=True), ALICE, TECHNIQUE)


def test_new_profile_joins_scoped_profile_app_url_tags_and_role():
    assert _evaluate() == {ROLE_ARN: "conditional"}
    assert ROLE_ARN not in _evaluate(grants=_grants(app_tags=False))
    assert ROLE_ARN not in _evaluate(grants=_grants(passed_service=False))
    assert ROLE_ARN not in _evaluate(grants=_grants(app_arn=APP_PREFIX + "other/JupyterLab/default"))
    assert ROLE_ARN not in _evaluate(domain_auth="SSO")
    assert ROLE_ARN not in _evaluate(domain_status="Deleting")
    assert ROLE_ARN not in _evaluate(domain_id="d-other")
    assert ROLE_ARN not in _evaluate(profile_inventory="denied")
    assert ROLE_ARN not in _evaluate(trust="ec2.amazonaws.com")
    existing = {"DomainId": DOMAIN_ID, "UserProfileName": NAME,
                "UserProfileArn": PROFILE_PREFIX + NAME, "Status": "InService"}
    assert ROLE_ARN not in _evaluate(profiles=[existing], profile_inventory="collected")
