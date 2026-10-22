"""A new Studio profile route needs one coherent profile, app and role request."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, REGION, ALICE, aws_snap, col, user, role, allow, real, reached,
)

TECHNIQUE = "aws-sagemaker-createuserprofile-passrole-createapp"
DOMAIN_TECHNIQUE = "aws-sagemaker-updatedomain-createuserprofile-passrole"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/studio"
DOMAIN_ID = "d-123456789abc"
DOMAIN_ARN = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:domain/{DOMAIN_ID}"
PROFILE_PREFIX = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:user-profile/{DOMAIN_ID}/"
APP_PREFIX = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:app/{DOMAIN_ID}/"
NAME = "PeasoProfile"
APP_ARN = APP_PREFIX + NAME + "/JupyterLab/default"


def _grants(*, app_arn=APP_ARN, profile_arn=PROFILE_PREFIX + NAME,
            app_tags=True, passed_service=True, domain_update=False):
    passrole = allow("iam:PassRole", resource=ROLE_ARN)
    if not passed_service:
        passrole = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": ROLE_ARN,
                    "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}}
    grants = [passrole, allow("sagemaker:CreateUserProfile", resource=profile_arn),
              allow("sagemaker:CreatePresignedDomainUrl", resource=profile_arn),
              allow("sagemaker:CreateApp", resource=app_arn)]
    if app_tags:
        grants.append(allow("sagemaker:AddTags", resource=app_arn))
    if domain_update:
        grants.append(allow("sagemaker:UpdateDomain", resource=DOMAIN_ARN))
    return grants


def _evaluate(*, grants=None, domain_auth="IAM", domain_status="InService",
              domain_id=DOMAIN_ID, profiles=(), profile_inventory="empty",
              trust="sagemaker.amazonaws.com", domains=None, apps=(), app_inventory="empty",
              technique=TECHNIQUE):
    domain = {"DomainArn": DOMAIN_ARN, "DomainId": domain_id,
              "Status": domain_status, "AuthMode": domain_auth}
    snap = aws_snap([user("alice", *(grants if grants is not None else _grants()))],
                    [role("studio", trust)], [col("sagemaker_domain", domains if domains is not None else [domain]),
                    col("sagemaker_user_profile", profiles, profile_inventory),
                    col("sagemaker_app", apps, app_inventory)])
    return reached(real(snap, technique, include_unknown=True), ALICE, technique)


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


def test_unusable_domain_does_not_hide_another_domain():
    failed = {"DomainArn": DOMAIN_ARN.replace(DOMAIN_ID, "d-bad"),
              "DomainId": "d-bad", "Status": "Failed", "AuthMode": "IAM"}
    good = {"DomainArn": DOMAIN_ARN, "DomainId": DOMAIN_ID,
            "Status": "InService", "AuthMode": "IAM"}
    assert _evaluate(domains=[failed, good]) == {ROLE_ARN: "conditional"}


def test_domain_default_route_needs_same_domain_empty_apps_and_update_grant():
    grants = _grants(domain_update=True)
    assert _evaluate(grants=grants, technique=DOMAIN_TECHNIQUE) == {ROLE_ARN: "conditional"}
    assert ROLE_ARN not in _evaluate(technique=DOMAIN_TECHNIQUE)
    assert ROLE_ARN not in _evaluate(grants=grants, app_inventory="denied", technique=DOMAIN_TECHNIQUE)
    assert ROLE_ARN not in _evaluate(grants=grants, domain_auth="SSO", technique=DOMAIN_TECHNIQUE)
    assert ROLE_ARN not in _evaluate(grants=grants, domain_status="Failed", technique=DOMAIN_TECHNIQUE)
    assert ROLE_ARN not in _evaluate(grants=grants, apps=[{"DomainId": DOMAIN_ID,
        "AppType": "JupyterLab", "AppName": "default", "Status": "InService"}],
        app_inventory="collected", technique=DOMAIN_TECHNIQUE)
    assert ROLE_ARN not in _evaluate(grants=grants, apps=[{"AppType": "JupyterLab"}],
        app_inventory="collected", technique=DOMAIN_TECHNIQUE)
    assert _evaluate(grants=grants, apps=[{"DomainId": "d-other",
        "AppType": "JupyterLab", "AppName": "default", "Status": "InService"}],
        app_inventory="collected", technique=DOMAIN_TECHNIQUE) == {ROLE_ARN: "conditional"}
    assert ROLE_ARN not in _evaluate(grants=_grants(domain_update=True,
        app_arn=APP_ARN.replace("/" + NAME + "/", "/other/")), technique=DOMAIN_TECHNIQUE)
