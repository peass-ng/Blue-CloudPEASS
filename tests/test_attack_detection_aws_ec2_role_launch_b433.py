"""Synthetic derivatives of isolated EC2 role-bearing launch events."""

from copy import deepcopy

from peaso.attack_detection.aws_ec2_role_launch_b433 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
PROFILE = f"arn:aws:iam::{ACCOUNT}:instance-profile/synthetic-private-profile"
SECRET = "<synthetic-private-user-data>"


def row(name):
    if name == "CreateLaunchTemplate":
        request = {"CreateLaunchTemplateRequest": {
            "LaunchTemplateName": "synthetic-template",
            "LaunchTemplateData": {"IamInstanceProfile": {"Arn": PROFILE},
                                   "UserData": SECRET}}}
        response = {"CreateLaunchTemplateResponse": {"launchTemplate": {
            "launchTemplateId": "lt-" + "a" * 17,
            "launchTemplateName": "synthetic-template"}}}
    else:
        request = {"launchSpecification": {
            "iamInstanceProfile": {"arn": PROFILE}, "userData": SECRET},
            "instanceCount": 1}
        response = {"spotInstanceRequestSet": {"items": [{
            "spotInstanceRequestId": "sir-zzzz1234", "state": "open"}]}}
    return {
        "eventSource": "ec2.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "eventID": "synthetic-" + name, "eventTime": "2026-10-23T03:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def test_role_and_user_data_launch_routes_match_without_private_values():
    for name, marker in (
        ("CreateLaunchTemplate", "request.ec2_role_user_data_template_created"),
        ("RequestSpotInstances", "request.ec2_role_user_data_spot_requested"),
    ):
        raw = row(name)
        normalized = normalize(raw)
        assert normalized is not None and normalized[marker] is True
        assert PROFILE not in str(normalized) and SECRET not in str(normalized)
        rule = Rule(id=name, title=name, description="Synthetic", level="high",
                    technique_id=name, product="aws",
                    selection={"event.source": "ec2.amazonaws.com",
                               "event.name": name, "event.outcome": "success",
                               marker: True})
        hits = detect_aws_events([raw], (rule,))
        assert len(hits) == 1 and SECRET not in str(hits)


def test_failed_or_missing_role_launch_routes_do_not_match():
    for name in ("CreateLaunchTemplate", "RequestSpotInstances"):
        for change in (
            lambda x: x.update(errorCode="UnauthorizedOperation"),
            lambda x: x["userIdentity"].update(accountId="111111111111"),
            lambda x: x.update(readOnly=True),
        ):
            candidate = deepcopy(row(name))
            change(candidate)
            assert normalize(candidate) is None
        candidate = row(name)
        data = (candidate["requestParameters"]["CreateLaunchTemplateRequest"]["LaunchTemplateData"]
                if name == "CreateLaunchTemplate"
                else candidate["requestParameters"]["launchSpecification"])
        data.pop("UserData" if name == "CreateLaunchTemplate" else "userData")
        assert normalize(candidate) is None
        candidate = row(name)
        data = (candidate["requestParameters"]["CreateLaunchTemplateRequest"]["LaunchTemplateData"]
                if name == "CreateLaunchTemplate"
                else candidate["requestParameters"]["launchSpecification"])
        data.pop("IamInstanceProfile" if name == "CreateLaunchTemplate" else "iamInstanceProfile")
        assert normalize(candidate) is None
    candidate = row("CreateLaunchTemplate")
    candidate["responseElements"]["CreateLaunchTemplateResponse"]["launchTemplate"]["launchTemplateName"] = "other"
    assert normalize(candidate) is None
    candidate = row("RequestSpotInstances")
    candidate["responseElements"]["spotInstanceRequestSet"]["items"] = []
    assert normalize(candidate) is None
