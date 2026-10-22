"""Synthetic AppStream user pool CloudTrail derivatives."""

from copy import deepcopy

from peaso.attack_detection.aws_appstream_userpool_batch201 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"


def event(name, request, response=None):
    return {
        "eventSource": "appstream.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-" + name, "eventTime": "2026-10-22T00:00:00Z",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-admin"},
        "requestParameters": request, "responseElements": response,
    }


def examples():
    hidden = "HIDDEN_DUE_TO_SECURITY_REASONS"
    return [
        event("CreateUser", {"userName": hidden, "authenticationType": "USERPOOL", "messageAction": "SUPPRESS"}),
        event("BatchAssociateUserStack", {"userStackAssociations": [
            {"stackName": "synthetic-stack", "userName": hidden,
             "authenticationType": "USERPOOL", "sendEmailNotification": False},
        ]}, {"errors": []}),
        event("EnableUser", {"userName": hidden, "authenticationType": "USERPOOL"}),
    ]


def rules():
    return tuple(Rule(
        id=f"20100000-0000-4000-8000-{index:012d}", title=name, level="low",
        description=name, technique_id="aws-appstream-userpool-" + name.lower(),
        product="aws", selection={
            "event.source": "appstream.amazonaws.com", "event.name": name,
            "event.outcome": "success", flag: True,
        },
    ) for index, (name, flag) in enumerate([
        ("CreateUser", "request.appstream_userpool_suppressed_create"),
        ("BatchAssociateUserStack", "request.appstream_userpool_stack_associated"),
        ("EnableUser", "request.appstream_userpool_user_enabled"),
    ], 1))


def test_three_controls_match_and_redact_user_and_stack():
    rows = examples()
    signals = [normalize(row) for row in rows]
    assert all(signals)
    assert len(detect_aws_events(rows, rules())) == 3
    for signal in signals:
        assert signal["target.id"].startswith("sha256:")
        assert "synthetic-stack" not in str(signal)
        assert "userName" not in str(signal)
        assert "HIDDEN_DUE_TO_SECURITY_REASONS" not in str(signal)


def test_inband_failure_and_other_negative_variants():
    base = examples()
    variants = []
    for field, value in [("errorCode", "AccessDeniedException"),
                         ("eventCategory", "Data"), ("readOnly", True),
                         ("eventSource", "other.amazonaws.com")]:
        changed = deepcopy(base[1]); changed[field] = value; variants.append(changed)
    changed = deepcopy(base[1]); changed["responseElements"]["errors"] = [{"errorCode": "USER_NOT_FOUND"}]
    variants.append(changed)
    changed = deepcopy(base[1]); changed["responseElements"] = None; variants.append(changed)
    changed = deepcopy(base[1]); changed["requestParameters"]["userStackAssociations"][0]["authenticationType"] = "SAML"
    variants.append(changed)
    changed = deepcopy(base[0]); changed["requestParameters"]["messageAction"] = None; variants.append(changed)
    changed = deepcopy(base[2]); changed["requestParameters"]["authenticationType"] = "SAML"
    variants.append(changed)
    changed = deepcopy(base[1]); changed["userIdentity"]["accountId"] = "888888888888"
    variants.append(changed)
    assert all(normalize(row) is None for row in variants)
    assert detect_aws_events(variants, rules()) == []
