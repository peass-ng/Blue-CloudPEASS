"""Synthetic derivatives for five live-verified Roles Anywhere signals."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
REGION = "us-east-1"
RESOURCE_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SENSITIVE = "SYNTHETIC_CERTIFICATE_OR_CRL_BYTES"
CASES = [
    ("CreateTrustAnchor", {"name": "synthetic-anchor",
                            "source": {"sourceType": "CERTIFICATE_BUNDLE",
                                       "sourceData": {"x509CertificateData": SENSITIVE}}},
     {"trustAnchor": {"trustAnchorId": RESOURCE_ID}},
     "request.rolesanywhere_bundle_anchor_created"),
    ("CreateProfile", {"name": "synthetic-profile",
                       "roleArns": [f"arn:aws:iam::{ACCOUNT}:role/synthetic-role"]},
     {"profile": {"profileId": RESOURCE_ID}},
     "request.rolesanywhere_profile_with_roles_created"),
    ("DisableCrl", {"crlId": RESOURCE_ID},
     {"crl": {"crlId": RESOURCE_ID, "enabled": False}},
     "request.rolesanywhere_crl_disabled"),
    ("UpdateCrl", {"crlId": RESOURCE_ID, "crlData": SENSITIVE},
     {"crl": {"crlId": RESOURCE_ID}},
     "request.rolesanywhere_crl_data_updated"),
    ("DeleteCrl", {"crlId": RESOURCE_ID}, None,
     "request.rolesanywhere_crl_deleted"),
]


def event(name: str, params: dict, response: dict | None) -> dict:
    return {"eventSource": "rolesanywhere.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": "11111111-1111-4111-8111-111111111111",
            "eventTime": "2026-10-20T00:00:00Z",
            "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator",
                             "accountId": ACCOUNT},
            "requestParameters": params, "responseElements": response}


@pytest.mark.parametrize("name,params,response,signal", CASES)
def test_rolesanywhere_dispatch(name: str, params: dict, response: dict | None,
                                signal: str) -> None:
    rule = Rule(id="synthetic-" + name, title="Synthetic Roles Anywhere route",
                description="Synthetic dispatch check", level="medium",
                technique_id="synthetic-route", product="aws",
                selection={"event.source": "rolesanywhere.amazonaws.com",
                           "event.name": name, "event.outcome": "success", signal: True})
    row = event(name, params, response)
    found = detect_aws_events([row], [rule])
    assert len(found) == 1
    assert found[0].actor_id and found[0].target_id
    assert SENSITIVE not in str(found[0])
    for change in ({"errorCode": "AccessDeniedException"},
                   {"eventSource": "wrong.amazonaws.com"},
                   {"managementEvent": False}):
        denied = deepcopy(row)
        denied.update(change)
        assert detect_aws_events([denied], [rule]) == []
