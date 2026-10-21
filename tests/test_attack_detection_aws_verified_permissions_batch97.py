"""Synthetic derivatives of an owned Verified Permissions lab; no live identifiers."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.aws_verified_permissions_batch97 import normalize_aws_verified_permissions_batch97
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
STORE = "synthetic-store"
POLICY = "synthetic-policy"
SOURCE = "synthetic-source"


def event(name, request, response=None, *, read=False):
    return {
        "eventSource": "verifiedpermissions.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "eventID": "synthetic-event",
        "eventTime": "2026-10-21T00:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def oidc():
    return {"openIdConnectConfiguration": {
        "issuer": "https://synthetic.example.invalid/issuer",
        "tokenSelection": {"identityTokenOnly": {"principalIdClaim": "sub"}},
    }}


CASES = [
    ("aws-vp-static-permit-policy-created", event(
        "CreatePolicy", {"policyStoreId": STORE},
        {"policyStoreId": STORE, "policyId": POLICY, "policyType": "STATIC", "effect": "Permit"})),
    ("aws-vp-policy-body-read", event(
        "BatchGetPolicy", {"policyStoreId": STORE, "policyId": POLICY}, read=True)),
    ("aws-vp-policy-store-alias-mapped", event(
        "CreatePolicyStoreAlias", {"policyStoreId": STORE, "aliasName": "synthetic-alias"},
        {"policyStoreId": STORE, "aliasName": "synthetic-alias"})),
    ("aws-vp-schema-written", event(
        "PutSchema", {"policyStoreId": STORE}, {"policyStoreId": STORE})),
    ("aws-vp-validation-disabled", event(
        "UpdatePolicyStore", {"policyStoreId": STORE, "validationSettings": {"mode": "OFF"}},
        {"policyStoreId": STORE})),
    ("aws-vp-policy-deleted", event(
        "DeletePolicy", {"policyStoreId": STORE, "policyId": POLICY})),
    ("aws-vp-policy-store-deleted", event(
        "DeletePolicyStore", {"policyStoreId": STORE})),
    ("aws-vp-oidc-identity-source-created", event(
        "CreateIdentitySource", {"policyStoreId": STORE, "configuration": oidc()},
        {"policyStoreId": STORE, "identitySourceId": SOURCE})),
    ("aws-vp-oidc-identity-source-updated", event(
        "UpdateIdentitySource", {"policyStoreId": STORE, "identitySourceId": SOURCE,
                                 "updateConfiguration": oidc()},
        {"policyStoreId": STORE, "identitySourceId": SOURCE})),
]


def rules():
    return [rule for rule in load_rules(product="aws")
            if rule.technique_id.startswith("aws-vp-")]


def test_all_nine_synthetic_events_match_corresponding_rules():
    wanted = {name for name, _ in CASES}
    assert len(rules()) == len(CASES)
    assert {hit.technique_id for hit in detect_aws_events([value for _, value in CASES], rules())} == wanted


def test_failed_and_wrong_category_operations_do_not_match():
    for _, base in CASES:
        for modification in (lambda x: x.update(errorCode="ResourceNotFoundException"),
                             lambda x: x.update(eventCategory="Data"),
                             lambda x: x.update(readOnly=not x["readOnly"]),
                             lambda x: x["requestParameters"].update(policyStoreId="")):
            bad = deepcopy(base)
            modification(bad)
            assert detect_aws_events([bad], rules()) == []


def test_specific_incomplete_operations_do_not_claim_effect():
    variants = [
        (0, lambda x: x["responseElements"].update(effect="Forbid")),
        (0, lambda x: x["responseElements"].update(policyType="TEMPLATE_LINKED")),
        (2, lambda x: x["responseElements"].update(policyStoreId="other-store")),
        (4, lambda x: x["requestParameters"]["validationSettings"].update(mode="STRICT")),
        (7, lambda x: x["requestParameters"]["configuration"]["openIdConnectConfiguration"].update(issuer="")),
        (8, lambda x: x["responseElements"].update(identitySourceId="other-source")),
    ]
    for index, change in variants:
        bad = deepcopy(CASES[index][1])
        change(bad)
        assert detect_aws_events([bad], rules()) == []


def test_get_policy_read_is_covered_and_invalid_shape_ignored():
    get = deepcopy(CASES[1][1])
    get["eventName"] = "GetPolicy"
    assert normalize_aws_verified_permissions_batch97(get)["request.vp_policy_body_read_requested"] is True
    assert {hit.technique_id for hit in detect_aws_events([get], rules())} == {"aws-vp-policy-body-read"}
    get["eventName"] = []
    assert normalize_aws_verified_permissions_batch97(get) is None
