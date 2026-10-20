"""Synthetic derivatives for five Customer Profiles management signals."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
REGION = "us-east-1"
PROFILE_A = "a" * 32
PROFILE_B = "b" * 32
CANARY = "SYNTHETIC_PRIVATE_LOOKUP_VALUE"
DOMAIN = "synthetic_domain"
STREAM = f"arn:aws:kinesis:{REGION}:{ACCOUNT}:stream/synthetic-stream"
CASES = [
    ("AddProfileKey", {"profileId": PROFILE_A, "keyName": "_ctrContactId",
                       "values": [CANARY]}, {"keyName": "_ctrContactId"},
     "request.customer_profiles_key_added"),
    ("CreateEventStream", {"eventStreamName": "synthetic-stream", "uri": STREAM},
     None, "request.customer_profiles_event_stream_created"),
    ("MergeProfiles", {"mainProfileId": PROFILE_A,
                       "profileIdsToBeMerged": [PROFILE_B]}, {"message": "merged"},
     "request.customer_profiles_profiles_merged"),
    ("UpdateDomain", {"matching": {"enabled": True,
                                   "autoMerging": {"enabled": True}}},
     {"matching": {"autoMerging": {"enabled": True}}},
     "request.customer_profiles_auto_merging_enabled"),
    ("DeleteDomain", {}, {"message": "deleted"},
     "request.customer_profiles_domain_deleted"),
]


def event(name: str, params: dict, response: dict | None) -> dict:
    return {"eventSource": "profile.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": "11111111-1111-4111-8111-111111111111",
            "eventTime": "2026-10-20T00:00:00Z",
            "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator",
                             "accountId": ACCOUNT},
            "requestParameters": {"domainName": DOMAIN, **params},
            "responseElements": response}


@pytest.mark.parametrize("name,params,response,signal", CASES)
@pytest.mark.parametrize("cloudtrail_initial_caps", [False, True])
def test_customer_profiles_dispatch(name: str, params: dict, response: dict | None,
                                    signal: str, cloudtrail_initial_caps: bool) -> None:
    rule = Rule(id="synthetic-" + name, title="Synthetic Customer Profiles route",
                description="Synthetic dispatch check", level="medium",
                technique_id="synthetic-route", product="aws",
                selection={"event.source": "profile.amazonaws.com",
                           "event.name": name, "event.outcome": "success", signal: True})
    row = event(name, params, response)
    if cloudtrail_initial_caps:
        def caps(value):
            if isinstance(value, dict):
                return {key[0].upper() + key[1:]: caps(item) for key, item in value.items()}
            if isinstance(value, list):
                return [caps(item) for item in value]
            return value
        row["requestParameters"] = caps(row["requestParameters"])
        row["responseElements"] = caps(response) if response is not None else None
    found = detect_aws_events([row], [rule])
    assert len(found) == 1
    assert found[0].actor_id and found[0].target_id
    assert CANARY not in str(found[0])
    for change in ({"errorCode": "AccessDeniedException"},
                   {"eventSource": "wrong.amazonaws.com"},
                   {"managementEvent": False},
                   {"recipientAccountId": "888888888888"} if name == "CreateEventStream" else
                   {"requestParameters": {**row["requestParameters"],
                                          "DomainName" if cloudtrail_initial_caps else "domainName": "invalid/domain"}}):
        denied = deepcopy(row)
        denied.update(change)
        assert detect_aws_events([denied], [rule]) == []
