"""Synthetic derivatives of five live Customer Profiles management event shapes.

No profile content, source account, identifiers or CloudTrail record is stored here.
"""
from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
PID = "a" * 32
CASES = [
    ("CreateProfile", {"FirstName": "SYNTHETIC_PRIVATE_NAME"}, {"ProfileId": PID}, "profile_created"),
    ("UpdateProfile", {"ProfileId": PID, "LastName": "SYNTHETIC_PRIVATE_NAME"}, {"ProfileId": PID}, "profile_updated"),
    ("BatchPutProfileObject", {"ObjectTypeName": "SyntheticType", "Items": [{"Object": "SYNTHETIC_PRIVATE_BODY"}]}, {"Successful": [{"ItemId": "SYNTHETIC_PRIVATE_KEY"}], "Failed": []}, "profile_object_batch_ingested"),
    ("PutProfileObjectType", {"ObjectTypeName": "SyntheticType", "Fields": "SYNTHETIC_REDACTED", "Keys": "SYNTHETIC_REDACTED"}, {"ObjectTypeName": "SyntheticType"}, "profile_object_type_changed"),
    ("CreateUploadJob", {"DisplayName": "SYNTHETIC_PRIVATE_FILE", "Fields": "SYNTHETIC_REDACTED", "UniqueKey": "SYNTHETIC_PRIVATE_KEY"}, {"JobId": PID}, "upload_job_created"),
]


@pytest.mark.parametrize("name,params,response,flag", CASES)
def test_customer_profiles_write(name, params, response, flag):
    rule = Rule(id="synthetic-" + name, title="Synthetic Customer Profiles write",
                description="Synthetic dispatch", level="medium", technique_id="synthetic",
                product="aws", selection={"event.source": "profile.amazonaws.com",
                                          "event.name": name, "event.outcome": "success",
                                          "request.customer_profiles_" + flag: True})
    row = {"eventSource": "profile.amazonaws.com", "eventName": name,
           "eventCategory": "Management", "eventType": "AwsApiCall",
           "managementEvent": True, "readOnly": False,
           "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
           "eventID": "11111111-1111-4111-8111-111111111111",
           "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
           "requestParameters": {"DomainName": "synthetic_domain", **params},
           "responseElements": response}
    hits = detect_aws_events([row], [rule])
    assert len(hits) == 1 and hits[0].target_id
    assert detect_aws_events([{**row, "responseElements": None}], [rule])
    for secret in ("SYNTHETIC_PRIVATE_NAME", "SYNTHETIC_PRIVATE_BODY", "SYNTHETIC_PRIVATE_KEY", "SYNTHETIC_PRIVATE_FILE"):
        assert secret not in str(hits[0])
    for change in ({"errorCode": "AccessDeniedException"},
                   {"eventSource": "wrong.amazonaws.com"},
                   {"readOnly": True},
                   {"managementEvent": False},
                   {"requestParameters": {**row["requestParameters"], "DomainName": "bad/domain"}}):
        denied = deepcopy(row)
        denied.update(change)
        assert detect_aws_events([denied], [rule]) == []
    if name == "BatchPutProfileObject":
        assert detect_aws_events([{**row, "responseElements": {"Successful": [], "Failed": [{}]}}], [rule]) == []
