"""Synthetic derivatives of five live AppSync management-event shapes."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
REGION = "us-east-1"
API = "abcdefghijklmnopqrstuvwxyz"
ARN = f"arn:aws:appsync:{REGION}:{ACCOUNT}:apis/{API}"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
PRIVATE = "SYNTHETIC_PRIVATE_VALUE"

CASES = [
    ("UpdateGraphqlApi", {"apiId": API, "authenticationType": "API_KEY", "name": "synthetic"},
     {"graphqlApi": {"apiId": API, "arn": ARN, "authenticationType": "API_KEY"}},
     "request.appsync_api_key_auth_enabled"),
    ("CreateApiKey", {"apiId": API, "description": PRIVATE, "expires": 1800000000},
     {"apiKey": {"id": "***", "expires": 1800000000}},
     "request.appsync_api_key_created"),
    ("UpdateApiKey", {"apiId": API, "id": "***", "description": PRIVATE,
                      "expires": 1800000000},
     {"apiKey": {"id": "***", "expires": 1800000000}},
     "request.appsync_api_key_updated"),
    ("PutGraphqlApiEnvironmentVariables", {"apiId": API, "environmentVariables": "***"},
     {"environmentVariables": "***"}, "request.appsync_environment_replaced"),
    ("UpdateResolver", {"apiId": API, "typeName": "Query", "fieldName": "marker",
                        "dataSourceName": "SyntheticNone", "requestMappingTemplate": "***",
                        "responseMappingTemplate": "***"},
     {"resolver": {"resolverArn": ARN + "/types/Query/resolvers/marker",
                   "typeName": "Query", "fieldName": "marker",
                   "requestMappingTemplate": "***"}},
     "request.appsync_resolver_definition_updated"),
]


def event(name, request, response):
    return {"eventSource": "appsync.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": "11111111-1111-4111-8111-111111111111",
            "eventTime": "2026-01-01T00:00:00Z",
            "userIdentity": {"accountId": ACCOUNT, "arn": ACTOR},
            "requestParameters": request, "responseElements": response}


@pytest.mark.parametrize("name,params,response,flag", CASES)
def test_appsync_live_shape_and_negative_controls(name, params, response, flag):
    rule = Rule(id="synthetic-" + name, title="Synthetic AppSync", description="Synthetic",
                level="medium", technique_id="synthetic", product="aws",
                selection={"event.source": "appsync.amazonaws.com", "event.name": name,
                           "event.outcome": "success", flag: True})
    row = event(name, params, response)
    found = detect_aws_events([row], [rule])
    assert len(found) == 1 and found[0].target_id == ARN
    assert PRIVATE not in str(found[0]) and "***" not in str(found[0])
    for changed in ({"errorCode": "AccessDeniedException"}, {"readOnly": True},
                    {"eventCategory": "Data"}, {"managementEvent": False},
                    {"recipientAccountId": "111111111111"},
                    {"eventSource": "wrong.amazonaws.com"},
                    {"responseElements": None}):
        bad = deepcopy(row); bad.update(changed)
        assert detect_aws_events([bad], [rule]) == []
    bad = deepcopy(row); bad["requestParameters"]["apiId"] = "not-an-appsync-id"
    assert detect_aws_events([bad], [rule]) == []
    if name == "UpdateGraphqlApi":
        bad = deepcopy(row); bad["responseElements"]["graphqlApi"]["authenticationType"] = "AWS_IAM"
        assert detect_aws_events([bad], [rule]) == []
    if name == "UpdateResolver":
        bad = deepcopy(row); bad["responseElements"]["resolver"]["resolverArn"] = ARN + "/other"
        assert detect_aws_events([bad], [rule]) == []
