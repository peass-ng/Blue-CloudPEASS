"""Synthetic derivatives of AppSync read/function/introspection live events."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
REGION = "us-east-1"
API = "abcdefghijklmnopqrstuvwxyz"
ARN = f"arn:aws:appsync:{REGION}:{ACCOUNT}:apis/{API}"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
FUNCTION = "syntheticfunction123"
PRIVATE = "SYNTHETIC_PRIVATE_VALUE"

CASES = [
    ("GetGraphqlApiEnvironmentVariables", {"apiId": API}, None,
     "request.appsync_environment_read", True),
    ("ListApiKeys", {"apiId": API}, None,
     "request.appsync_api_keys_listed", True),
    ("GetIntrospectionSchema", {"apiId": API, "format": "SDL"}, None,
     "request.appsync_schema_export_requested", True),
    ("UpdateFunction", {"apiId": API, "functionId": FUNCTION,
                        "name": "SyntheticFunction", "responseMappingTemplate": "***"},
     {"functionConfiguration": {"functionId": FUNCTION,
                                 "functionArn": ARN + "/functions/" + FUNCTION,
                                 "name": "SyntheticFunction", "code": PRIVATE}},
     "request.appsync_function_definition_updated", False),
    ("UpdateGraphqlApi", {"apiId": API, "name": "synthetic",
                          "authenticationType": "API_KEY", "introspectionConfig": "ENABLED"},
     {"graphqlApi": {"apiId": API, "arn": ARN, "introspectionConfig": "ENABLED"}},
     "request.appsync_introspection_enabled", False),
]


def event(name, params, response, read):
    return {"eventSource": "appsync.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": read,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": "11111111-1111-4111-8111-111111111111",
            "eventTime": "2026-01-01T00:00:00Z",
            "userIdentity": {"accountId": ACCOUNT, "arn": ACTOR},
            "requestParameters": params, "responseElements": response}


@pytest.mark.parametrize("name,params,response,flag,read", CASES)
def test_appsync_read_and_function_signals(name, params, response, flag, read):
    rule = Rule(id="synthetic-" + name, title="Synthetic AppSync", description="Synthetic",
                level="medium", technique_id="synthetic", product="aws",
                selection={"event.source": "appsync.amazonaws.com", "event.name": name,
                           "event.outcome": "success", flag: True})
    row = event(name, params, response, read)
    found = detect_aws_events([row], [rule])
    assert len(found) == 1 and found[0].target_id == ARN
    assert PRIVATE not in str(found[0]) and "***" not in str(found[0])
    for changed in ({"errorCode": "AccessDeniedException"}, {"readOnly": not read},
                    {"eventCategory": "Data"}, {"managementEvent": False},
                    {"recipientAccountId": "111111111111"},
                    {"eventSource": "wrong.amazonaws.com"}):
        bad = deepcopy(row); bad.update(changed)
        assert detect_aws_events([bad], [rule]) == []
    bad = deepcopy(row); bad["requestParameters"]["apiId"] = "wrong"
    assert detect_aws_events([bad], [rule]) == []
    if name == "UpdateFunction":
        bad = deepcopy(row)
        bad["responseElements"]["functionConfiguration"]["functionArn"] = ARN + "/other"
        assert detect_aws_events([bad], [rule]) == []
    if name == "UpdateGraphqlApi":
        bad = deepcopy(row)
        bad["responseElements"]["graphqlApi"]["introspectionConfig"] = "DISABLED"
        assert detect_aws_events([bad], [rule]) == []
