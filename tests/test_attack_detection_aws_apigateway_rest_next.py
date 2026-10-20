"""Synthetic derivatives of five isolated API Gateway REST routes."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
REGION = "us-east-1"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
API_ID = "abcdefghij"
RESOURCE = "abc1234"
KEY_ID = "key1234567"
PLAN_ID = "plan123456"
SECRET = "SYNTHETIC_PARTIAL_KEY_OR_TEMPLATE"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
HEADER = "method.response.header.Access-Control-Allow-Origin"
POLICY = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke",
    "Resource": f"arn:aws:execute-api:{REGION}:{ACCOUNT}:{API_ID}/*"}]})
ROUTES = [
    ("ApiGatewayRestNewKeyAttachedToPlan", "request.apigateway_new_key_attached_to_plan"),
    ("ApiGatewayRestApiKeyValueRequested", "request.apigateway_api_key_value_requested"),
    ("ApiGatewayRestMethodResponsePublished", "request.apigateway_method_response_published"),
    ("ApiGatewayRestGatewayResponsePublished", "request.apigateway_gateway_response_published"),
    ("ApiGatewayRestWildcardPolicyPublished", "request.apigateway_wildcard_policy_published"),
]


def event(name, request, response, minute, *, read_only=False):
    return {"eventSource": "apigateway.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": read_only,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": f"11111111-1111-4111-8111-{minute+1:012d}",
            "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": ACTOR},
            "requestParameters": request, "responseElements": response}


def fixtures():
    return [
        event("CreateApiKey", {"createApiKeyInput": {"enabled": True,
              "name": "synthetic", "value": SECRET}}, {"id": KEY_ID, "value": SECRET}, 0),
        event("CreateUsagePlanKey", {"usagePlanId": PLAN_ID,
              "createUsagePlanKeyInput": {"keyId": KEY_ID, "keyType": "API_KEY"}},
              {"id": KEY_ID, "value": SECRET}, 1),
        event("GetApiKey", {"apiKey": KEY_ID, "includeValue": True}, None, 2, read_only=True),
        event("PutMethodResponse", {"restApiId": API_ID, "resourceId": RESOURCE,
              "httpMethod": "GET", "statusCode": "200",
              "putMethodResponseInput": {"responseParameters": {HEADER: False}}},
              {"statusCode": "200"}, 3),
        event("PutIntegrationResponse", {"restApiId": API_ID, "resourceId": RESOURCE,
              "httpMethod": "GET", "statusCode": "200",
              "putIntegrationResponseInput": {"responseParameters": {HEADER: "'https://synthetic.invalid'"},
                                              "responseTemplates": {"application/json": SECRET}}},
              {"statusCode": "200"}, 4),
        event("CreateDeployment", {"restApiId": API_ID,
              "createDeploymentInput": {"stageName": "lab"}}, {"id": "deploy0001"}, 5),
        event("UpdateGatewayResponse", {"restApiId": API_ID, "responseType": "DEFAULT_4XX",
              "updateGatewayResponseInput": {"patchOperations": [{"op": "replace",
                  "path": "/responseTemplates/application~1json", "value": SECRET}]}},
              {"responseType": "DEFAULT_4XX"}, 6),
        event("CreateDeployment", {"restApiId": API_ID,
              "createDeploymentInput": {"stageName": "lab"}}, {"id": "deploy0002"}, 7),
        event("UpdateRestApi", {"restApiId": API_ID,
              "updateRestApiInput": {"patchOperations": [{"op": "replace", "path": "/policy",
                                                       "value": POLICY}]}},
              {"policy": SECRET}, 8),
        event("CreateDeployment", {"restApiId": API_ID,
              "createDeploymentInput": {"stageName": "lab"}}, {"id": "deploy0003"}, 9),
    ]


def rules():
    return [Rule(id="synthetic-"+name, title="Synthetic API Gateway REST",
                 description="Synthetic", level="high", technique_id="synthetic",
                 product="aws", selection={"event.source": "apigateway.amazonaws.com",
                     "event.name": name, "event.outcome": "success", flag: True})
            for name, flag in ROUTES]


def test_five_routes_match_without_keys_templates_or_policy():
    found = detect_aws_events(reversed(fixtures()), rules())
    assert len(found) == 5
    assert {d.rule_id for d in found} == {r.id for r in rules()}
    rendered = str(found)
    assert SECRET not in rendered
    assert POLICY not in rendered
    assert "synthetic.invalid" not in rendered
    assert sum(d.rule_id.endswith("ApiGatewayRestMethodResponsePublished") for d in found) == 1


def test_routes_reject_errors_wrong_ids_and_missing_publish():
    source = fixtures()
    cases = []
    for index in (0, 1, 2, 3, 4, 6, 8):
        changed = deepcopy(source)
        changed[index]["errorCode"] = "AccessDeniedException"
        cases.append((changed, 4))
    bad_key = deepcopy(source)
    bad_key[1]["requestParameters"]["createUsagePlanKeyInput"]["keyId"] = "other12345"
    cases.append((bad_key, 4))
    no_value = deepcopy(source)
    no_value[2]["requestParameters"]["includeValue"] = False
    cases.append((no_value, 4))
    bad_header = deepcopy(source)
    bad_header[4]["requestParameters"]["putIntegrationResponseInput"]["responseParameters"] = {
        "method.response.header.Unrelated": "'x'"}
    cases.append((bad_header, 4))
    bad_policy = deepcopy(source)
    bad_policy[8]["requestParameters"]["updateRestApiInput"]["patchOperations"][0]["value"] = json.dumps({
        "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "execute-api:Invoke"}]})
    cases.append((bad_policy, 4))
    no_publish = deepcopy(source)
    no_publish[9]["errorCode"] = "BadRequestException"
    cases.append((no_publish, 4))
    for records, expected in cases:
        assert len(detect_aws_events(records, rules())) == expected


def test_malformed_event_source_does_not_abort_following_valid_record():
    malformed = deepcopy(fixtures()[0])
    malformed["eventSource"] = []
    found = detect_aws_events([malformed, fixtures()[2]], rules())
    assert len(found) == 1
