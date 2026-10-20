"""Synthetic derivatives for AppSync signed HTTP role binding."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
REGION = "us-east-1"
API_ID = "a" * 26
API_ARN = f"arn:aws:appsync:{REGION}:{ACCOUNT}:apis/{API_ID}"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-appsync-exec"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-creator"
SECRET = "SYNTHETIC_RESOLVER_SECRET"
HTTP = {"endpoint": "https://sts.us-east-1.amazonaws.com",
        "authorizationConfig": {"authorizationType": "AWS_IAM",
            "awsIamConfig": {"signingRegion": REGION, "signingServiceName": "sts"}}}


def event(name, source_name, index):
    return {"eventSource": "appsync.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": f"11111111-1111-4111-8111-{index:012d}",
            "eventTime": "2026-01-01T00:00:00Z",
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": ACTOR},
            "requestParameters": {"apiId": API_ID, "name": source_name, "type": "HTTP",
                                  "serviceRoleArn": ROLE, "httpConfig": deepcopy(HTTP),
                                  "requestMappingTemplate": SECRET},
            "responseElements": {"dataSource": {
                "dataSourceArn": f"{API_ARN}/datasources/{source_name}",
                "name": source_name, "type": "HTTP", "serviceRoleArn": ROLE,
                "httpConfig": deepcopy(HTTP)}}}


def rules():
    return [Rule(id="synthetic-" + name, title="Synthetic AppSync role",
                 description="Synthetic", level="high", technique_id="synthetic",
                 product="aws", selection={"event.source": "appsync.amazonaws.com",
                     "event.name": name, "event.outcome": "success", flag: True})
            for name, flag in (
                ("CreateDataSource", "request.appsync_signed_http_role_data_source_created"),
                ("UpdateDataSource", "request.appsync_signed_http_role_data_source_updated"))]


def test_two_signed_role_routes_match_without_endpoint_role_or_template():
    records = [event("CreateDataSource", "SyntheticRole", 1),
               event("UpdateDataSource", "SyntheticChange", 2)]
    found = detect_aws_events(records, rules())
    assert len(found) == 2
    assert {d.rule_id for d in found} == {r.id for r in rules()}
    assert {d.target_id for d in found} == {
        f"{API_ARN}/datasources/SyntheticRole", f"{API_ARN}/datasources/SyntheticChange"}
    rendered = str(found)
    assert SECRET not in rendered
    assert ROLE not in rendered
    assert HTTP["endpoint"] not in rendered


def test_role_binding_rejects_failed_mismatched_and_unsigned_sources():
    source = event("CreateDataSource", "SyntheticRole", 1)
    variants = []
    for field, value in (("serviceRoleArn", "arn:aws:iam::111111111111:role/foreign"),
                         ("type", "NONE")):
        changed = deepcopy(source)
        changed["requestParameters"][field] = value
        variants.append(changed)
    bad_endpoint = deepcopy(source)
    bad_endpoint["requestParameters"]["httpConfig"]["endpoint"] = "https://synthetic.invalid"
    variants.append(bad_endpoint)
    bad_auth = deepcopy(source)
    bad_auth["requestParameters"]["httpConfig"]["authorizationConfig"] = {}
    variants.append(bad_auth)
    wrong_response = deepcopy(source)
    wrong_response["responseElements"]["dataSource"]["serviceRoleArn"] = "arn:aws:iam::111111111111:role/other"
    variants.append(wrong_response)
    failed = deepcopy(source)
    failed["errorCode"] = "AccessDeniedException"
    variants.append(failed)
    malformed_endpoint = deepcopy(source)
    malformed_endpoint["requestParameters"]["httpConfig"]["endpoint"] = "https://["
    variants.append(malformed_endpoint)
    for record in variants:
        assert detect_aws_events([record], rules()) == []
