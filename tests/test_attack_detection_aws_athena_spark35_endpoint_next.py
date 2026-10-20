"""Synthetic derivative of the isolated Spark 3.5 cross-actor lab."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
REGION = "us-east-1"
WG = "synthetic-spark35-workgroup"
WG_ARN = f"arn:aws:athena:{REGION}:{ACCOUNT}:workgroup/{WG}"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-exec"
ADMIN = f"arn:aws:iam::{ACCOUNT}:user/synthetic-creator"
READER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-reader"
READER = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-reader/session"
SESSION = "spark-synthetic-0001"
SECRET = "SYNTHETIC_ENDPOINT_BEARER_TOKEN"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(name, request, response, minute, *, reader=False, read_only=False):
    identity = ({"type": "AssumedRole", "accountId": ACCOUNT, "arn": READER,
                 "sessionContext": {"sessionIssuer": {"type": "Role", "arn": READER_ROLE}}}
                if reader else {"type": "IAMUser", "accountId": ACCOUNT, "arn": ADMIN})
    return {"eventSource": "athena.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": read_only,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": f"11111111-1111-4111-8111-{minute+1:012d}",
            "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
            "userIdentity": identity, "requestParameters": request,
            "responseElements": response}


def fixtures():
    return [
        event("CreateWorkGroup", {"name": WG, "configuration": {
              "executionRole": ROLE, "engineVersion": {
                  "selectedEngineVersion": "Apache Spark version 3.5"}}}, None, 0),
        event("StartSession", {"workGroup": WG, "engineConfiguration": {}},
              {"sessionId": SESSION, "state": "CREATED"}, 1),
        event("GetSessionEndpoint", {"sessionId": SESSION}, None,
              2, reader=True, read_only=True),
    ]


def rules():
    return [Rule(id="synthetic-athena-spark35-endpoint", title="Synthetic Spark 3.5 endpoint",
                 description="Synthetic", level="high", technique_id="synthetic",
                 product="aws", selection={"event.source": "athena.amazonaws.com",
                     "event.name": "AthenaSpark35CrossActorGetSessionEndpoint",
                     "event.outcome": "success",
                     "request.athena_spark35_cross_actor_endpoint_requested": True})]


def test_other_actor_endpoint_matches_without_secret_or_session_id():
    assert len(detect_aws_events(fixtures(), rules())) == 1
    records = fixtures()
    records[2]["responseElements"] = {
        "endpointUrl": "https://synthetic.invalid", "authToken": SECRET}
    found = detect_aws_events(reversed(records), rules())
    assert len(found) == 1
    assert found[0].target_id == WG_ARN
    rendered = str(found)
    assert all(value not in rendered for value in (SECRET, SESSION, "synthetic.invalid"))
    assert found[0].evidence["correlation"]["source_event_id"] == fixtures()[1]["eventID"]


def test_endpoint_requires_exact_session_actor_engine_and_accepted_events():
    source = fixtures()
    cases = []
    for index in range(3):
        changed = deepcopy(source)
        changed[index]["errorCode"] = "AccessDeniedException"
        cases.append(changed)
    same_actor = deepcopy(source)
    same_actor[2]["userIdentity"] = deepcopy(source[1]["userIdentity"])
    cases.append(same_actor)
    wrong_session = deepcopy(source)
    wrong_session[2]["requestParameters"]["sessionId"] = "11111111-2222-4333-8444-555555555555"
    cases.append(wrong_session)
    wrong_engine = deepcopy(source)
    wrong_engine[0]["requestParameters"]["configuration"]["engineVersion"]["selectedEngineVersion"] = "PySpark engine version 3"
    cases.append(wrong_engine)
    wrong_account = deepcopy(source)
    wrong_account[2]["recipientAccountId"] = "111111111111"
    cases.append(wrong_account)
    late = deepcopy(source)
    late[2]["eventTime"] = (BASE + timedelta(hours=25)).isoformat()
    cases.append(late)
    for records in cases:
        assert detect_aws_events(records, rules()) == []
