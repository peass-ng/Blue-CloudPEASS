"""Synthetic derivatives for five live Athena PySpark 3 route signals."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
REGION = "us-east-1"
WG = "synthetic-spark-workgroup"
WG_ARN = f"arn:aws:athena:{REGION}:{ACCOUNT}:workgroup/{WG}"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-execution"
ADMIN = f"arn:aws:iam::{ACCOUNT}:user/synthetic-creator"
READER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-reader"
READER = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-reader/session"
NOTEBOOK = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
SESSION = "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee"
PRIVATE = "SYNTHETIC_BEARER_TOKEN_OR_CODE"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
ROUTES = [
    ("AthenaSparkExecutionRoleWorkGroupCreated", "request.athena_spark_execution_role_bound"),
    ("AthenaSparkStartSession", "request.athena_new_role_workgroup_session_started"),
    ("AthenaSparkUpdateNotebook", "request.athena_cross_actor_notebook_updated"),
    ("AthenaSparkCreatePresignedNotebookUrl", "request.athena_cross_actor_notebook_url_requested"),
    ("AthenaSparkStartCalculationExecution", "request.athena_cross_actor_calculation_submitted"),
]


def event(name, request, response, minute, *, reader=False):
    identity = ({"type": "AssumedRole", "accountId": ACCOUNT, "arn": READER,
                 "sessionContext": {"sessionIssuer": {"type": "Role", "arn": READER_ROLE}}}
                if reader else {"type": "IAMUser", "accountId": ACCOUNT, "arn": ADMIN})
    return {"eventSource": "athena.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": f"11111111-1111-4111-8111-{minute+1:012d}",
            "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
            "userIdentity": identity, "requestParameters": request,
            "responseElements": response}


def fixtures():
    return [
        event("CreateWorkGroup", {"name": WG, "configuration": {
              "executionRole": ROLE, "engineVersion": {
                  "selectedEngineVersion": "PySpark engine version 3"}}}, None, 0),
        event("CreateNotebook", {"workGroup": WG, "name": "synthetic-notebook"},
              {"notebookId": NOTEBOOK}, 1),
        event("UpdateNotebook", {"notebookId": NOTEBOOK, "payload": PRIVATE},
              None, 2, reader=True),
        event("StartSession", {"workGroup": WG}, {"sessionId": SESSION, "state": "CREATED"}, 3),
        event("CreatePresignedNotebookUrl", {"sessionId": SESSION},
              {"authToken": PRIVATE, "notebookUrl": "https://synthetic.invalid/?authToken="+PRIVATE},
              4, reader=True),
        event("StartCalculationExecution", {"sessionId": SESSION, "codeBlock": PRIVATE},
              {"calculationExecutionId": "11111111-2222-4333-8444-555555555555"},
              5, reader=True),
    ]


def rules():
    return [Rule(id="synthetic-"+name, title="Synthetic Athena Spark",
                 description="Synthetic", level="medium", technique_id="synthetic",
                 product="aws", selection={"event.source": "athena.amazonaws.com",
                     "event.name": name, "event.outcome": "success", flag: True})
            for name, flag in ROUTES]


def test_five_routes_match_without_secret_or_session_identifiers():
    found = detect_aws_events(reversed(fixtures()), rules())
    assert len(found) == 5
    assert {d.rule_id for d in found} == {r.id for r in rules()}
    assert all(d.target_id == WG_ARN for d in found)
    rendered = str(found)
    assert all(value not in rendered for value in (PRIVATE, NOTEBOOK, SESSION, "synthetic.invalid"))
    assert {d.evidence["correlation"]["source_event_id"] for d in found
            if "correlation" in d.evidence} == {
                fixtures()[0]["eventID"], fixtures()[1]["eventID"], fixtures()[3]["eventID"]}


def test_cross_actor_routes_require_distinct_successful_principals_and_ids():
    source = fixtures()
    for index in (2, 4, 5):
        same_actor = deepcopy(source)
        same_actor[index]["userIdentity"] = deepcopy(source[0]["userIdentity"])
        assert len(detect_aws_events(same_actor, rules())) == 4
        failed = deepcopy(source)
        failed[index]["errorCode"] = "AccessDeniedException"
        assert len(detect_aws_events(failed, rules())) == 4
        wrong = deepcopy(source)
        field = "notebookId" if index == 2 else "sessionId"
        wrong[index]["requestParameters"][field] = "11111111-2222-4333-8444-555555555555"
        assert len(detect_aws_events(wrong, rules())) == 4
    late = deepcopy(source)
    late[5]["eventTime"] = (BASE + timedelta(hours=25)).isoformat()
    assert len(detect_aws_events(late, rules())) == 4


def test_role_binding_requires_supported_engine_and_same_account_role():
    source = fixtures()
    for config in ({"engineVersion": {"selectedEngineVersion": "Apache Spark version 3.5"},
                    "executionRole": ROLE},
                   {"engineVersion": {"selectedEngineVersion": "PySpark engine version 3"},
                    "executionRole": "arn:aws:iam::111111111111:role/foreign"}):
        changed = deepcopy(source)
        changed[0]["requestParameters"]["configuration"] = config
        assert all(d.rule_id != rules()[0].id for d in detect_aws_events(changed, rules()))
