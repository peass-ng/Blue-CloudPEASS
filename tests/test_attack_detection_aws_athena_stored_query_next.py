"""Synthetic derivatives of the live Athena workgroup and stored-query events."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
REGION = "us-east-1"
WORKGROUP = "synthetic-workgroup"
ARN = f"arn:aws:athena:{REGION}:{ACCOUNT}:workgroup/{WORKGROUP}"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
QUERY_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
NAMED_ID = "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
PRIVATE = "SYNTHETIC_PRIVATE_SQL_OR_BUCKET"


def event(name, params, response=None, *, minutes=0):
    return {"eventSource": "athena.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": f"11111111-1111-4111-8111-{minutes+1:012d}",
            "eventTime": (BASE + timedelta(minutes=minutes)).isoformat(),
            "userIdentity": {"accountId": ACCOUNT, "arn": ACTOR},
            "requestParameters": params, "responseElements": response}


CASES = [
    ("CreateWorkGroup", {"name": WORKGROUP, "configuration": {
        "resultConfiguration": {"outputLocation": "s3://synthetic-bucket/results/"}}},
     None, "request.athena_workgroup_result_output_configured"),
    ("UpdatePreparedStatement", {"workGroup": WORKGROUP,
        "statementName": "synthetic_statement", "queryStatement": "***OMITTED***"},
     None, "request.athena_prepared_statement_updated"),
    ("UpdateNamedQuery", {"namedQueryId": NAMED_ID, "name": "synthetic_named",
        "queryString": "***OMITTED***"},
     None, "request.athena_named_query_updated"),
]


@pytest.mark.parametrize("name,params,response,flag", CASES)
def test_athena_single_event_routes(name, params, response, flag):
    rule = Rule(id="synthetic-" + name, title="Synthetic Athena", description="Synthetic",
                level="medium", technique_id="synthetic", product="aws",
                selection={"event.source": "athena.amazonaws.com", "event.name": name,
                           "event.outcome": "success", flag: True})
    row = event(name, params, response)
    found = detect_aws_events([row], [rule])
    assert len(found) == 1
    assert found[0].target_id == (NAMED_ID if name == "UpdateNamedQuery" else ARN)
    assert PRIVATE not in str(found[0]) and "***OMITTED***" not in str(found[0])
    for changed in ({"errorCode": "AccessDeniedException"}, {"readOnly": True},
                    {"managementEvent": False}, {"eventCategory": "Data"},
                    {"recipientAccountId": "111111111111"},
                    {"eventSource": "wrong.amazonaws.com"}):
        bad = deepcopy(row); bad.update(changed)
        assert detect_aws_events([bad], [rule]) == []


def test_query_requires_bounded_same_actor_new_workgroup():
    create = event("CreateWorkGroup", {"name": WORKGROUP,
                   "configuration": {"resultConfiguration": {
                       "outputLocation": "s3://synthetic-bucket/results/"}}})
    start = event("StartQueryExecution", {"workGroup": WORKGROUP,
                  "queryString": "***OMITTED***", "clientRequestToken": PRIVATE},
                  {"queryExecutionId": QUERY_ID}, minutes=1)
    rule = Rule(id="synthetic-pair", title="Synthetic Athena pair", description="Synthetic",
                level="medium", technique_id="synthetic", product="aws",
                selection={"event.source": "athena.amazonaws.com",
                           "event.name": "StartQueryExecutionInNewWorkGroup",
                           "event.outcome": "success",
                           "request.athena_new_workgroup_query_started": True})
    found = detect_aws_events([start, create], [rule])
    assert len(found) == 1 and found[0].target_id == ARN
    assert found[0].evidence["correlation"]["create_workgroup_event_id"] == create["eventID"]
    assert PRIVATE not in str(found[0]) and "s3://" not in str(found[0])
    assert detect_aws_events([start], [rule]) == []
    for change in ("workGroup", "queryExecutionId"):
        bad = deepcopy(start)
        if change == "workGroup": bad["requestParameters"][change] = "other"
        else: bad["responseElements"][change] = "bad"
        assert detect_aws_events([create, bad], [rule]) == []
    bad = deepcopy(start); bad["userIdentity"]["arn"] = f"arn:aws:iam::{ACCOUNT}:user/other"
    assert detect_aws_events([create, bad], [rule]) == []
    bad = deepcopy(start); bad["eventTime"] = (BASE + timedelta(minutes=61)).isoformat()
    assert detect_aws_events([create, bad], [rule]) == []
    bad = deepcopy(start); bad["errorCode"] = "AccessDeniedException"
    assert detect_aws_events([create, bad], [rule]) == []
