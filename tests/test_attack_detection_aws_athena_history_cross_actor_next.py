"""Synthetic derivatives of five live Athena cross-actor history reads."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
REGION = "us-east-1"
WORKGROUP = "synthetic-workgroup"
ARN = f"arn:aws:athena:{REGION}:{ACCOUNT}:workgroup/{WORKGROUP}"
QID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CREATOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-creator"
READER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-reader"
READER = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-reader/session"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
PRIVATE = "SYNTHETIC_PRIVATE_SQL_OR_ROWS"

READS = [
    ("ListQueryExecutions", {"workGroup": WORKGROUP},
     "request.athena_cross_actor_query_listed"),
    ("GetQueryExecution", {"queryExecutionId": QID},
     "request.athena_cross_actor_query_execution_read"),
    ("BatchGetQueryExecution", {"queryExecutionIds": [QID]},
     "request.athena_cross_actor_batch_query_execution_read"),
    ("GetQueryResults", {"queryExecutionId": QID},
     "request.athena_cross_actor_query_results_read"),
    ("GetQueryRuntimeStatistics", {"queryExecutionId": QID},
     "request.athena_cross_actor_runtime_statistics_read"),
]


def event(name, params, response, *, minute=0, creator=False):
    user = ({"type": "IAMUser", "accountId": ACCOUNT, "arn": CREATOR}
            if creator else {"type": "AssumedRole", "accountId": ACCOUNT,
                             "arn": READER, "sessionContext": {
                                 "sessionIssuer": {"type": "Role", "arn": READER_ROLE}}})
    return {"eventSource": "athena.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": not creator,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": f"11111111-1111-4111-8111-{minute+1:012d}",
            "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
            "userIdentity": user, "requestParameters": params,
            "responseElements": response}


@pytest.mark.parametrize("name,params,flag", READS)
def test_cross_actor_history_read(name, params, flag):
    start = event("StartQueryExecution", {"workGroup": WORKGROUP,
                  "queryString": "***OMITTED***", "clientRequestToken": PRIVATE},
                  {"queryExecutionId": QID}, creator=True)
    read = event(name, params, {"private": PRIVATE}, minute=1)
    rule = Rule(id="synthetic-" + name, title="Synthetic Athena history",
                description="Synthetic", level="medium", technique_id="synthetic",
                product="aws", selection={"event.source": "athena.amazonaws.com",
                    "event.name": "AthenaCrossActor" + name,
                    "event.outcome": "success", flag: True})
    found = detect_aws_events([read, start], [rule])
    assert len(found) == 1 and found[0].target_id == ARN
    assert found[0].evidence["correlation"]["start_query_event_id"] == start["eventID"]
    assert PRIVATE not in str(found[0]) and QID not in str(found[0])
    assert detect_aws_events([read], [rule]) == []
    for changed in ({"errorCode": "InvalidRequestException"}, {"readOnly": False},
                    {"eventCategory": "Data"}, {"recipientAccountId": "111111111111"},
                    {"eventSource": "wrong.amazonaws.com"}):
        bad = deepcopy(read); bad.update(changed)
        assert detect_aws_events([start, bad], [rule]) == []
    bad = deepcopy(read); bad["userIdentity"] = deepcopy(start["userIdentity"])
    assert detect_aws_events([start, bad], [rule]) == []
    bad = deepcopy(read); bad["eventTime"] = (BASE + timedelta(hours=25)).isoformat()
    assert detect_aws_events([start, bad], [rule]) == []
    bad = deepcopy(read)
    if name == "ListQueryExecutions": bad["requestParameters"]["workGroup"] = "other"
    elif name == "BatchGetQueryExecution": bad["requestParameters"]["queryExecutionIds"] = ["ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"]
    else: bad["requestParameters"]["queryExecutionId"] = "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert detect_aws_events([start, bad], [rule]) == []
