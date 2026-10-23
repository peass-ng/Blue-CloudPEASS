"""Synthetic derivative of a Neptune Analytics graph data event."""

from copy import deepcopy

from peaso.attack_detection.aws_neptune_graph_data_b428 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
GRAPH = "g-synthetic9"
ARN = f"arn:aws:neptune-graph:us-east-1:{ACCOUNT}:graph/{GRAPH}"
QUERY = "MATCH (n) RETURN n.syntheticSecret"
RULE = Rule(
    id="synthetic-neptune-query", title="Synthetic graph query",
    description="Synthetic", level="medium", technique_id="synthetic-neptune-query",
    product="aws", selection={"event.source": "neptune-graph.amazonaws.com",
                              "event.name": "ExecuteQuery", "event.outcome": "success",
                              "request.neptune_graph_query_executed": True},
)


def _row():
    return {
        "eventSource": "neptune-graph.amazonaws.com", "eventName": "ExecuteQuery",
        "eventType": "AwsApiCall", "eventCategory": "Data",
        "managementEvent": False, "readOnly": False,
        "eventID": "synthetic-neptune-query-event",
        "eventTime": "2026-10-23T02:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-reader"},
        "requestParameters": {"requestType": "POST", "requestPayload": QUERY},
        "responseElements": {"responseCode": 200, "responseContent": "syntheticSecret"},
        "resources": [{"type": "AWS::NeptuneGraph::Graph", "accountId": ACCOUNT,
                       "ARN": ARN}],
    }


def test_graph_query_matches_without_query_or_results():
    row = _row()
    event = normalize(row)
    assert event is not None and event["target.id"].startswith("sha256:")
    assert QUERY not in str(event) and GRAPH not in str(event)
    hits = detect_aws_events([row], (RULE,))
    assert len(hits) == 1
    assert QUERY not in str(hits)
    row["readOnly"] = True
    assert normalize(row) is not None


def test_failed_or_wrong_graph_query_is_rejected():
    for change in (
        lambda row: row.update(errorCode="AccessDeniedException"),
        lambda row: row["responseElements"].update(responseCode=403),
        lambda row: row["resources"][0].update(accountId="111111111111"),
        lambda row: row["resources"][0].update(ARN=ARN.replace("us-east-1", "us-west-2")),
        lambda row: row.update(eventCategory="Management"),
        lambda row: row["requestParameters"].update(requestType="GET"),
    ):
        row = deepcopy(_row())
        change(row)
        assert normalize(row) is None
