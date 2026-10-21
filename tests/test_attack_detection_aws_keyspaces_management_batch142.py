"""Keyspaces signals from accepted management events and bounded request evidence."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from peaso.attack_detection.rules import detect_aws_events, load_rules


IDS = {f"aws-keyspaces-{name}" for name in (
    "cdc-table-created", "streams-listed", "stream-read", "pitr-disabled",
    "cdc-disabled", "table-dropped",
)}
ACCOUNT = "999999999999"
REGION = "us-east-1"
KEYSPACE = "synthetic_lab"
TABLE = "synthetic_records"
STREAM = (f"arn:aws:cassandra:{REGION}:{ACCOUNT}:/keyspace/{KEYSPACE}/table/{TABLE}"
          "/stream/2026-10-21T12:00:00.000")


def event(name, request, *, read_only=False, event_id=None):
    return {
        "eventVersion": "1.11", "eventSource": "cassandra.amazonaws.com",
        "eventName": name, "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read_only,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": event_id or name, "eventTime": "2026-10-21T12:00:00Z",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": request,
        "responseElements": None,
    }


def candidates():
    names = {"keyspaceName": KEYSPACE, "tableName": TABLE}
    quoted = f'"{KEYSPACE}"."{TABLE}"'
    return [
        event("CreateTable", {**names, "rawquery": f"CREATE TABLE {quoted}(tenant text, PRIMARY KEY(tenant)) WITH cdc = true"}),
        event("ListStreams", names, read_only=True),
        event("GetStream", {"streamArn": STREAM}, read_only=True),
        event("AlterTable", {**names, "rawquery": f"ALTER TABLE {quoted} WITH custom_properties = {{'point_in_time_recovery':{{'status':'disabled'}}}}"}, event_id="pitr"),
        event("AlterTable", {**names, "rawquery": f"ALTER TABLE {quoted} WITH cdc = false"}, event_id="cdc-off"),
        event("DropTable", {**names, "rawquery": f"DROP TABLE {quoted}"}),
    ]


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 6
    return selected


def test_six_accepted_operations_match_distinct_rules():
    hits = detect_aws_events(candidates(), rules())
    assert len(hits) == 6
    assert len(Counter(hit.rule_id for hit in hits)) == 6
    assert all(hit.account_id == ACCOUNT and hit.actor_id.endswith("/synthetic") for hit in hits)
    assert all("rawquery" not in hit.evidence and "shardIterator" not in hit.evidence for hit in hits)


def test_errors_foreign_streams_and_unrelated_alterations_do_not_match():
    selected = rules()
    denied = deepcopy(candidates()[0]); denied["errorCode"] = "AccessDenied"
    foreign = deepcopy(candidates()[2]); foreign["requestParameters"]["streamArn"] = STREAM.replace(ACCOUNT, "111111111111")
    altered = deepcopy(candidates()[3]); altered["requestParameters"]["rawquery"] = (
        f'ALTER TABLE "{KEYSPACE}"."{TABLE}" WITH custom_properties = '
        "{'point_in_time_recovery':{'status':'enabled'}}")
    wrong_table = deepcopy(candidates()[5]); wrong_table["requestParameters"]["rawquery"] = (
        f'DROP TABLE "{KEYSPACE}"."other_table"')
    bad_category = deepcopy(candidates()[1]); bad_category["eventCategory"] = "Data"
    assert detect_aws_events([denied, foreign, altered, wrong_table, bad_category], selected) == []


def test_one_alteration_can_disable_pitr_and_cdc_together():
    row = candidates()[3]
    row["requestParameters"]["rawquery"] += " AND cdc = false"
    found = detect_aws_events([row], rules())
    assert {hit.technique_id for hit in found} == {
        "aws-keyspaces-pitr-disabled", "aws-keyspaces-cdc-disabled",
    }
