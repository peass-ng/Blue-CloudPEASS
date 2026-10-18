"""Inert activity projection tests forbid cached/serialized payload and secrets."""
import json
from datetime import datetime, timezone, timedelta

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber

from peaso.collectors import aws

REGION = "us-east-1"
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
MARKER = "INERT_ACTIVITY_PAYLOAD_DO_NOT_CACHE"


def raw_event():
    payload = {"userIdentity": {"arn": "arn:aws:iam::123456789012:user/reviewer", "type": "IAMUser", "sessionContext": {"private": MARKER}},
        "requestParameters": {"secret": MARKER}, "responseElements": {"Token": MARKER}, "eventName": "ListUsers", "eventTime": NOW.isoformat()}
    return {"EventId": "12345678-1234-1234-1234-123456789012", "EventName": "ListUsers", "EventTime": NOW, "CloudTrailEvent": json.dumps(payload)}


def test_transport_projects_before_cache_future_copy_or_snapshot(monkeypatch):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name=REGION)
    client = session.client("cloudtrail", region_name=REGION)
    stub = Stubber(client)
    arguments = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "ListUsers"}], "StartTime": NOW-timedelta(days=1), "EndTime": NOW}
    stub.add_response("lookup_events", {"Events": [raw_event()]}, arguments)
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    with stub:
        requests = aws.Requests({}, sleep=lambda _: None)
        response = requests.call(session, "cloudtrail", REGION, "lookup_events", **arguments)
        assert set(response["Events"][0]) == {"ActorArn", "ActorType", "EventName", "EventTime", "EventId"}
        assert MARKER not in json.dumps(response)
        assert "CloudTrailEvent" not in json.dumps(response)
        again = requests.call(session, "cloudtrail", REGION, "lookup_events", **arguments)
        assert again == response
        assert requests.calls == requests.activity_lookup_calls == 1
        assert all(MARKER not in json.dumps(future.result()) for future in requests._cache.values())
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("attributes", [[{"AttributeKey": "Username", "AttributeValue": "someone"}], [{"AttributeKey": "EventName", "AttributeValue": "UndeclaredArbitraryEvent"}], []])
def test_unapproved_event_query_rejected_before_client_construction(monkeypatch, attributes):
    requests = aws.Requests({})
    monkeypatch.setattr(requests, "client", lambda *args: pytest.fail("undeclared query constructed client"))
    with pytest.raises(aws.ReadFailure, match="undeclared_activity_event_query"):
        requests.call(object(), "cloudtrail", REGION, "lookup_events", LookupAttributes=attributes, StartTime=NOW-timedelta(days=1), EndTime=NOW)
    assert requests.calls == 0


def test_malformed_projection_does_not_cache_secret_payload(monkeypatch):
    response = {"Events": [{**raw_event(), "CloudTrailEvent": MARKER}]}
    with pytest.raises(aws.ReadFailure, match="malformed_activity_projection_payload"):
        aws._project_activity_response(response)


def test_service_event_without_actor_arn_is_ignored_as_pinned_source_requires():
    event = {**raw_event(), "CloudTrailEvent": json.dumps({"userIdentity": {"type": "AWSService"}})}
    assert aws._project_activity_response({"Events": [event]}) == {"Events": []}
