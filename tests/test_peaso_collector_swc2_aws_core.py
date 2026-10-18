"""Provider-owned tests for the wave 2 AWS SSM and EventBridge facts."""
from collections import defaultdict, deque

import pytest

from peaso.collectors.aws import ReadResult
from peaso.collectors.aws import Requests, ReadFailure
from peaso.collectors import aws_facts_swc as facts


class Reads:
    def __init__(self):
        self.responses = defaultdict(deque)
        self.calls = []
        self.max_pages = None
        self.max_items = None

    def add(self, operation, *responses):
        self.responses[operation].extend(responses)

    def pages(self, session, service, region, operation, expression, **arguments):
        self.calls.append((service, operation, expression, arguments))
        return self.responses[operation].popleft()

    def detail(self, session, service, region, operation, **arguments):
        self.calls.append((service, operation, None, arguments))
        return self.responses[operation].popleft()


STATES = [
    ("complete", "collected", 1),
    ("empty", "empty", 0),
    ("paginated", "collected", 2),
    ("error", "denied", 0),
    ("partial", "partial", 1),
]


@pytest.mark.parametrize("state,status,count", STATES)
def test_eventbridge_rules_and_targets(state, status, count):
    reads = Reads()
    reads.add("list_event_buses", ReadResult([{"Name": "default"}], "collected"))
    rules = [{"Name": "one", "Arn": "arn:aws:events:us-east-1:123456789012:rule/one", "State": "ENABLED", "EventPattern": "{}"}]
    reads.add("list_rules", ReadResult([], "denied", {"code": "AccessDenied"}) if state == "error" else
              ReadResult(rules, "partial", {"code": "AccessDenied"}) if state == "partial" else
              ReadResult(rules * count, "collected") if count else ReadResult([], "empty"))
    result = facts._rules(reads, None, "us-east-1", "123456789012")
    assert result.status == status
    assert len(result.items) == count
    if count:
        assert all(row["EventBusName"] == "default" for row in result.items)
    assert reads.calls[0][1] == "list_event_buses"
    assert reads.calls[1][3]["EventBusName"] == "default"

    if state == "error":
        return
    reads.add("list_targets_by_rule", ReadResult([{"Id": "target", "Arn": "arn:aws:sns:us-east-1:123456789012:alerts", "Input": "discard"}], "partial", {"code": "AccessDenied"}) if state == "partial" else
              ReadResult([], "denied", {"code": "AccessDenied"}) if state == "empty" else
              ReadResult([{"Id": "target", "Arn": "arn:aws:sns:us-east-1:123456789012:alerts", "Input": "discard"}] * count, "collected"))
    enriched = facts._event_rule(reads, None, "us-east-1", [{**rules[0], "EventBusName": "default"}])[0]
    assert enriched["Targets"]["collection_status"] == ("partial" if state == "partial" else "denied" if state == "empty" else "collected")
    assert all("Input" not in row for row in enriched["Targets"]["items"])


@pytest.mark.parametrize("state,status,count", STATES)
def test_ssm_application_and_compliance(state, status, count):
    reads = Reads()
    error = {"code": "AccessDenied"}
    apps = [{"Name": "agent", "Version": "2.1", "CaptureTime": "2026-01-01T00:00:00+00:00", "Content": "discard"}]
    response = lambda rows: ReadResult(rows * count if status == "collected" else rows if status == "partial" else [], status, error if status in ("partial", "denied") else None)
    reads.add("list_inventory_entries", {"collection_status": "denied", "error": error} if state == "error" else
              {"collection_status": "collected", "Entries": apps, "CaptureTime": "2026-01-01T00:00:00+00:00", "NextToken": "next"} if state in ("partial", "paginated") else
              {"collection_status": "collected", "Entries": [] if state == "empty" else apps, "CaptureTime": "2026-01-01T00:00:00+00:00"})
    if state in ("partial", "paginated"):
        reads.add("list_inventory_entries", {"collection_status": "denied", "error": error} if state == "partial" else
                  {"collection_status": "collected", "Entries": apps, "CaptureTime": "2026-01-02T00:00:00+00:00"})
    compliance = [{"ResourceId": "i-12345678", "ComplianceType": "Association", "Id": "baseline", "Status": "COMPLIANT", "Details": {"offsetMilliseconds": 1, "Secret": "discard"}}]
    reads.add("list_compliance_items", *(response(compliance) for _ in range(3)))
    item = facts._ssm_inventory(reads, None, "us-east-1", [{"InstanceId": "i-12345678"}])[0]
    assert item["ApplicationInventory"]["collection_status"] == status
    assert item["ApplicationInventory"]["InstanceId"] == "i-12345678"
    assert len(item["ApplicationInventory"]["Entries"]) == count
    if state == "paginated":
        assert item["ApplicationInventory"]["Entries"][1]["CaptureTime"] == "2026-01-02T00:00:00+00:00"
    assert item["AssociationCompliance"]["collection_status"] == status
    assert item["TimeSyncCompliance"]["collection_status"] == status
    assert item["MalwareDefinitionsCompliance"]["collection_status"] == status
    assert "discard" not in str(item)
    assert reads.calls[0][3]["TypeName"] == "AWS:Application"
    assert [call[3]["Filters"][0]["Values"][0] for call in reads.calls if call[1] == "list_compliance_items"] == ["Association", "Custom:TimeSync", "Custom:MalwareDefinitions"]


def test_ssm_and_eventbridge_actions_are_read_only():
    assert {("ssm", "list_inventory_entries"), ("ssm", "list_compliance_items"), ("events", "list_event_buses"), ("events", "list_targets_by_rule")} <= facts.READ_ACTIONS
    assert facts.ENRICHERS["ssm_managed_instance"] is facts._ssm_inventory
    assert facts.FETCHERS["eventbridge_rule"] is facts._rules


def test_eventbridge_partial_bus_pages_never_emit_bus_as_rule():
    reads = Reads()
    reads.add("list_event_buses", ReadResult([{"Name": "default"}], "partial", {"code": "AccessDenied"}))
    read = facts._rules(reads, None, "us-east-1", "123456789012")
    assert read.status == "partial"
    assert read.items == []
    assert len(reads.calls) == 1


@pytest.mark.parametrize("state,status", [("complete", "collected"), ("empty", "collected"), ("error", "denied")])
def test_shield_drt_singleton(state, status):
    class Detail:
        def detail(self, session, service, region, operation):
            assert (service, operation) == ("shield", "describe_drt_access")
            return {"collection_status": "denied", "error": {"code": "AccessDenied"}} if state == "error" else {
                "collection_status": "collected", "RoleArn": "arn:aws:iam::123456789012:role/srt" if state == "complete" else "",
                "LogBucketList": ["audit"] if state == "complete" else []}

    read = facts._shield_drt(Detail(), None, "us-east-1", "123456789012")
    assert read.status == status
    assert len(read.items) == (0 if state == "error" else 1)
    if read.items:
        assert read.items[0]["LogBucketList"] == (["audit"] if state == "complete" else [])


def test_detective_graph_spec_paginates_through_shared_requests():
    assert facts.SPECS["detective_graph"] == ("detective", "list_graphs", "GraphList")
    assert facts.NATIVE_IDS["detective_graph"] == "Arn"
    assert facts.SPECS["dhcp_options"] == ("ec2", "describe_dhcp_options", "DhcpOptions")


@pytest.mark.parametrize("state,status", [("complete", "collected"), ("empty", "empty"), ("partial", "partial")])
def test_default_event_rule_alias(state, status):
    reads = Reads()
    row = {"Name": "rule", "Arn": "arn:aws:events:us-east-1:123456789012:rule/rule"}
    reads.add("list_rules", ReadResult([row] if state != "empty" else [], status, {"code": "AccessDenied"} if state == "partial" else None))
    result = facts._default_rules(reads, None, "us-east-1", "123456789012")
    assert result.status == status
    assert reads.calls[0][3]["EventBusName"] == "default"
    assert all(item["EventBusName"] == "default" for item in result.items)


@pytest.mark.parametrize("state,expected", [("complete", "collected"), ("empty", "empty"), ("paginated", "collected"), ("error", "denied"), ("partial", "partial")])
def test_shared_request_pagination_retains_failure_state(state, expected):
    requests = Requests({"retry_attempts": 1})
    class Client:
        def can_paginate(self, operation):
            return False
    requests.client = lambda session, service, region: Client()
    row = {"Name": "default"}
    responses = deque(([{"EventBuses": [row], "NextToken": "next"}, {"EventBuses": [row]}] if state == "paginated" else
                       [{"EventBuses": [row], "NextToken": "next"}, ReadFailure("denied", "AccessDeniedException")] if state == "partial" else
                       [ReadFailure("denied", "AccessDeniedException")] if state == "error" else
                       [{"EventBuses": []}] if state == "empty" else [{"EventBuses": [row]}]))
    calls = []
    def call(session, service, region, operation, **arguments):
        calls.append(arguments)
        result = responses.popleft()
        if isinstance(result, Exception):
            raise result
        return result
    requests.call = call
    read = requests.pages(None, "events", "us-east-1", "list_event_buses", "EventBuses", _tokens=("NextToken", "NextToken"))
    assert read.status == expected
    if state in ("paginated", "partial"):
        assert calls[1]["NextToken"] == "next"
