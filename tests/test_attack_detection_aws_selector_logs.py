"""CloudTrail Event History selector reads use only an injected fake client."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from peaso.server.aws_selector_logs import read_aws_selector_event_history


START = datetime(2026, 10, 18, 10, 0, tzinfo=timezone.utc)
END = datetime(2026, 10, 18, 11, 0, tzinfo=timezone.utc)


class FakeClient:
    def __init__(self, pages: list[dict | Exception]):
        self.pages = pages
        self.calls: list[dict] = []

    def lookup_events(self, **kwargs):
        self.calls.append(kwargs)
        page = self.pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page


def _event(event_id: str, second: int, account: str = "123456789012", region: str = "eu-west-1") -> dict:
    return {"eventSource": "cloudtrail.amazonaws.com", "eventName": "PutEventSelectors",
            "eventID": event_id, "eventTime": f"2026-10-18T10:00:{second:02d}Z",
            "recipientAccountId": account, "awsRegion": region,
            "requestParameters": {"trailName": "audit-trail"}}


def _row(event: dict) -> dict:
    return {"EventId": event["eventID"], "CloudTrailEvent": json.dumps(event)}


def _read(client: FakeClient, **kwargs):
    return read_aws_selector_event_history(
        client, account_id="123456789012", region="eu-west-1",
        start_time=START, end_time=END, **kwargs,
    )


def test_complete_pagination_filters_deduplicates_sorts_and_keeps_fixed_lookup_parameters() -> None:
    first = _event("first", 10)
    later = _event("later", 20)
    other_account = _event("foreign", 5, account="999999999999")
    other_region = _event("different-region", 6, region="us-east-1")
    client = FakeClient([
        {"Events": [_row(later), _row(other_account), _row(other_region)], "NextToken": "page-2"},
        {"Events": [_row(first), _row(later)]},
    ])
    result = _read(client)
    assert result.complete is True
    assert result.partial_reason is None
    assert [event["eventID"] for event in result.events] == ["first", "later"]
    assert result.pages_read == 2
    assert result.records_seen == 5
    assert client.calls == [
        {"StartTime": START, "EndTime": END,
         "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "PutEventSelectors"}],
         "MaxResults": 50},
        {"StartTime": START, "EndTime": END,
         "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "PutEventSelectors"}],
         "MaxResults": 50, "NextToken": "page-2"},
    ]
    assert "90 days" in result.coverage
    assert "recent events may not yet have arrived" in result.coverage


@pytest.mark.parametrize("scenario,expected", [
    ("page_cap", "page_cap"), ("record_cap", "record_cap"),
    ("token_cycle", "token_cycle"), ("parse_failure", "malformed_event"),
    ("missing_event_id", "malformed_event"), ("malformed_page", "malformed_page"),
    ("lookup_failure", "lookup_failed"), ("conflicting_duplicate", "conflicting_duplicate"),
    ("outside_window", "event_outside_window"), ("wrong_envelope_id", "malformed_event"),
    ("malformed_token", "malformed_token"),
])
def test_incomplete_enumeration_never_claims_complete(scenario: str, expected: str) -> None:
    first = _event("first", 10)
    pages = [{"Events": [_row(first)]}]
    options = {}
    if scenario == "page_cap": pages[0]["NextToken"] = "more"; options["max_pages"] = 1
    if scenario == "record_cap": options["max_records"] = 1
    if scenario == "token_cycle": pages = [
        {"Events": [_row(first)], "NextToken": "repeat"},
        {"Events": [_row(_event("second", 20))], "NextToken": "repeat"},
    ]
    if scenario == "parse_failure": pages[0]["Events"].append({"CloudTrailEvent": "{"})
    if scenario == "missing_event_id":
        row = _row(first); row["CloudTrailEvent"] = json.dumps({key: value for key, value in first.items() if key != "eventID"})
        pages[0]["Events"].append(row)
    if scenario == "malformed_page": pages = [{"Events": "not a list"}]
    if scenario == "lookup_failure": pages = [RuntimeError("simulated")]
    if scenario == "conflicting_duplicate":
        changed = deepcopy(first); changed["requestParameters"]["trailName"] = "different-trail"
        pages[0]["Events"].append(_row(changed))
    if scenario == "outside_window":
        old = _event("old", 20)
        old["eventTime"] = "2026-10-17T10:00:20Z"
        pages[0]["Events"].append(_row(old))
    if scenario == "wrong_envelope_id": pages[0]["Events"].append({**_row(_event("second", 20)), "EventId": "other"})
    if scenario == "malformed_token": pages[0]["NextToken"] = 123
    result = _read(FakeClient(pages), **options)
    assert result.complete is False
    assert result.partial_reason == expected


def test_page_result_larger_than_requested_is_partial_without_unbounded_parse() -> None:
    client = FakeClient([{"Events": [_row(_event("one", 1)), _row(_event("two", 2))]}])
    result = _read(client, max_records=1)
    assert result.complete is False
    assert result.partial_reason == "malformed_page"
    assert result.records_seen == 0
    assert client.calls[0]["MaxResults"] == 1


@pytest.mark.parametrize("kwargs", [
    {"max_pages": 0}, {"max_records": 0}, {"max_pages": True},
    {"start_time": END, "end_time": START},
    {"account_id": "not-account"}, {"region": "bad-region"},
])
def test_invalid_bounds_are_rejected_before_lookup(kwargs: dict) -> None:
    client = FakeClient([])
    base = {"account_id": "123456789012", "region": "eu-west-1",
            "start_time": START, "end_time": END}
    with pytest.raises(ValueError, match="invalid_selector_history_bounds"):
        read_aws_selector_event_history(client, **{**base, **kwargs})
    assert client.calls == []
