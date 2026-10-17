"""Route-search completion must agree with the provider's truncation marker."""
from types import SimpleNamespace

import pytest

from peaso.collectors.aws import Requests


def read_pages(monkeypatch, responses, *, paginated):
    request = Requests({})
    client = SimpleNamespace(
        can_paginate=lambda operation: paginated,
        get_paginator=lambda operation: SimpleNamespace(_pagination_cfg={
            "input_token": "NextToken", "output_token": "NextToken"}),
    )
    monkeypatch.setattr(request, "client", lambda *args: client)
    calls = []
    pages = iter(responses)

    def call(*args, **kwargs):
        calls.append(kwargs)
        return next(pages)

    monkeypatch.setattr(request, "call", call)
    result = request.pages(object(), "ec2", "us-east-1", "search_transit_gateway_routes", "Routes",
                           TransitGatewayRouteTableId="tgw-rtb-fixture")
    return result, calls


@pytest.mark.parametrize("paginated", [False, True])
@pytest.mark.parametrize("routes", [[], [{"DestinationCidrBlock": "10.0.0.0/8"}]])
def test_truncated_search_without_token_never_proves_complete(monkeypatch, paginated, routes):
    result, calls = read_pages(monkeypatch, [{"Routes": routes, "AdditionalRoutesAvailable": True}], paginated=paginated)
    assert result.items == routes
    assert result.status == ("partial" if routes else "not_collected")
    assert result.error["code"] == "missing_pagination_token"
    assert len(calls) == 1


def test_modern_paginator_continues_available_routes_to_verified_last_page(monkeypatch):
    first = {"DestinationCidrBlock": "10.0.0.0/8"}
    last = {"DestinationCidrBlock": "192.168.0.0/16"}
    result, calls = read_pages(monkeypatch, [
        {"Routes": [first], "AdditionalRoutesAvailable": True, "NextToken": "next-page"},
        {"Routes": [last], "AdditionalRoutesAvailable": False},
    ], paginated=True)
    assert result.status == "collected" and result.error is None
    assert result.items == [first, last]
    assert [call.get("NextToken") for call in calls] == [None, "next-page"]


@pytest.mark.parametrize("paginated", [False, True])
def test_confirmed_empty_search_is_empty(monkeypatch, paginated):
    result, calls = read_pages(monkeypatch, [{"Routes": [], "AdditionalRoutesAvailable": False}], paginated=paginated)
    assert result.status == "empty" and result.items == [] and result.error is None
    assert len(calls) == 1


def test_malformed_completion_marker_cannot_prove_empty(monkeypatch):
    result, calls = read_pages(monkeypatch, [{"Routes": [], "AdditionalRoutesAvailable": "false"}], paginated=True)
    assert result.status == "malformed"
    assert result.error["code"] == "malformed_route_search_completion"
    assert len(calls) == 1
