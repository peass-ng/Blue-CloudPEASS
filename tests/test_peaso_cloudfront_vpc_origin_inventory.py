"""SDK-backed VPC-origin reads and explicit denied-detail coverage."""
import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.collectors.aws_network_service_metadata import enrich, fetch


def test_vpc_origin_sdk_list_and_detail_are_registered_and_secret_free(monkeypatch):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    client = session.client("cloudfront")
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    arn = "arn:aws:cloudfront::111111111111:vpcorigin/vo-one"
    endpoint = "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/backend/1"
    import datetime
    now = datetime.datetime(2026, 10, 20, tzinfo=datetime.timezone.utc)
    with Stubber(client) as stub:
        stub.add_response("list_vpc_origins", {"VpcOriginList": {"Items": [{"Id": "vo-one", "Arn": arn,
            "Name": "origin", "Status": "Deployed", "CreatedTime": now, "LastModifiedTime": now, "OriginEndpointArn": endpoint}],
            "IsTruncated": False, "Quantity": 1, "MaxItems": 100, "Marker": ""}})
        stub.add_response("get_vpc_origin", {"VpcOrigin": {"Id": "vo-one", "Arn": arn,
            "Status": "Deployed", "CreatedTime": now, "LastModifiedTime": now,
            "VpcOriginEndpointConfig": {"Name": "origin", "Arn": endpoint, "HTTPPort": 80, "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only"}}}, {"Id": "vo-one"})
        requests = aws.Requests({})
        read = fetch(requests, session, "us-east-1", "111111111111")
        assert read.status == "collected"
        rows = enrich(requests, session, "us-east-1", read.items)
        assert rows[0]["VpcOrigin"]["VpcOriginEndpointConfig"]["Arn"] == endpoint
        stub.assert_no_pending_responses()
    assert "cloudfront_vpc_origin" in aws.GLOBAL_TYPES
    assert ("cloudfront", "get_vpc_origin") in aws.READ_ACTIONS


@pytest.mark.parametrize("header,expected", [
    ({"IsTruncated": False}, "empty"),
    ({"IsTruncated": True}, "malformed"),
])
def test_empty_and_truncated_origin_lists_do_not_look_the_same(monkeypatch, header, expected):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert")
    client = session.client("cloudfront")
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    with Stubber(client) as stub:
        stub.add_response("list_vpc_origins", {"VpcOriginList": {"Marker": "", "MaxItems": 100, "Quantity": 0, **header}})
        result = fetch(aws.Requests({}), session, "us-east-1", "111111111111")
    assert result.status == expected


@pytest.mark.parametrize("items,quantity,expected", [
    ([], 0, "empty"),
    ([{"Id": "vo-one"}], 1, "malformed"),
])
def test_omitted_completion_flag_requires_exact_empty_response(items, quantity, expected):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert")
    requests = aws.Requests({})
    # The live CloudFront response omits an SDK-required field, so Stubber
    # rejects it before collector response handling can be exercised.
    requests.call = lambda *args, **kwargs: {"VpcOriginList": {"MaxItems": 100,
        "Quantity": quantity, "Items": items}}
    result = fetch(requests, session, "us-east-1", "111111111111")
    assert result.status == expected


def test_origin_pagination_uses_nested_next_marker(monkeypatch):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert")
    client = session.client("cloudfront")
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    with Stubber(client) as stub:
        stub.add_response("list_vpc_origins", {"VpcOriginList": {"Marker": "", "MaxItems": 100, "Quantity": 0,
            "IsTruncated": True, "NextMarker": "next"}}, {})
        stub.add_response("list_vpc_origins", {"VpcOriginList": {"Marker": "next", "MaxItems": 100, "Quantity": 0,
            "IsTruncated": False}}, {"Marker": "next"})
        result = fetch(aws.Requests({}), session, "us-east-1", "111111111111")
        stub.assert_no_pending_responses()
    assert result.status == "empty"


def test_denied_origin_detail_does_not_erase_the_listed_origin(monkeypatch):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    client = session.client("cloudfront")
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    with Stubber(client) as stub:
        stub.add_client_error("get_vpc_origin", "AccessDenied", expected_params={"Id": "vo-one"})
        rows = enrich(aws.Requests({}), session, "us-east-1", [{"Id": "vo-one"}])
    assert rows == [{"Id": "vo-one", "VpcOrigin": {"collection_status": "denied", "error": {"code": "AccessDenied"}}}]
