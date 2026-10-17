"""Cached API stage ARN families and collector-to-snapshot evaluation."""
from __future__ import annotations

from peaso.checks import compliance_new_aws_apigateway as api
from peaso.collectors.aws import ReadResult
from peaso.collectors.aws_b_services import FETCHERS
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


class Session:
    def __init__(self, partition):
        self.partition = partition
        self.regions = []

    def get_partition_for_region(self, region):
        self.regions.append(region)
        return self.partition


class Pages:
    def __init__(self, *, rest=True):
        self.rest = rest
        self.calls = []

    def pages(self, session, service, region, operation, expression, **arguments):
        self.calls.append((service, region, operation, expression, arguments))
        if operation in ("get_rest_apis", "get_apis"):
            return ReadResult([{"id": "abc123"}] if self.rest else [{"ApiId": "abc123"}])
        assert operation == "get_stages" and arguments in (
            {"restApiId": "abc123"}, {"ApiId": "abc123"})
        if self.rest:
            return ReadResult([{"stageName": "prod", "methodSettings": {
                "*/*": {"loggingLevel": "INFO", "cachingEnabled": True,
                        "cacheDataEncrypted": True}},
                "cacheClusterEnabled": True, "cacheClusterStatus": "AVAILABLE"}])
        return ReadResult([{"StageName": "$default"}])


def test_rest_and_http_stage_ids_use_distinct_official_paths_and_sdk_partition():
    rest_pages, rest_session = Pages(), Session("aws-cn")
    rest = FETCHERS["rest_api_stage"](rest_pages, rest_session, "cn-north-1",
                                      "123456789012")
    assert rest.status == "collected" and len(rest.items) == 1
    assert rest.items[0]["id"] == (
        "arn:aws-cn:apigateway:cn-north-1::/restapis/abc123/stages/prod")
    assert rest.items[0]["_provenance"] == {"source_operation": "get_stages",
        "parent_api_id": "abc123", "read_only": True,
        "optional_fields_complete": ["accessLogSettings"]}
    assert rest_session.regions == ["cn-north-1"] and len(rest_pages.calls) == 2

    http_pages, http_session = Pages(rest=False), Session("aws-us-gov")
    http = FETCHERS["http_api_stage"](http_pages, http_session, "us-gov-west-1",
                                      "123456789012")
    assert http.status == "collected" and len(http.items) == 1
    assert http.items[0]["id"] == (
        "arn:aws-us-gov:apigateway:us-gov-west-1::/apis/abc123/stages/$default")
    assert http.items[0]['_provenance'] == {'source_operation':'get_stages',
        'parent_api_id':'abc123','read_only':True}
    assert http_session.regions == ["us-gov-west-1"] and len(http_pages.calls) == 2


def test_collected_rest_stage_flows_to_production_scoped_evaluator():
    pages, session = Pages(), Session("aws")
    read = FETCHERS["rest_api_stage"](pages, session, "us-east-1", "123456789012")
    assert read.status == "collected"
    snapshot = make_snapshot("aws", ["123456789012/us-east-1"], [
        {"type": "rest_api_stage", "scope": "123456789012/us-east-1",
         "service": "apigateway", "status": read.status, "items": read.items},
    ], created_at="2026-10-12T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, categories=["hardening"],
                               checks=[api.LOGGING_ID, api.CACHE_ID])
    findings = {row["check_id"]: row for row in report["findings"]
                if row["check_id"] in (api.LOGGING_ID, api.CACHE_ID)}
    assert {key: row["status"] for key, row in findings.items()} == {
        api.LOGGING_ID: "PASS", api.CACHE_ID: "PASS"}
    assert len(pages.calls) == 2 and session.regions == ["us-east-1"]
