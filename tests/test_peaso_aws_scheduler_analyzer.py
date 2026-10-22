"""Offline timing contract for AWS analyzer preparation and ordinary reads."""
import threading
import time

import pytest

from peaso.collectors import aws
from peaso.collectors import aws_lambda_environment_secret_indicators as lambda_content
from peaso.collectors import aws_selected_configuration_secret_indicators as configuration_content
from peaso.collectors.aws_access_analyzer_lifecycle import AnalyzerLifecycle


ACCOUNT = "123456789012"
REGION = "us-east-1"


@pytest.mark.parametrize("call_cap", [None, 1])
def test_analyzer_preparation_overlaps_queued_inventory_without_losing_output(monkeypatch, call_cap):
    inventory_started = threading.Event()
    prepared = threading.Event()
    observed = {}

    class Session:
        region_name = REGION

        def get_partition_for_region(self, region):
            return "aws"

    monkeypatch.setattr(aws, "_session", lambda auth, region: (Session(), "offline"))
    monkeypatch.setattr(aws, "_identity", lambda requests, session, region, expected=None: {
        "Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/offline", "UserId": "offline"})

    def pages(self, session, service, region, operation, expression, **arguments):
        assert (service, operation) == ("ec2", "describe_vpcs")
        inventory_started.set()
        time.sleep(0.12)  # delayed offline transport
        return aws.ReadResult([], "empty")

    def prepare(self, session, identity, regions):
        observed["inventory_started_during_prepare"] = inventory_started.wait(0.5 if call_cap is None else 0.01)
        time.sleep(0.12)  # delayed offline analyzer SDK transport
        prepared.set()

    def analyzer_read(self, session, identity, region, enrich):
        assert prepared.is_set()
        return aws.ReadResult([], "empty")

    monkeypatch.setattr(aws.Requests, "pages", pages)
    monkeypatch.setattr(AnalyzerLifecycle, "prepare", prepare)
    monkeypatch.setattr(AnalyzerLifecycle, "collect", analyzer_read)

    options = {"service_concurrency": 2, "max_resources": 1}
    if call_cap is not None:
        options["max_calls"] = call_cap
    started = time.monotonic()
    snapshot = aws.collect({"provider": "aws", "scopes": [f"{ACCOUNT}/{REGION}"],
        "options": options},
        ["vpc", "access_analyzer"])
    observed["elapsed"] = time.monotonic() - started
    selected = {(row["type"], row["scope"]): row["status"] for row in snapshot["collections"]
        if row["type"] in {"vpc", "access_analyzer"}}
    assert observed["inventory_started_during_prepare"] is (call_cap is None)
    assert selected == {("vpc", f"{ACCOUNT}/{REGION}"): "empty",
                        ("access_analyzer", f"{ACCOUNT}/{REGION}"): "empty"}


def test_selected_content_cannot_fill_all_service_workers_ahead_of_inventory(monkeypatch):
    inventory_started = threading.Event()
    content_saw_inventory = []

    class Session:
        region_name = REGION

        def get_partition_for_region(self, region):
            return "aws"

    monkeypatch.setattr(aws, "_session", lambda auth, region: (Session(), "offline"))
    monkeypatch.setattr(aws, "_identity", lambda requests, session, region, expected=None: {
        "Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/offline", "UserId": "offline"})

    def pages(self, session, service, region, operation, expression, **arguments):
        assert (service, operation) == ("ec2", "describe_vpcs")
        inventory_started.set()
        return aws.ReadResult([], "empty")

    def slow_content(*args, **kwargs):
        content_saw_inventory.append(inventory_started.wait(0.4))
        return aws.ReadResult([], "empty")

    monkeypatch.setattr(aws.Requests, "pages", pages)
    monkeypatch.setattr(lambda_content, "collect_selected", slow_content)
    monkeypatch.setattr(configuration_content, "collect_selected", slow_content)
    scope = f"{ACCOUNT}/{REGION}"
    snapshot = aws.collect({"provider": "aws", "scopes": [scope],
        "options": {"service_concurrency": 2}},
        [lambda_content.KIND, configuration_content.KIND, "vpc"])
    selected = {(row["type"], row["scope"]): row["status"] for row in snapshot["collections"]
        if row["type"] in {lambda_content.KIND, configuration_content.KIND, "vpc"}}
    assert content_saw_inventory == [True, True]
    assert selected == {(kind, scope): "empty" for kind in
                        (lambda_content.KIND, configuration_content.KIND, "vpc")}
