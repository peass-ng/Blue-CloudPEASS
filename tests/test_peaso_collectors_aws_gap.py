"""Read-only collector facts for the AWS upstream-gap monitoring and contact predicates (botocore Stubber, no cloud calls)."""
import json
from pathlib import Path

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.collectors import aws_facts_gap as facts

REGION = "us-east-1"
ACCOUNT = "123456789012"
ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ("Alice Example", "alice@example.invalid", "+1 000 000 0001", "Bob Example", "bob@example.invalid", "+1 000 000 0002",
           "Carol Example", "carol@example.invalid", "+1 000 000 0003", "Dan Example", "+1 000 000 0004")


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name=REGION)
    clients, stubs = {}, {}

    def add(service):
        if service not in clients:
            clients[service] = session.client(service, region_name=REGION)
            stubs[service] = Stubber(clients[service])
            stubs[service].activate()
        return stubs[service]
    monkeypatch.setattr(aws.Requests, "client", lambda requests, context, service, region: clients[service])
    yield session, add
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def denied(stub, operation, code="AccessDeniedException", params=None):
    stub.add_client_error(operation, service_error_code=code, service_message="denied", http_status_code=403, expected_params=params)


def metric_filter(group, name, pattern="{ ($.errorCode = \"AccessDenied\") }"):
    return {"filterName": name, "filterPattern": pattern, "logGroupName": group, "creationTime": 1,
            "metricTransformations": [{"metricName": "m", "metricNamespace": "CISBenchmark", "metricValue": "1"}]}


def test_module_is_loaded_into_the_collector_registry():
    for kind, spec in facts.SPECS.items():
        assert aws.SPECS[kind] == spec
    assert facts.GLOBAL_TYPES <= aws.GLOBAL_TYPES
    assert "log_metric_filter" not in aws.GLOBAL_TYPES
    for service, operation in facts.READ_ACTIONS:
        assert operation.startswith(("get_", "list_", "describe_")), (service, operation)
        assert (service, operation) in aws.READ_ACTIONS


def test_customer_policy_grants_the_new_read_actions():
    policy = json.dumps(json.loads((ROOT / "infra/aws/customer-role.json").read_text()))
    for action in ("logs:DescribeMetricFilters", "account:GetContactInformation", "account:GetAlternateContact",
                   "cloudwatch:DescribeAlarms", "sns:ListSubscriptions"):
        assert action in policy, action


def test_metric_filters_paginate_every_log_group(sdk):
    session, add = sdk
    logs = add("logs")
    logs.add_response("describe_metric_filters", {"metricFilters": [metric_filter("g1", "a")], "nextToken": "n"}, {})
    logs.add_response("describe_metric_filters", {"metricFilters": [metric_filter("g2", "b")]}, {"nextToken": "n"})
    read = facts.FETCHERS["log_metric_filter"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected"
    assert [item["id"] for item in read.items] == ["g1/a", "g2/b"]
    assert read.items[0]["metricTransformations"] == [{"metricName": "m", "metricNamespace": "CISBenchmark", "dimensions": None}]
    assert "creationTime" not in read.items[0]


def test_metric_filters_denied_is_never_an_empty_inventory(sdk):
    session, add = sdk
    denied(add("logs"), "describe_metric_filters")
    read = facts.FETCHERS["log_metric_filter"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "denied" and read.items == []


def test_metric_filters_page_limit_is_not_complete(sdk):
    session, add = sdk
    add("logs").add_response("describe_metric_filters", {"metricFilters": [metric_filter("g1", "a")], "nextToken": "n"}, {})
    read = facts.FETCHERS["log_metric_filter"](aws.Requests({"max_pages": 1}), session, REGION, ACCOUNT)
    assert read.status == "partial" and read.error["code"] == "page_limit"


def _contacts(add, operations=("ok", "ok", "ok", "ok"), duplicate_phone=False):
    account = add("account")
    primary, billing, operations_, security = operations
    if primary == "ok":
        account.add_response("get_contact_information", {"ContactInformation": {
            "FullName": PRIVATE[9], "PhoneNumber": PRIVATE[10], "AddressLine1": "1 Inert St", "City": "Nowhere", "CountryCode": "US", "PostalCode": "00000"}}, {})
    else:
        denied(account, "get_contact_information", params={})
    for label, state, (name, email, phone) in zip(("BILLING", "OPERATIONS", "SECURITY"), (billing, operations_, security),
                                                    (PRIVATE[0:3], PRIVATE[3:6], PRIVATE[6:9])):
        params = {"AlternateContactType": label}
        if state == "ok":
            phone = PRIVATE[2].replace(" ", "-") if duplicate_phone and label == "SECURITY" else phone
            account.add_response("get_alternate_contact", {"AlternateContact": {
                "Name": name, "EmailAddress": email, "PhoneNumber": phone, "Title": "t", "AlternateContactType": label}}, params)
        elif state == "absent":
            account.add_client_error("get_alternate_contact", "ResourceNotFoundException", http_status_code=404, expected_params=params)
        else:
            denied(account, "get_alternate_contact", params=params)


def _evaluate(item):
    from peaso.checks import CHECKS
    check = next(c for c in CHECKS if c.id == "aws.gap.account.distinct_primary_billing_operations_security_contacts")
    return check.evaluate(aws._safe(item), {})[0]


def test_contact_details_store_only_presence_and_distinct_counts(sdk):
    session, add = sdk
    _contacts(add)
    read = facts.FETCHERS["aws_account_contact_details"](aws.Requests({}), session, REGION, ACCOUNT)
    item = read.items[0]
    assert read.status == "collected" and item["Partition"] == "aws"
    assert (item["DistinctNames"], item["DistinctPhones"], item["DistinctEmails"]) == (4, 4, 3)
    assert (item["NamesCompared"], item["PhonesCompared"], item["EmailsCompared"]) == (4, 4, 3)
    serialized = json.dumps(item).casefold()
    for value in PRIVATE + ("Inert St", "00000", "10000000001"):
        assert value.casefold() not in serialized, value
    assert _evaluate(item) == "PASS"


def test_contact_phone_normalization_detects_duplicates(sdk):
    session, add = sdk
    _contacts(add, duplicate_phone=True)
    item = facts.FETCHERS["aws_account_contact_details"](aws.Requests({}), session, REGION, ACCOUNT).items[0]
    assert item["DistinctPhones"] == 3 and item["PhonesCompared"] == 4
    assert _evaluate(item) == "FAIL"


def test_absent_alternate_contact_fails_and_denied_is_unknown(sdk):
    session, add = sdk
    _contacts(add, ("ok", "ok", "absent", "ok"))
    item = facts.FETCHERS["aws_account_contact_details"](aws.Requests({}), session, REGION, ACCOUNT).items[0]
    assert item["Contacts"]["OPERATIONS"]["collection_status"] == "empty" and item["Contacts"]["OPERATIONS"]["absent"] is True
    assert _evaluate(item) == "FAIL"


def test_denied_primary_contact_is_unknown_not_pass(sdk):
    session, add = sdk
    _contacts(add, ("denied", "ok", "ok", "ok"))
    item = facts.FETCHERS["aws_account_contact_details"](aws.Requests({}), session, REGION, ACCOUNT).items[0]
    assert item["Contacts"]["PRIMARY"] == {"collection_status": "denied", "error": {"code": "AccessDeniedException"}}
    assert _evaluate(item) == "UNKNOWN"


def test_metric_alarm_rows_keep_per_listing_status_and_scope_subscriptions():
    topic = "arn:aws:sns:us-east-1:%s:alerts" % ACCOUNT
    reads = {
        ("us-east-1", "log_metric_filter"): aws.ReadResult([{"id": "g/f", "logGroupName": "g", "filterName": "f"}], "collected"),
        ("us-east-1", "cloudwatch_alarm"): aws.ReadResult([{"AlarmName": "a", "MetricName": "m", "Namespace": "n", "AlarmActions": [topic],
                                                            "ActionsEnabled": True, "Threshold": 1.0, "StateValue": "OK"}], "collected"),
        ("us-east-1", "sns_subscription"): aws.ReadResult([{"SubscriptionArn": topic + ":1", "TopicArn": topic, "Protocol": "email", "id": topic + ":1"},
                                                           {"SubscriptionArn": "arn:aws:sns:us-east-1:%s:other:1" % ACCOUNT, "TopicArn": "other"}], "collected"),
        ("eu-west-1", "log_metric_filter"): aws.ReadResult([], "denied", {"code": "AccessDeniedException"}),
        ("eu-west-1", "cloudwatch_alarm"): aws.ReadResult([], "empty"),
        ("eu-west-1", "sns_subscription"): aws.ReadResult([], "empty"),
    }
    read = facts.metric_alarm_rows(lambda session, identity, region, kind: reads[(region, kind)], None, {"Account": ACCOUNT}, ["us-east-1", "eu-west-1"])
    east, west = read.items
    assert east["id"] == "metric-alarm-coverage/%s/us-east-1" % ACCOUNT and east["SourceRegion"] == "us-east-1"
    assert east["MetricAlarms"]["items"] == [{"AlarmName": "a", "MetricName": "m", "Namespace": "n", "AlarmActions": [topic], "ActionsEnabled": True}]
    assert [s["TopicArn"] for s in east["Subscriptions"]["items"]] == [topic]
    assert west["MetricFilters"] == {"collection_status": "denied", "items": [], "error": {"code": "AccessDeniedException"}}
