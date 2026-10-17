"""Selected alarm and notification facts must be readable before coverage can pass."""

import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import aws_gap_metrics as metrics

REGISTRY = {check.id: check for check in CHECKS}
METRIC = metrics.PROWLER_NATIVES["cloudwatch_log_metric_filter_root_usage"]
CIS = metrics.STEAMPIPE_NATIVES["log_metric_filter_root_login"]


def evaluate(cid, edit):
    case = CASES[cid]
    item = copy.deepcopy(case["pass"])
    index = copy.deepcopy(case["index"])
    row = index["metric_alarm_account_inventory"][0]["data"]
    edit(row)
    return REGISTRY[cid].evaluate(item, index)[0]


def alarm(row):
    return row["MetricAlarms"]["items"][0]


@pytest.mark.parametrize("cid", (METRIC, CIS))
@pytest.mark.parametrize("field", ("MetricName", "Namespace", "Dimensions"))
def test_denied_selected_alarm_identity_is_unknown(cid, field):
    assert evaluate(cid, lambda row: alarm(row).setdefault("_coverage", {}).update({field: {"status": "denied"}})) == "UNKNOWN"


@pytest.mark.parametrize("field", ("ActionsEnabled", "AlarmActions"))
def test_denied_selected_notification_field_is_unknown(field):
    assert evaluate(CIS, lambda row: alarm(row).setdefault("_coverage", {}).update({field: {"status": "denied"}})) == "UNKNOWN"


def test_denied_selected_subscription_field_is_unknown():
    def deny(row):
        row["Subscriptions"]["items"][0].setdefault("_coverage", {})["SubscriptionArn"] = {"status": "denied"}
    assert evaluate(CIS, deny) == "UNKNOWN"


def test_omitted_alarm_dimensions_still_means_dimensionless():
    assert evaluate(METRIC, lambda row: alarm(row).pop("Dimensions")) == "PASS"
    assert evaluate(CIS, lambda row: alarm(row).pop("Dimensions")) == "PASS"


def test_other_valid_alarm_can_still_prove_coverage():
    def add_other(row):
        original = alarm(row)
        invalid = copy.deepcopy(original)
        invalid.setdefault("_coverage", {})["Namespace"] = {"status": "denied"}
        row["MetricAlarms"]["items"] = [invalid, original]
    assert evaluate(METRIC, add_other) == "PASS"
    assert evaluate(CIS, add_other) == "PASS"


def test_malformed_selected_metric_query_is_unknown():
    def malformed(row):
        target = alarm(row)
        target.pop("MetricName")
        target["Metrics"] = [{"Metric": {"MetricName": "m", "Namespace": "CISBenchmark", "Dimensions": []},
                              "ReturnData": True, "_coverage": {"Metric": {"status": "denied"}}}]
    assert evaluate(METRIC, malformed) == "UNKNOWN"


@pytest.mark.parametrize("cid,field", ((METRIC, "MetricAlarms"), (CIS, "MetricAlarms"), (CIS, "Subscriptions")))
def test_denied_selected_collection_is_unknown(cid, field):
    assert evaluate(cid, lambda row: row.setdefault("_coverage", {}).update({field: {"status": "denied"}})) == "UNKNOWN"


def test_collected_metric_query_and_denied_metric_spec():
    def metric_query(row):
        target = alarm(row)
        target.pop("MetricName")
        target["Metrics"] = [{"Metric": {"MetricName": "m", "Namespace": "CISBenchmark", "Dimensions": []},
                              "ReturnData": True}]
    assert evaluate(METRIC, metric_query) == "PASS"

    def denied(row):
        metric_query(row)
        alarm(row)["Metrics"][0]["Metric"].setdefault("_coverage", {})["Namespace"] = {"status": "denied"}
    assert evaluate(METRIC, denied) == "UNKNOWN"


def test_missing_alarm_actions_is_unknown_but_explicit_empty_is_not_coverage():
    assert evaluate(CIS, lambda row: alarm(row).pop("AlarmActions")) == "UNKNOWN"
    assert evaluate(CIS, lambda row: alarm(row).update(AlarmActions=[])) == "FAIL"
