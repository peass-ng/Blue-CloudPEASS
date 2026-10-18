"""Collected CloudWatch filter facts must authorize coverage conclusions."""

import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import aws_gap_metrics as metrics

REGISTRY = {check.id: check for check in CHECKS}
ROOT_IDS = (
    metrics.PROWLER_NATIVES["cloudwatch_log_metric_filter_root_usage"],
    metrics.STEAMPIPE_NATIVES["log_metric_filter_root_login"],
)


def evaluate(cid, edit):
    case = CASES[cid]
    item = copy.deepcopy(case["pass"])
    index = copy.deepcopy(case["index"])
    listing = index["metric_alarm_account_inventory"][0]["data"]["MetricFilters"]
    edit(listing)
    return REGISTRY[cid].evaluate(item, index)[0]


@pytest.mark.parametrize("cid", ROOT_IDS)
def test_missing_or_denied_pattern_is_unknown(cid):
    def missing(listing):
        listing["items"][0].pop("filterPattern")

    def denied(listing):
        listing["items"][0].setdefault("_coverage", {})["filterPattern"] = {"status": "denied"}

    assert evaluate(cid, missing) == "UNKNOWN"
    assert evaluate(cid, denied) == "UNKNOWN"


@pytest.mark.parametrize("cid", ROOT_IDS)
def test_malformed_collected_listing_is_unknown(cid):
    assert evaluate(cid, lambda listing: listing.update(items=None)) == "UNKNOWN"
    assert evaluate(cid, lambda listing: listing.pop("items")) == "UNKNOWN"


@pytest.mark.parametrize("cid", ROOT_IDS)
def test_explicit_empty_pattern_still_covers_events(cid):
    assert evaluate(cid, lambda listing: listing["items"][0].update(filterPattern="")) == "PASS"
