"""Metric-filter join and transformation facts must be readable for alarm coverage."""

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
    listing = index["metric_alarm_account_inventory"][0]["data"]["MetricFilters"]["items"]
    edit(listing)
    return REGISTRY[cid].evaluate(item, index)[0]


@pytest.mark.parametrize("cid", ROOT_IDS)
@pytest.mark.parametrize("field", ("logGroupName", "applyOnTransformedLogs", "metricTransformations",
                                   "metricName", "metricNamespace", "dimensions"))
def test_denied_selected_filter_or_transformation_fact_is_unknown(cid, field):
    def deny(listing):
        source = listing[0]
        target = source["metricTransformations"][0] if field in ("metricName", "metricNamespace", "dimensions") else source
        if field == "dimensions":
            target.pop("dimensions", None)
        target.setdefault("_coverage", {})[field] = {"status": "denied"}
    assert evaluate(cid, deny) == "UNKNOWN"


@pytest.mark.parametrize("cid", ROOT_IDS)
def test_missing_transformation_list_is_unknown(cid):
    assert evaluate(cid, lambda listing: listing[0].pop("metricTransformations")) == "UNKNOWN"


@pytest.mark.parametrize("cid", ROOT_IDS)
def test_omitted_dimensions_and_explicit_empty_pattern_still_cover(cid):
    def omit(listing):
        listing[0]["metricTransformations"][0].pop("dimensions", None)
        listing[0]["filterPattern"] = ""
    assert evaluate(cid, omit) == "PASS"


@pytest.mark.parametrize("cid", ROOT_IDS)
@pytest.mark.parametrize("field", ("logGroupName", "metricName"))
def test_valid_alternative_filter_proves_coverage(cid, field):
    def alternative(listing):
        invalid = copy.deepcopy(listing[0])
        target = invalid["metricTransformations"][0] if field == "metricName" else invalid
        target.setdefault("_coverage", {})[field] = {"status": "denied"}
        listing.insert(0, invalid)
    assert evaluate(cid, alternative) == "PASS"
