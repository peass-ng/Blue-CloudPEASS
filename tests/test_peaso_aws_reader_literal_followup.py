"""Registered AWS control coverage authority at two manually read fields."""
import copy
import json
from pathlib import Path

import pytest

from peaso.checks import evaluate_check
from peaso.checks.fixtures import CASES


CF = "aws_cloudfront_origin_failover_configured"
LB = "aws_g6_elbv2_only_https_tls_listeners"
LB_CASES = json.loads((Path(__file__).parent / "fixtures/post_dfaf_aws.json").read_text())


def cloudfront(name):
    return copy.deepcopy(CASES[CF][name])


def load_balancer(name):
    case = copy.deepcopy(next(row for row in LB_CASES if row["id"] == LB and row["name"] == name))
    return case["item"], case["index"]


def lb_verdict(item, index):
    index["collections"]["load_balancer_v2"][0]["items"][0] = item
    index["load_balancer_v2"][0]["data"] = item
    return evaluate_check(LB, item, index)[0]


def test_original_registered_verdicts_and_documented_omission():
    assert evaluate_check(CF, cloudfront("pass"), {})[0] == "PASS"
    assert evaluate_check(CF, cloudfront("fail"), {})[0] == "FAIL"
    omitted = cloudfront("pass")
    del omitted["Config"]["DistributionConfig"]["OriginGroups"]
    assert evaluate_check(CF, omitted, {})[0] == "FAIL"
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"),
                           ("partial_listener_observed_http", "FAIL")):
        assert lb_verdict(*load_balancer(name)) == expected


@pytest.mark.parametrize("marker", (None, {"status": "empty"}))
def test_cloudfront_origin_groups_coverage(marker):
    item = cloudfront("pass")
    item["Config"]["DistributionConfig"]["_coverage"] = {"OriginGroups": marker}
    assert evaluate_check(CF, item, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("level", ("Listeners", "items"))
@pytest.mark.parametrize("marker", (None, {"status": "empty"}))
def test_listener_field_coverage(level, marker):
    item, index = load_balancer("pass")
    parent = item if level == "Listeners" else item["Listeners"]
    parent["_coverage"] = {level: marker}
    assert lb_verdict(item, index) == "UNKNOWN"


@pytest.mark.parametrize("marker,expected", [
    ({"status": "empty"}, "FAIL"),
    ({"status": "collected"}, "UNKNOWN"),
    (None, "UNKNOWN"),
    ({"status": "denied"}, "UNKNOWN"),
])
def test_cloudfront_omitted_origin_groups_coverage(marker, expected):
    item = cloudfront("pass")
    config = item["Config"]["DistributionConfig"]
    del config["OriginGroups"]
    config["_coverage"] = {"OriginGroups": marker}
    assert evaluate_check(CF, item, {})[0] == expected
