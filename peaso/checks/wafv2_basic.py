"""Proposed WAFv2 rule-group checks; import only after signed admission.

The existing collector fetches ListRuleGroups/GetRuleGroup once. Both metrics
IDs must call ``group_metrics`` on the same engine MemoIndex so the strict
scoped predicate runs once per rule group, without extra AWS requests.
"""
from __future__ import annotations

import re

from peaso.checks import register, result
from peaso.checks.facts import Unavailable, complete_items, get, memoized
from peaso.checks.fixtures import CASES

SPECS = {
    "aws.pci.wafv2.rule_group_metrics": {
        "category": "hardening", "kind": "wafv2_rule_group", "severity": "medium", "control": "AU-12",
        "sha256": "68c0870a052157b9277dc9889347264ae416c566e9b89feb341689648447876b",
        "title": "WAFv2 rule groups publish CloudWatch metrics",
        "remediation": "Enable CloudWatchMetricsEnabled and a nonempty MetricName in each WAFv2 rule-group VisibilityConfig.",
    },
    "aws.pci.wafv2.rule_group_nonempty": {
        "category": "hardening", "kind": "wafv2_rule_group", "severity": "medium", "control": "CM-6",
        "sha256": "0c3e8decee40fc7c33a486fc596b80795e8fc95f0894c2817160622b9b5e705e",
        "title": "WAFv2 rule groups are nonempty",
        "remediation": "Add the required rules to the WAFv2 rule group; delete unused empty groups.",
    },
}
_SCOPE = re.compile(r"^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$")
_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):wafv2:([a-z]{2}(?:-[a-z]+)+-[0-9]):([0-9]{12}):(regional|global)/rulegroup/([^/]+)/([^/]+)$")


def _inventory(index):
    if get(index, "context.provider", str) != "aws":
        raise Unavailable("AWS context authority unavailable")
    scope = get(index, "context.scope", str)
    match = _SCOPE.fullmatch(scope)
    if not match:
        raise Unavailable("AWS account/Region scope unavailable")

    def build():
        envelopes = get(index, "collections", dict).get("wafv2_rule_group")
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable("missing or ambiguous WAFv2 rule-group collection")
        envelope = envelopes[0]
        if (get(envelope, "type", str) != "wafv2_rule_group" or
                get(envelope, "scope", str) != scope or
                get(envelope, "status", str) not in {"collected", "empty", "partial"}):
            raise Unavailable("foreign or incomplete WAFv2 rule-group collection")
        collection_status = get(envelope, "status", str)
        # A partial page still contains exact collected resources. It cannot
        # prove a safe aggregate, but a complete resource detail can prove FAIL.
        rows = (get(envelope, "items", list) if collection_status == "partial" else
                complete_items(index, "wafv2_rule_group"))
        wrappers = get(index, "wafv2_rule_group", list)
        if rows != get(envelope, "items", list) or len(rows) != len(wrappers):
            raise Unavailable("WAFv2 collection projection mismatch")
        by_arn = {}
        for wrapper, row in zip(wrappers, rows):
            if (get(wrapper, "type", str) != "wafv2_rule_group" or
                    get(wrapper, "scope", str) != scope or
                    get(wrapper, "data", dict) != row):
                raise Unavailable("foreign WAFv2 resource wrapper")
            arn = get(row, "ARN", str)
            parsed = _ARN.fullmatch(arn)
            declared_scope = get(row, "Scope", str)
            if (not parsed or parsed.group(2) != match.group(2) or
                    parsed.group(3) != match.group(1) or
                    declared_scope not in {"REGIONAL", "CLOUDFRONT"} or
                    parsed.group(4) != ("global" if declared_scope == "CLOUDFRONT" else "regional") or
                    (declared_scope == "CLOUDFRONT" and match.group(2) != "us-east-1") or
                    arn in by_arn):
                raise Unavailable("foreign, malformed or duplicate WAFv2 rule-group ARN")
            by_arn[arn] = row
        return by_arn, collection_status

    return memoized(index, ("signed_wafv2_rule_group_inventory", scope), build)


def _detail(item, index):
    arn = get(item, "ARN", str)
    inventory, collection_status = _inventory(index)
    row = inventory.get(arn)
    if row is None or row != item:
        raise Unavailable("WAFv2 subject absent or differs from complete inventory")
    detail = get(item, "RuleGroup", dict)
    if get(detail, "ARN", str) != arn:
        raise Unavailable("WAFv2 rule-group detail identity mismatch")
    return arn, detail, collection_status


def group_metrics(item, index):
    """One strict Boolean verdict shared by the signed PCI and existing CB IDs."""
    arn, detail, collection_status = _detail(item, index)
    enabled = memoized(index, ("signed_wafv2_rule_group_metrics", arn),
                       lambda: get(detail, "VisibilityConfig.CloudWatchMetricsEnabled", bool))
    if collection_status == "partial" and enabled:
        raise Unavailable("partial WAFv2 inventory cannot establish metrics pass")
    return arn, enabled


@register("aws.pci.wafv2.rule_group_metrics", "aws", "hardening", "wafv2_rule_group",
          SPECS["aws.pci.wafv2.rule_group_metrics"]["title"], "medium", "AU-12",
          SPECS["aws.pci.wafv2.rule_group_metrics"]["remediation"], dependencies=["wafv2_rule_group"])
def rule_group_metrics(item, index):
    arn, enabled = group_metrics(item, index)
    return result(not enabled, rule_group_arn=arn, cloudwatch_metrics_enabled=enabled)


@register("aws.pci.wafv2.rule_group_nonempty", "aws", "hardening", "wafv2_rule_group",
          SPECS["aws.pci.wafv2.rule_group_nonempty"]["title"], "medium", "CM-6",
          SPECS["aws.pci.wafv2.rule_group_nonempty"]["remediation"], dependencies=["wafv2_rule_group"])
def rule_group_nonempty(item, index):
    arn, detail, collection_status = _detail(item, index)
    rules = get(detail, "Rules", list)
    if any(not isinstance(rule, dict) for rule in rules):
        raise Unavailable("malformed WAFv2 rules")
    names = [get(rule, "Name", str) for rule in rules]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise Unavailable("missing or duplicate WAFv2 rule name")
    if collection_status == "partial" and rules:
        raise Unavailable("partial WAFv2 inventory cannot establish nonempty pass")
    return result(not rules, rule_group_arn=arn, rule_count=len(rules))


def _fixture(enabled, rules):
    arn = "arn:aws:wafv2:us-east-1:111111111111:regional/rulegroup/g/1"
    row = {"Name": "g", "Id": "1", "ARN": arn, "Scope": "REGIONAL",
           "RuleGroup": {"Name": "g", "Id": "1", "ARN": arn, "Capacity": 1,
           "VisibilityConfig": {"SampledRequestsEnabled": True,
                                "CloudWatchMetricsEnabled": enabled, "MetricName": "g"},
           "Rules": rules}}
    scope = "111111111111/us-east-1"
    index = {"context": {"provider": "aws", "scope": scope},
             "collections": {"wafv2_rule_group": [{"type": "wafv2_rule_group", "scope": scope,
                 "status": "collected", "items": [row]}]},
             "wafv2_rule_group": [{"type": "wafv2_rule_group", "scope": scope, "data": row}]}
    return row, index


_metrics_pass, _metrics_pass_index = _fixture(True, [])
_metrics_fail, _metrics_fail_index = _fixture(False, [])
_nonempty_pass, _nonempty_pass_index = _fixture(True, [{
    "Name": "block", "Priority": 0,
    "Statement": {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}},
    "Action": {"Block": {}},
    "VisibilityConfig": {"SampledRequestsEnabled": True,
                         "CloudWatchMetricsEnabled": True, "MetricName": "block"},
}])
_nonempty_fail, _nonempty_fail_index = _fixture(True, [])
CASES["aws.pci.wafv2.rule_group_metrics"] = {
    "pass": _metrics_pass, "pass_index": _metrics_pass_index,
    "fail": _metrics_fail, "fail_index": _metrics_fail_index,
    "missing": {}, "malformed": None,
}
CASES["aws.pci.wafv2.rule_group_nonempty"] = {
    "pass": _nonempty_pass, "pass_index": _nonempty_pass_index,
    "fail": _nonempty_fail, "fail_index": _nonempty_fail_index,
    "missing": {}, "malformed": None,
}
