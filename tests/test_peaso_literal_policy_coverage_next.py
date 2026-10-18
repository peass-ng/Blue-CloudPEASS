"""Literal owner-policy coverage follows the shared facts contract."""
from __future__ import annotations

import copy
import importlib
import importlib.util
from functools import lru_cache
from pathlib import Path

import pytest


@lru_cache(maxsize=None)
def _fixtures(name):
    path = Path(__file__).with_name(f"test_peaso_compliance_new_{name}.py")
    spec = importlib.util.spec_from_file_location(f"_literal_policy_{name}_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    from peaso.checks import CHECKS
    before = list(CHECKS)
    try:
        CHECKS[:] = []
        spec.loader.exec_module(module)
        if name == "sw12":
            module.api = importlib.import_module("peaso.checks.compliance_new_sw12")
    finally:
        CHECKS[:] = before
    if name == "sw16" and not module.OWN_CHECKS:
        module.OWN_CHECKS = {check.id: check for check in before if check.id in module.api.IDS}
    return module


def _case(name):
    if name == "sw07":
        from peaso.checks import evaluate_check
        cid = "aws_wafv2_blanket_rate_rule"
        scope = "123456789012/us-east-1"
        arn = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/example/abc"
        rule = {"Statement": {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}},
                "Action": {"Block": {}}}
        row = {"ARN": arn, "WebACL": {"ARN": arn, "Rules": [rule]}}
        mapping = {arn: 100}
        index = {"context": {"provider": "aws", "scope": scope, "metadata": {
            "compliance_policy": {"status": "collected", "scope": scope,
                                  "wafv2_request_ceilings": mapping}}},
            "collections": {"wafv2_web_acl": [{"type": "wafv2_web_acl", "scope": scope,
                "status": "collected", "items": [row]}]},
            "wafv2_web_acl": [{"type": "wafv2_web_acl", "scope": scope, "data": row}]}
        return lambda: evaluate_check(cid, row, index)[0], mapping, arn
    fixture = _fixtures(name)
    if name == "sw12":
        cid = fixture.IDS[0]
        item, index = fixture.case(cid)
        module = fixture.api
        mapping = index["context"]["metadata"]["compliance_policy"]["sw12"]["checks"]
        return lambda: fixture.grade(module, cid, item, index), mapping, cid
    if name == "sw16":
        cid = fixture.api.IDS[2]
        index = fixture.BUILDERS[cid]()
        mapping = index["context"]["metadata"]["compliance_policy"]["sw16"]
        return lambda: fixture.evaluate(cid, index)[0], mapping, cid
    cid = fixture.mod.STALE
    row, extras, policy = fixture.fixture(cid)
    index = fixture.inventory(row, fixture.mod.SPECS[cid]["resource_kind"], extras=extras, policy=policy)
    mapping = index["context"]["metadata"]["compliance_policy"]["sw19"]
    return lambda: fixture.invoke(cid, row, index)[0], mapping, cid


@pytest.mark.parametrize("name", ("sw07", "sw12", "sw16", "sw19"))
@pytest.mark.parametrize("marker,expected", (
    (None, "UNKNOWN"),
    ({"status": "empty"}, "UNKNOWN"),
    ({"status": "denied"}, "UNKNOWN"),
    ("malformed", "UNKNOWN"),
    ({"status": "collected"}, "PASS"),
))
def test_literal_policy_coverage(name, marker, expected):
    evaluate, mapping, key = _case(name)
    assert evaluate() == "PASS"  # Original registered positive fixture, absent marker.
    mapping.setdefault("_coverage", {})[key] = copy.deepcopy(marker)
    assert evaluate() == expected
