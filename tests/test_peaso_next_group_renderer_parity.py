"""Portable regression fixtures for the reviewed Markdown escaping memo.

The expected output digests come from the accepted 24-case old/new renderer
comparison in cspm-markdown-optimization/escape-proposal.  This file has no
runtime dependency on that private comparison or on retained customer data.
"""

import copy
import hashlib
import json

import pytest

from peaso import reports
from peaso.engine import CHECK_META_ENCODING, hydrate_frameworks
import peaso.remediation as remediation


EXPECTED = {
    "compact": "4e922c2737c07d99de9a949a8c324263cc98f8ca081952b970db6d0a15c709c6",
    "expanded": "4e922c2737c07d99de9a949a8c324263cc98f8ca081952b970db6d0a15c709c6",
    "distinct": "f1098c767eec05c3fe1600989b35a4d0bb3375b2a3a1a5cfd7455e0642f543b9",
    "legacy": "3f082e220e49bda0be6cf6e6ba3220280173894dde5f3c67524c2b453bba8b1d",
    "empty": "5db236f4946947c162720e16646f9ca17c685cb685d192d22a5da1eafdc623cf",
    "catalog": "9ea61239058c4b26d41c171c9a5da5e5c5c52ef030e6732acefca1484f9a7248",
    "diff": "0d271bbbc85718fa689adee86cccd9d84e83121412fbcd6f6158b24b1f488618",
    "equal-distinct-and-shared-overrides": "7f0ccaa77e4cabec323f5ad68545f80b6852f60d7887b79885825a5fca7c82eb",
    "mutation-first": "eb831bd17aa2f3e088cb340065c4e948283f6e87f70b5bb5e5fafdb057bbe2c8",
    "mutation-second": "f3bab7cecce45c4edbe48bd881e198642ebc998f124466d5debc87d947c14171",
    "uncommon-default": "b8e75a192b7da20d12f746d4c4fe689f48d3e937c995a650fe449b9b2d98b4c7",
    "uncommon-7": "a05e820581a8693f339bbc871ff7f4b428562dddd4b82215458c3d853fe95d73",
    "in-render-mutation": "7b135f56aba7285438930be6f00065aa65cd51a0b7c226781c5f3fe4a0cdba49",
    "repeated-2000": "b698969069df2effd9f5bcf3497c33c2390b68d71fa9c37bcdf4c17c43185af4",
    "distinct-1200": "a491efa7fe67d4fee5608d842dcf0a4eadf506446299ff8c36a685cd1bc8889f",
}


@pytest.fixture(autouse=True)
def fixture_check_kinds(monkeypatch):
    # The real binder remains in use; only registry identity for synthetic IDs is supplied.
    monkeypatch.setattr(remediation, "_check_kinds", lambda: {"fixture.bucket": "bucket", "fixture.role": "iam_role"})


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def _report(n=12, distinct=False):
    detail = {
        "summary": "Use reviewed action | <tag> `code` é\nnext " + ("meaning " * 400),
        "steps": ["one ** step", "two step", "two step"],
        "cli": [
            {"label": "Account-aware | command", "code": "aws s3api get-bucket-policy --bucket <BUCKET_NAME> --region <REGION> --expected-bucket-owner <ACCOUNT_ID> # <UNKNOWN>"},
            {"label": "Duplicate", "code": "echo <RESOURCE_ARN> ```"},
            {"label": "Duplicate", "code": "echo <RESOURCE_ARN> ```"},
            None,
            {"code": 4},
        ],
        "iac": {"language": "hcl", "label": "quoted [x]", "code": 'resource "x" {} ````'},
        "caveats": ["retain duplicates", "retain duplicates"],
        "references": [{"url": "https://example.com/x?q=1", "title": "safe * ref"}, {"url": "javascript:bad"}, None],
    }
    meta = {
        "title": "Title | <x>", "severity": "high", "category": "hardening", "service": "s3",
        "description": "What | <x> é\nnext", "evaluated": ["a", "a", {"nested": [1, 1.0, True, None, -0.0]}],
        "pass_when": "pass", "fail_when": "fail", "not_applicable_when": "missing", "remediation": "legacy",
    }
    findings = []
    for i in range(n):
        acct = "123456789012" if i % 2 else "999999999999"
        finding = {
            "id": f"f{i}", "check_id": "fixture.bucket", "provider": "aws",
            "scope": acct + "/eu-west-1", "native_resource_id": f"arn:aws:s3:::bucket-{i}",
            "resource_id": f"r{i}", "resource_name": f"bucket-{i}",
            "status": ["FAIL", "PASS", "UNKNOWN", "DENIED", "MANUAL", "NOT_APPLICABLE", "EMPTY"][i % 7],
            "evidence": {"unknown_reason": ["missing", "malformed", "denied", "partial"][i % 4], "duplicates": [1, 1], "raw": "``` | <x> é"},
            "message": "reason | <br>",
        }
        if i % 3 == 0:
            finding["severity"] = "critical"
        if i % 4 == 0:
            finding["frameworks"] = ["F2", "F2", "F1"]
        if distinct:
            finding["remediation_details"] = dict(copy.deepcopy(detail), summary=detail["summary"] + str(i))
        findings.append(finding)
    findings.append(findings[0])
    return {
        "schema_version": "1.1", "provider": "aws", "scopes": ["123456789012/eu-west-1"],
        "snapshot_id": "synthetic", "created_at": "2026-01-01", "stats": {"by_status": {"UNKNOWN": 2}},
        "check_meta_encoding": dict(CHECK_META_ENCODING), "check_meta": {"fixture.bucket": meta},
        "check_frameworks": {"fixture.bucket": ["F1", "F1", "F2"]}, "remediation_templates": {"fixture.bucket": detail},
        "findings": findings,
        "coverage": [{"level": "inventory", "type": "bucket", "status": s, "scope": "x", "reason": s + " | <reason>"} for s in ["missing", "malformed", "denied", "partial", "empty"]],
        "framework_versions": [{"framework_id": "F1", "native_check_ids": ["x", "x"], "mappings": ["partial", "manual", "unknown"]}],
        "snapshot_metadata": {"coverage": "partial", "unknown_reasons": ["missing", "denied"]},
        "resources": [{"id": "r", "type": "bucket", "scope": "x", "data": {"native": ["same", "same"], "config": "```"}}],
        "finding_aggregates": [{"status": "EMPTY", "check_id": "c", "title": "T", "count": 2, "scopes": {"x": 2}, "sample_resource_ids": ["r", "r"]}],
        "graphs": {"iam": {"nodes": [{"id": "n", "evidence": {"unknown": True}}], "edges": []}},
    }


def _assert_frozen(name, value):
    before = _digest(value)
    markdown = reports.render_markdown(value)
    assert _digest(value) == before, "renderer mutated the source report"
    assert hashlib.sha256(markdown.encode()).hexdigest() == EXPECTED[name]
    return markdown


@pytest.mark.parametrize("name", ["compact", "expanded", "distinct", "legacy", "empty", "catalog", "diff"])
def test_representative_report_bytes_and_identity_binding(name):
    value = {
        "compact": _report,
        "expanded": lambda: hydrate_frameworks(_report()),
        "distinct": lambda: _report(24, True),
        "legacy": lambda: {"findings": [{"check_id": "legacy", "description": "legacy desc", "remediation": "legacy | action"}, {"check_id": "legacy", "description": "legacy desc", "remediation": "different"}]},
        "empty": dict,
        "catalog": lambda: {"checks": [{"id": "c", "metadata": ["a", "a"]}]},
        "diff": lambda: {"added": [{"evidence": {"raw": "```"}}], "changed": [], "removed": []},
    }[name]()
    markdown = _assert_frozen(name, value)
    if name == "compact":
        bound = remediation.bind_command(value["remediation_templates"]["fixture.bucket"]["cli"][0]["code"], value["findings"][0])
        assert bound == "aws s3api get-bucket-policy --bucket bucket-0 --region eu-west-1 --expected-bucket-owner 999999999999 # <UNKNOWN>"
        assert bound in markdown


def test_equal_distinct_and_shared_overrides():
    value = _report()
    detail = value["remediation_templates"]["fixture.bucket"]
    value["findings"][1]["remediation_details"] = copy.deepcopy(detail)
    value["findings"][2]["description"] = "override"
    value["findings"][2]["remediation_details"] = detail
    value["findings"][3]["remediation_details"] = {"summary": "", "cli": []}
    value["findings"][3]["remediation"] = "fallback"
    value["findings"][4]["remediation_details"] = []
    _assert_frozen("equal-distinct-and-shared-overrides", value)


def test_nested_mutation_invalidates_reused_escape():
    # Continue the shared/override report used by the accepted old/new experiment.
    value = _report()
    detail = value["remediation_templates"]["fixture.bucket"]
    value["findings"][1]["remediation_details"] = copy.deepcopy(detail)
    value["findings"][2]["description"] = "override"
    value["findings"][2]["remediation_details"] = detail
    value["findings"][3]["remediation_details"] = {"summary": "", "cli": []}
    value["findings"][3]["remediation"] = "fallback"
    value["findings"][4]["remediation_details"] = []
    for replacement in ["first", "second", "second"]:
        value["remediation_templates"]["fixture.bucket"]["steps"][0] = replacement
        _assert_frozen("mutation-" + replacement, value)


class OddDict(dict):
    pass


class OddList(list):
    pass


class OddStr(str):
    pass


UNCOMMON = [1, 1.0, True, -0.0, float("nan"), {"a": [1, 1.0, True, -0.0]}, OddDict(a=1), OddList([1]), OddStr("x"), {1: "v"}]


@pytest.mark.parametrize("index", range(10))
def test_uncommon_values_preserve_original_bytes(index):
    value = _report(2)
    value["findings"][0]["evaluated"] = UNCOMMON[index]
    _assert_frozen("uncommon-7" if index == 7 else "uncommon-default", value)


def test_original_error_types_for_unsupported_json_values():
    value = _report(2)
    value["findings"][0]["evaluated"] = {1}
    with pytest.raises(TypeError):
        reports.render_markdown(value)
    cycle = []
    cycle.append(cycle)
    value["findings"][0]["evaluated"] = cycle
    with pytest.raises(ValueError):
        reports.render_markdown(value)


def test_escape_cache_bounds_and_non_string_fallback():
    memo = reports._RemediationTextMemo()
    for i in range(1100):
        text = "label " + str(i)
        assert memo(text) == reports._remediation_text(text)
    assert len(memo.entries) == 1024 and memo.bytes <= 1024 * 1024
    memo = reports._RemediationTextMemo()
    for i in range(1024):
        text = ("[" * 1000) + str(i)
        assert memo(text) == reports._remediation_text(text)
    assert memo.bytes <= 1024 * 1024 and len(memo.entries) < 1024
    previous = len(memo.entries)
    assert memo("x" * 4097) == reports._remediation_text("x" * 4097)
    assert len(memo.entries) == previous
    for value in ["", OddStr("x"), [1], {"label": "x"}, None, "\ud800"]:
        assert memo(value) == reports._remediation_text(value)


def test_live_in_render_mutation_keeps_frozen_output():
    value = _report(4)
    target = value["remediation_templates"]["fixture.bucket"]

    class Mutator(dict):
        def get(self, key, default=None):
            if key == "remediation_details":
                target["steps"][0] = "mutated"
            return super().get(key, default)

    value["findings"][1] = Mutator(value["findings"][1])
    output = reports.render_markdown(value)
    assert hashlib.sha256(output.encode()).hexdigest() == EXPECTED["in-render-mutation"]


@pytest.mark.parametrize("name,count,distinct", [("repeated-2000", 2000, False), ("distinct-1200", 1200, True)])
def test_large_repeated_and_distinct_reports_keep_exact_bytes(name, count, distinct):
    _assert_frozen(name, _report(count, distinct))
