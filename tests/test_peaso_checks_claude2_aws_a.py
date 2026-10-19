"""Behaviour tests for the claude2_aws_a native ports and partition dispositions."""
from peaso.checks.hacktricks_scope import includes
import copy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import claude2_aws_a
from peaso.checks.claude2_aws_a_common import CONTEXT, IDS, ROWS, idx, policy_document, principal_aws_values, report_time
from peaso.checks.claude2_aws_a_rows import HELD_ELSEWHERE, QUERY_ROWS

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = {check.id: check for check in CHECKS}
HACKTRICKS = "HackTricks Cloud Best Practices"


def _evaluate(cid, name):
    cases = CASES[cid]
    index = cases.get(name + "_index", cases.get("case_indices", {}).get(name, cases.get("index", {})))
    data, scoped = copy.deepcopy(cases[name]), copy.deepcopy(index)
    before, before_index = copy.deepcopy(data), copy.deepcopy(scoped)
    status = REGISTRY[cid].evaluate(data, scoped)[0]
    assert data == before and scoped == before_index
    return status


@pytest.mark.parametrize("cid", IDS)
def test_pass_fail_unknown(cid):
    check = REGISTRY[cid]
    cases = CASES[cid]
    assert _evaluate(cid, "pass") == "PASS"
    if "fail" in cases:
        assert _evaluate(cid, "fail") == "FAIL"
    else:
        assert _evaluate(cid, "manual") == "MANUAL"
    assert _evaluate(cid, "unknown") == "UNKNOWN"
    assert check.evaluate({}, cases.get("index", {}))[0] == "UNKNOWN"
    assert check.evaluate(None, cases.get("index", {}))[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, cases.get("index", {}))[0] == "UNKNOWN"
    if "not_applicable" in cases:
        assert _evaluate(cid, "not_applicable") == "NOT_APPLICABLE"
    assert (HACKTRICKS in check.frameworks) == includes(check.id)
    assert ROWS[cid]


@pytest.mark.parametrize("cid", [c for c in IDS if len(REGISTRY[c].dependencies or []) > 1 or "pass_index" in CASES[c]])
def test_dependency_missing_is_unknown(cid):
    """A predicate that needs another inventory never guesses without it."""
    check = REGISTRY[cid]
    assert check.evaluate(copy.deepcopy(CASES[cid]["pass"]), {"context": dict(CONTEXT)})[0] in ("UNKNOWN", "NOT_APPLICABLE")


STANDARD = {"pass", "fail", "manual", "unknown", "not_applicable", "missing", "malformed", "index", "case_indices"}
EXTRAS = [(cid, key) for cid in IDS for key in CASES[cid] if key not in STANDARD and not key.endswith(("_index", "_expect"))]


@pytest.mark.parametrize("cid,key", EXTRAS)
def test_named_fixtures(cid, key):
    assert _evaluate(cid, key) == CASES[cid][key + "_expect"]


def test_partition_dispositions_are_complete():
    partition = json.loads((ROOT / "peaso/rulepacks/port_partitions_claude2.json").read_text())["partitions"]["claude2_aws_a"]["check_ids"]
    expected = set(partition)
    assert len(expected) == 323
    assert {row for rows in QUERY_ROWS.values() for row in rows} <= expected
    dispositions = claude2_aws_a.dispositions()
    assert set(dispositions) | set(HELD_ELSEWHERE) == expected and not set(dispositions) & set(HELD_ELSEWHERE)
    ported = set(claude2_aws_a.ported())
    for row, (kind, _target) in dispositions.items():
        assert kind in ("ported", "merged", "manual", "rejected")
    for row, (natives, note) in claude2_aws_a.MERGED.items():
        assert natives and note and all(cid in REGISTRY for cid in natives), row
        assert row not in ported
    for row, entry in claude2_aws_a.REJECTED.items():
        assert entry["classification"] in ("invalid_predicate", "intrusive_unsuitable") and entry["reason"] and entry["docs"], row
        assert all(cid in REGISTRY for cid in entry["replacement"]), row
        assert row not in ported
    assert not set(claude2_aws_a.MERGED) & set(claude2_aws_a.REJECTED)
    assert not claude2_aws_a.MANUAL
    for cid in IDS:
        assert any(row not in HELD_ELSEWHERE for row in ROWS[cid]), cid


def test_shards_match_dispositions():
    reviewed = json.loads((ROOT / "peaso/rulepacks/reviewed_claude2_aws_a.json").read_text())
    manual = json.loads((ROOT / "peaso/rulepacks/reviewed_claude2_aws_a_manual.json").read_text())
    dispositions = claude2_aws_a.dispositions()
    assert set(reviewed) | set(manual) == set(dispositions) and not set(reviewed) & set(manual)
    for row, (kind, target) in dispositions.items():
        entry = reviewed[row]
        assert entry["reviewed_source"]
        if kind == "rejected":
            assert entry["disposition"] == "rejected" and not entry["native_checks"]
            assert entry["review_classification"] == target["classification"] and entry["official_docs"]
        else:
            assert entry["disposition"] == kind and sorted(entry["native_checks"]) == sorted(target)
    assert reviewed["prowler.aws.cloudtrail_multi_region_enabled"]["supersedes"] == "prowler.aws.cloudtrail_multi_region_enabled"


def test_ported_checks_carry_partition_frameworks():
    reviewed = json.loads((ROOT / "peaso/rulepacks/reviewed_claude2_aws_a.json").read_text())
    for cid in IDS:
        assert any(cid in entry["native_checks"] for entry in reviewed.values()), cid


def test_threat_ratio_counts_distinct_names_over_pinned_list():
    cid = "aws.claude2_a.cloudtrail.threat_detection_llm_jacking"
    check = REGISTRY[cid]
    actor = "arn:aws:iam::123456789012:user/x"
    names = ["InvokeModel"] * 20 + ["ListFoundationModels"]
    events = [{"ActorArn": actor, "ActorType": "IAMUser", "EventName": n, "EventTime": "2026-10-10T10:00:00+00:00", "EventId": str(i)}
              for i, n in enumerate(names)]
    # 2 distinct of 14 pinned names = 0.14 <= 0.4: repeated calls of one API never trip the ratio.
    assert check.evaluate({"scope": "123456789012/us-east-1"}, idx(aws_cloudtrail_activity=events))[0] == "PASS"
    other = [dict(e, ActorArn="arn:aws:iam::123456789012:user/y", EventName="Unrelated") for e in events]
    assert check.evaluate({"scope": "123456789012/us-east-1"}, idx(aws_cloudtrail_activity=other))[0] == "PASS"


def test_helpers():
    assert principal_aws_values({"Principal": "*"}) == ["*"]
    assert principal_aws_values({"Principal": {"AWS": "arn:aws:iam::1:root"}}) == ["arn:aws:iam::1:root"]
    assert principal_aws_values({"Principal": {"Service": "logs.amazonaws.com"}}) == []
    assert report_time({"x": "N/A"}, "x") is None and report_time({"x": "no_information"}, "x") is None
    assert policy_document('{"Statement":{"Effect":"Allow","Principal":"*","Action":"*"}}')
