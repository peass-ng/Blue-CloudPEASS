"""Behaviour tests for the claude_aws_b native ports (AWS services fsx..workspaces)."""
from peaso.checks.hacktricks_scope import includes
import copy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, CHECK_ALIASES
from peaso.checks.fixtures import CASES
from peaso.checks import claude_aws_b
from peaso.checks.claude_aws_b_common import IDS, ROWS, CONTEXT, is_policy_public, policy_document, sg_rule_open, add_months, turbot_public_statements

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = {check.id: check for check in CHECKS}
HACKTRICKS = "HackTricks Cloud Best Practices"
RETIRED_SNS_SOURCE = "aws-perimeter.control.sns_topic_policy_prohibit_public_access"
RETIRED_SNS_ID = "aws.cb.sns.policy_prohibit_public_access_perimeter"
ACTIVE_SNS_ID = "aws.cb.sns.policy_no_unrestricted_wildcard"


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
        expected = "UNKNOWN" if cid == "aws.cb.sns.policy_prohibit_public_access_perimeter" else "NOT_APPLICABLE"
        assert _evaluate(cid, "not_applicable") == expected
    assert (HACKTRICKS in check.frameworks) == includes(check.id)
    assert ROWS[cid]


@pytest.mark.parametrize("cid", [c for c in IDS if "pass_index" in CASES[c]])
def test_dependency_missing_is_unknown(cid):
    """A predicate that needs another inventory never guesses without it."""
    check = REGISTRY[cid]
    if cid == "aws.cb.rds.instance_iam_auth_all_engines":
        # The observed enabled instance setting is direct configuration evidence;
        # the conditional capability inventory is needed only for a disabled value.
        assert check.evaluate(copy.deepcopy(CASES[cid]["pass"]), {"context": dict(CONTEXT)})[0] == "PASS"
        assert check.evaluate(copy.deepcopy(CASES[cid]["fail"]), {"context": dict(CONTEXT)})[0] == "UNKNOWN"
        return
    assert check.evaluate(copy.deepcopy(CASES[cid]["pass"]), {"context": dict(CONTEXT)})[0] in ("UNKNOWN", "NOT_APPLICABLE")


def test_partition_dispositions_are_complete():
    partition = json.loads((ROOT / "peaso/rulepacks/port_partitions_claude.json").read_text())["partitions"]["claude_aws_b"]["check_ids"]
    expected = set(partition)
    dispositions = claude_aws_b.dispositions()
    assert expected - set(dispositions) == {RETIRED_SNS_SOURCE}
    assert set(dispositions) == expected - {RETIRED_SNS_SOURCE}
    assert CHECK_ALIASES[RETIRED_SNS_ID] == ACTIVE_SNS_ID
    ported = {row for rows in ROWS.values() for row in rows}
    assert ported <= expected
    for row, (kind, _target) in dispositions.items():
        assert kind in ("ported", "merged", "manual", "rejected")
    for row, (natives, note) in claude_aws_b.MERGED.items():
        assert natives and note and all(cid in REGISTRY for cid in natives), row
        assert row not in ported
    for row, entry in claude_aws_b.MANUAL.items():
        assert entry["question"] and entry["guidance"] and entry["docs"], row
    for row, entry in claude_aws_b.REJECTED.items():
        assert entry["classification"] in ("invalid_predicate", "intrusive_unsuitable") and entry["reason"] and entry["docs"], row
        assert all(cid in REGISTRY for cid in entry["replacement"]), row
    assert not (set(claude_aws_b.MERGED) & set(claude_aws_b.MANUAL)) and not (set(claude_aws_b.MERGED) & set(claude_aws_b.REJECTED))


# Additional named fixtures and the status each one must produce.
EXTRA_EXPECT = {"absent": "PASS", "no_policy": "PASS", "no_config": "PASS", "unlisted": "UNKNOWN", "bundle": "FAIL", "default_key": "FAIL",
                "never": "FAIL", "no_rules": "FAIL", "other_account": "FAIL", "no_set": "FAIL"}
STANDARD = {"pass", "fail", "manual", "unknown", "not_applicable", "missing", "malformed", "index", "case_indices"}
EXTRAS = [(cid, key) for cid in IDS for key in CASES[cid] if key not in STANDARD and not key.endswith(("_index", "_expect"))]


@pytest.mark.parametrize("cid,key", EXTRAS)
def test_named_fixtures(cid, key):
    expected = CASES[cid].get(key + "_expect") or ("PASS" if key.endswith("_pass") else EXTRA_EXPECT[key])
    if key == "no_policy" and cid in {
        "aws.cb.sns.policy_no_unrestricted_wildcard",
        "aws.cb.sns.policy_no_public_publish",
        "aws.cb.sns.policy_no_public_subscribe",
    }:
        expected = "UNKNOWN"
    assert _evaluate(cid, key) == expected


@pytest.mark.parametrize("cid,key", [
    ("aws.cb.sns.policy_no_unrestricted_wildcard", "no_policy"),
    ("aws.cb.sns.policy_no_public_publish", "no_policy"),
    ("aws.cb.sns.policy_no_public_subscribe", "no_policy"),
])
def test_omitted_sns_policy_does_not_prove_absence(cid,key):
    cases=CASES[cid]
    item=copy.deepcopy(cases[key]);index=copy.deepcopy(cases.get(key+"_index",cases.get("index",{})))
    before,before_index=copy.deepcopy(item),copy.deepcopy(index)
    assert REGISTRY[cid].evaluate(item,index)==("UNKNOWN",{"reason":"missing fact: Policy"})
    assert item==before and index==before_index


def test_retired_sns_perimeter_source_keeps_its_historical_receipt():
    reviewed = json.loads((ROOT / "peaso/rulepacks/reviewed_claude_aws_b.json").read_text())
    historical = reviewed[RETIRED_SNS_SOURCE]
    assert historical["native_checks"] == [RETIRED_SNS_ID]
    assert historical["reviewed_source"]["sha256"] == "fc479f89040fe7f5f4426111fa7229cef32f9e7ac909aa955a1a51d6e12ae0d6"
    assert CHECK_ALIASES[RETIRED_SNS_ID] == ACTIVE_SNS_ID
    assert _evaluate(ACTIVE_SNS_ID, "no_policy") == "UNKNOWN"


def test_shards_match_dispositions():
    reviewed = json.loads((ROOT / "peaso/rulepacks/reviewed_claude_aws_b.json").read_text())
    manual = json.loads((ROOT / "peaso/rulepacks/reviewed_claude_aws_b_manual.json").read_text())
    dispositions = claude_aws_b.dispositions()
    assert set(reviewed) | set(manual) == set(dispositions) | {RETIRED_SNS_SOURCE}
    assert not set(reviewed) & set(manual)
    assert reviewed[RETIRED_SNS_SOURCE]["native_checks"] == [RETIRED_SNS_ID]
    assert reviewed[RETIRED_SNS_SOURCE]["reviewed_source"]["sha256"] == "fc479f89040fe7f5f4426111fa7229cef32f9e7ac909aa955a1a51d6e12ae0d6"
    for row, (kind, target) in dispositions.items():
        if kind == "manual":
            entry = manual[row]
            assert entry["disposition"] == "rejected" and entry["review_classification"] == "manual_attestation" and not entry["native_checks"]
            assert entry["manual_requirement"]["question"] == target["question"]
        elif kind == "rejected":
            assert reviewed[row]["disposition"] == "rejected" and not reviewed[row]["native_checks"]
            assert reviewed[row]["review_classification"] == target["classification"]
        else:
            assert reviewed[row]["disposition"] == kind and sorted(reviewed[row]["native_checks"]) == sorted(target)


def test_policy_evaluators():
    public = policy_document('{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}')
    assert is_policy_public(public, "111111111111")
    scoped = policy_document('{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Publish","Condition":{"StringEquals":{"aws:SourceAccount":"111111111111"}}}]}')
    assert not is_policy_public(scoped, "111111111111")
    assert turbot_public_statements(public)
    deny = policy_document('{"Statement":[{"Effect":"Deny","Principal":"*","Action":"*"}]}')
    assert not is_policy_public(deny, "111111111111") and not turbot_public_statements(deny)


def test_security_group_rule_semantics():
    world = [{"CidrIp": "0.0.0.0/0"}]
    assert sg_rule_open({"IpProtocol": "-1", "IpRanges": world, "Ipv6Ranges": []}, "tcp", [5432], any_address=True)
    assert sg_rule_open({"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": world, "Ipv6Ranges": []}, "tcp", [5432], any_address=True)
    assert not sg_rule_open({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": world, "Ipv6Ranges": []}, "tcp", [5432], any_address=True)
    assert not sg_rule_open({"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []}, "tcp", [5432], any_address=True)
    assert sg_rule_open({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": world, "Ipv6Ranges": []}, "tcp", None, any_address=True)


def test_add_months_clamps_month_end():
    from datetime import datetime, timezone
    assert add_months(datetime(2026, 11, 30, tzinfo=timezone.utc), 3) == datetime(2027, 2, 28, tzinfo=timezone.utc)
