"""Scope-local IAM attachment memo parity; no provider or privilege evaluation."""
from __future__ import annotations

import pytest

from peaso.checks import claude_aws_a_iam as iam
from peaso.checks.facts import MemoIndex, Unavailable


def index(scope, *, user_arns=(), role_arns=(), group_arns=(), user_groups=(), user_status="collected"):
    def principal(kind, name, arns):
        field = {"iam_user": "UserName", "iam_role": "RoleName", "iam_group": "GroupName"}[kind]
        return {field: name, "AttachedManagedPolicies": [{"PolicyArn": arn} for arn in arns]}

    user = principal("iam_user", "user", user_arns)
    user["GroupList"] = list(user_groups)
    role = principal("iam_role", "role", role_arns)
    group = principal("iam_group", "group", group_arns)
    return {"collections": {kind: [{"type": kind, "scope": scope, "status": user_status if kind == "iam_user" else "collected"}]
                             for kind in ("iam_user", "iam_group", "iam_role")},
            "iam_user": [{"type": "iam_user", "scope": scope, "data": user}],
            "iam_role": [{"type": "iam_role", "scope": scope, "data": role}],
            "iam_group": [{"type": "iam_group", "scope": scope, "data": group}]}


def outcome(function, value):
    try:
        return "ok", function(value)
    except Unavailable as exc:
        return "unavailable", exc.args


def test_two_scopes_and_new_snapshot_same_scope_do_not_share_membership():
    left = index("acct-a/us-east-1", user_arns=["arn:left"])
    right = index("acct-b/us-west-2", role_arns=["arn:right"])
    refreshed = index("acct-a/us-east-1", user_arns=["arn:new"])
    for rows in (left, right, refreshed):
        assert iam.in_use_arns(MemoIndex(rows)) == iam.in_use_arns(rows)
        assert iam.role_attached_arns(MemoIndex(rows)) == iam.role_attached_arns(rows)
    assert iam.in_use_arns(MemoIndex(left)) == {"arn:left"}
    assert iam.in_use_arns(MemoIndex(right)) == {"arn:right"}
    assert iam.in_use_arns(MemoIndex(refreshed)) == {"arn:new"}


def test_duplicate_user_group_and_policy_arns_preserve_original_set_and_copies():
    rows = index("s", user_arns=["arn:dup", "arn:dup"], role_arns=["arn:role", "arn:role"],
                 group_arns=["arn:group", "arn:group"], user_groups=["group", "group"])
    cached = MemoIndex(rows)
    assert iam.in_use_arns(cached) == iam.in_use_arns(rows) == {"arn:dup", "arn:role", "arn:group"}
    changed = iam.in_use_arns(cached)
    changed.add("arn:caller-only")
    assert "arn:caller-only" not in iam.in_use_arns(cached)
    changed = iam.role_attached_arns(cached)
    changed.add("arn:caller-only")
    assert iam.role_attached_arns(cached) == iam.role_attached_arns(rows) == {"arn:role"}


@pytest.mark.parametrize("fault", ["missing", "denied", "malformed"])
def test_missing_denied_and_malformed_facts_replay_same_unavailable(fault):
    rows = index("s", user_arns=["arn:user"])
    if fault == "missing":
        del rows["collections"]["iam_user"]
    elif fault == "denied":
        rows["collections"]["iam_user"][0]["status"] = "denied"
    else:
        rows["iam_user"][0]["data"]["AttachedManagedPolicies"] = [{"PolicyName": "missing ARN"}]
    plain = outcome(iam.in_use_arns, rows)
    assert plain[0] == "unavailable"
    cached = MemoIndex(rows)
    assert outcome(iam.in_use_arns, cached) == plain
    assert outcome(iam.in_use_arns, cached) == plain


def test_one_computation_per_memo_index_but_plain_dict_remains_sequential(monkeypatch):
    rows = index("s", role_arns=["arn:role"])
    calls = []
    original = iam._role_attached_arns

    def counted(value):
        calls.append(1)
        return original(value)

    monkeypatch.setattr(iam, "_role_attached_arns", counted)
    cached = MemoIndex(rows)
    assert iam.role_attached_arns(cached) == iam.role_attached_arns(cached) == {"arn:role"}
    assert len(calls) == 1
    assert iam.role_attached_arns(rows) == iam.role_attached_arns(rows) == {"arn:role"}
    assert len(calls) == 3
