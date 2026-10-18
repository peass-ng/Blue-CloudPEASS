"""Schema v1.1 extensions of the privilege-escalation catalog: nested requirement groups, AWS request_context,
bound (same-resource) requirements, generic id/name selectors and target.outcome / target.grants."""
from __future__ import annotations

import pytest

from peaso import privesc
from peaso.privesc.schema import (CatalogError, default_outcome, expand_requires, flatten_requirements, load_catalog,
                                  validate_entry)

ACCOUNT = "111111111111"
ALICE = f"arn:aws:iam::{ACCOUNT}:user/alice"


def snapshot(provider, collections):
    cols = [{"type": t, "scope": s, "service": t, "status": st[0] if st else "collected", "items": i, "error": None}
            for t, s, i, *st in collections]
    return {"schema_version": 1, "provider": provider, "scopes": sorted({c["scope"] for c in cols}),
            "collections": cols, "metadata": {}}


def entry(eid, provider, requires, target, **extra):
    return {"id": eid, "provider": provider, "service": "test", "title": eid, "source": "src/x.md",
            "summary": "s", "requires": requires, "target": target, "severity": "high", "mitigation": f"fix {eid}",
            "confidence": "derived", **extra}


def pol(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def user(name, *statements):
    return {"UserName": name, "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}", "GroupList": [], "AttachedManagedPolicies": [],
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": pol(*statements)}] if statements else []}


def role(name, service, path="/"):
    trust = pol({"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"})
    return {"RoleName": name, "Arn": f"arn:aws:iam::{ACCOUNT}:role{path}{name}", "Path": path,
            "AssumeRolePolicyDocument": trust, "RolePolicyList": [], "AttachedManagedPolicies": [], "InstanceProfileList": []}


def aws_snap(users, roles=()):
    scope = f"{ACCOUNT}/us-east-1"
    return snapshot("aws", [("iam_user", scope, list(users)), ("iam_role", scope, list(roles)), ("iam_group", scope, []),
                            ("iam_policy", scope, []), ("scp_policy", scope, [], "empty")])


def allow(action, resource="*", condition=None):
    st = {"Effect": "Allow", "Action": action, "Resource": resource}
    if condition:
        st["Condition"] = condition
    return st


def reached(result, source, technique=None):
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    out = {}
    for edge in result["graph"]["edges"]:
        if edge["source"] != source or (technique and technique not in edge["techniques"]):
            continue
        node = nodes.get(edge["target"], {})
        for member in (node.get("members") if node.get("kind") == "aggregate" and node.get("members") else [edge["target"]]):
            out[member] = edge["confidence"]
    return out


def errors_of(e):
    errs, _ = validate_entry(e, hacktricks_root="/nonexistent-hacktricks")
    return errs


LAMBDA_TARGET = {"kind": "aws_role", "selector": {"trust_allows_service": "lambda.amazonaws.com"}, "scope": "same_account"}


# ---------------------------------------------------------------- nested groups / DNF
def test_expand_requires_keeps_v1_semantics_for_every_catalog_entry():
    for e in load_catalog()["entries"]:
        req = e["requires"]
        if any(isinstance(i, dict) and ("any_of" in i or "all_of" in i) for i in flatten_requirements(req)):
            continue
        base = list(req.get("all_of") or [])
        legacy = [base + list(g) for g in (req.get("any_of") or [])] or [base]
        if not any(isinstance(i, dict) and ({"any_of", "all_of"} & set(i)) for i in base + [x for g in req.get("any_of") or [] for x in g]):
            assert expand_requires(req) == legacy, e["id"]


def test_nested_groups_expand_to_cartesian_product():
    a, b, c, d, x = ({"action": f"s:{n}"} for n in "ABCDX")
    req = {"all_of": [x, {"any_of": [a, [b, c]]}, {"any_of": [d, {"all_of": [a, b]}]}]}
    assert expand_requires(req) == [[x, a, d], [x, a, a, b], [x, b, c, d], [x, b, c, a, b]]
    assert flatten_requirements(req) == [x, a, b, c, d, a, b]
    # top-level any_of groups may contain nested groups too
    assert expand_requires({"all_of": [x], "any_of": [[{"any_of": [a, b]}], [c]]}) == [[x, a], [x, b], [x, c]]
    with pytest.raises(CatalogError):
        expand_requires({"all_of": [{"any_of": [{"action": f"s:A{i}{j}"} for j in range(9)]} for i in range(3)]})


def test_nested_group_validation():
    ok = entry("aws-t-nested", "aws", {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"},
                                                  {"any_of": [{"action": "lambda:InvokeFunction"},
                                                              {"all_of": [{"action": "lambda:CreateFunctionUrlConfig"},
                                                                          {"action": "lambda:InvokeFunctionUrl"}]}]}]},
               LAMBDA_TARGET)
    assert errors_of(ok) == []
    two_keys = entry("aws-t-bad", "aws", {"all_of": [{"any_of": [{"action": "a:B"}], "all_of": [{"action": "a:C"}]}]}, LAMBDA_TARGET)
    assert any("exactly one of all_of/any_of" in e for e in errors_of(two_keys))
    empty = entry("aws-t-bad", "aws", {"all_of": [{"any_of": []}]}, LAMBDA_TARGET)
    assert any("non-empty list" in e for e in errors_of(empty))
    leaf_bad = entry("aws-t-bad", "aws", {"all_of": [{"any_of": [{"action": "nocolon"}]}]}, LAMBDA_TARGET)
    assert any("any_of[0]" in e and "service:Action" in e for e in errors_of(leaf_bad))
    deep = {"action": "a:B"}
    for _ in range(6):
        deep = {"any_of": [deep]}
    assert any("nest deeper" in e for e in errors_of(entry("aws-t-bad", "aws", {"all_of": [deep]}, LAMBDA_TARGET)))
    huge = {"all_of": [{"any_of": [{"action": f"s:A{i}{j}"} for j in range(9)]} for i in range(3)]}
    assert any("exceeds" in e for e in errors_of(entry("aws-t-bad", "aws", huge, LAMBDA_TARGET)))


def test_nested_any_of_is_evaluated():
    e = entry("aws-t-nested", "aws", {"all_of": [
        {"action": "iam:PassRole", "resource": "{target.arn}"},
        {"action": "lambda:CreateFunction"},
        {"any_of": [{"action": "lambda:InvokeFunction"},
                    {"all_of": [{"action": "lambda:CreateFunctionUrlConfig"}, {"action": "lambda:InvokeFunctionUrl"}]}]}]},
        LAMBDA_TARGET)
    url = user("url", allow("iam:PassRole"), allow("lambda:CreateFunction"), allow("lambda:CreateFunctionUrlConfig"),
               allow("lambda:InvokeFunctionUrl"))
    half = user("half", allow("iam:PassRole"), allow("lambda:CreateFunction"), allow("lambda:CreateFunctionUrlConfig"))
    inv = user("inv", allow("iam:PassRole"), allow("lambda:CreateFunction"), allow("lambda:InvokeFunction"))
    result = privesc.analyze(aws_snap([url, half, inv], [role("fn", "lambda.amazonaws.com")]), entries=[e])
    fn = f"arn:aws:iam::{ACCOUNT}:role/fn"
    assert reached(result, f"arn:aws:iam::{ACCOUNT}:user/url") == {fn: "derived"}
    assert reached(result, f"arn:aws:iam::{ACCOUNT}:user/inv") == {fn: "derived"}
    assert reached(result, f"arn:aws:iam::{ACCOUNT}:user/half") == {}


# ---------------------------------------------------------------- request_context (AWS)
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
READONLY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
SELF_ADMIN = {"kind": "aws_account_admin", "selector": {"same_as_source": True, "source_kind": "aws_user"},
              "scope": "same_account"}


def _attach_entry(context=None):
    req = {"action": "iam:AttachUserPolicy", "resource": "{source.arn}"}
    if context is not None:
        req["request_context"] = context
    return entry("aws-t-attach", "aws", {"all_of": [req]}, SELF_ADMIN)


def _alice_with(condition):
    return aws_snap([user("alice", allow("iam:AttachUserPolicy", ALICE, condition))])


def _admin_reach(result):
    return {t: c for t, c in reached(result, ALICE).items()}


def test_request_context_proves_or_refutes_allow_conditions():
    readonly_only = {"ArnEquals": {"iam:PolicyARN": READONLY}}
    admin_ok = {"ArnEquals": {"iam:PolicyARN": [READONLY, ADMIN]}}
    # without request_context the condition is undecidable -> conditional (v1 behaviour)
    assert set(_admin_reach(privesc.analyze(_alice_with(readonly_only), entries=[_attach_entry()])).values()) == {"conditional"}
    # the technique attaches AdministratorAccess: an allow restricted to ReadOnlyAccess does not grant it
    ctx = {"iam:PolicyARN": ADMIN}
    assert _admin_reach(privesc.analyze(_alice_with(readonly_only), entries=[_attach_entry(ctx)])) == {}
    assert set(_admin_reach(privesc.analyze(_alice_with(admin_ok), entries=[_attach_entry(ctx)])).values()) == {"derived"}
    # a list is a choice of ONE value: any admin-equivalent policy the requester may pick
    choice = {"iam:PolicyARN": [READONLY, ADMIN]}
    got = privesc.analyze(_alice_with({"ArnEquals": {"iam:PolicyARN": ADMIN}}), entries=[_attach_entry(choice)])
    assert set(_admin_reach(got).values()) == {"derived"}
    detail = got["graph"]["edges"][0]["technique_details"][0]
    assert any(str(c).startswith("request_context_iam:policyarn=") for c in detail["conditions"])


def test_request_context_applies_to_explicit_denies():
    snap = aws_snap([user("alice", allow("iam:AttachUserPolicy", ALICE),
                          {"Effect": "Deny", "Action": "iam:AttachUserPolicy", "Resource": "*",
                           "Condition": {"ArnEquals": {"iam:PolicyARN": ADMIN}}})])
    assert set(_admin_reach(privesc.analyze(snap, entries=[_attach_entry()])).values()) == {"conditional"}
    assert _admin_reach(privesc.analyze(snap, entries=[_attach_entry({"iam:PolicyARN": ADMIN})])) == {}
    other = {"iam:PolicyARN": "arn:aws:iam::aws:policy/IAMFullAccess"}
    assert set(_admin_reach(privesc.analyze(snap, entries=[_attach_entry(other)])).values()) == {"derived"}


def test_request_context_absent_key():
    boundary = {"StringEquals": {"iam:PermissionsBoundary": f"arn:aws:iam::{ACCOUNT}:policy/Boundary"}}
    req = lambda ctx: entry("aws-t-createrole", "aws", {"all_of": [
        dict({"action": "iam:CreateRole"}, **({"request_context": ctx} if ctx else {})), {"action": "iam:AttachRolePolicy"}]},
        {"kind": "aws_account_admin", "selector": {"same_as_source": True}, "scope": "same_account"})
    snap = aws_snap([user("alice", allow("iam:CreateRole", "*", boundary), allow("iam:AttachRolePolicy"))])
    assert set(_admin_reach(privesc.analyze(snap, entries=[req(None)])).values()) == {"conditional"}
    assert _admin_reach(privesc.analyze(snap, entries=[req({"iam:PermissionsBoundary": {"absent": True}})])) == {}


def test_request_context_validation():
    assert errors_of(_attach_entry({"iam:PolicyARN": ADMIN})) == []
    assert errors_of(_attach_entry({"aws:TagKeys": {"values": ["a", "b"]}, "iam:PermissionsBoundary": {"absent": True}})) == []
    assert any("condition key" in e for e in errors_of(_attach_entry({"PolicyARN": ADMIN})))
    assert any("value must be" in e for e in errors_of(_attach_entry({"iam:PolicyARN": 3})))
    assert any("placeholders" in e for e in errors_of(_attach_entry({"iam:PolicyARN": "{target.arn}"})))
    assert any("combinations" in e for e in errors_of(_attach_entry({f"s:k{i}": ["a", "b"] for i in range(5)})))
    gcp = entry("gcp-t-ctx", "gcp", {"all_of": [{"permission": "iam.serviceAccounts.actAs", "request_context": {"a:b": "c"}}]},
                {"kind": "gcp_service_account", "scope": "same_project"})
    assert any("only evaluated for" in e for e in errors_of(gcp))


# ---------------------------------------------------------------- bind (same attacker-chosen resource)
def _bind_entry(bind=True):
    reqs = [{"action": "lambda:CreateFunction", "resource": f"arn:aws:lambda:*:{{source.account}}:function:*"},
            {"action": "lambda:InvokeFunction", "resource": f"arn:aws:lambda:*:{{source.account}}:function:*"}]
    if bind:
        for r in reqs:
            r["bind"] = "function"
    return entry("aws-t-bind", "aws", {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"}, *reqs]}, LAMBDA_TARGET)


def _fn_arn(pattern):
    return f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{pattern}"


def test_bound_requirements_need_one_common_resource():
    disjoint = user("disjoint", allow("iam:PassRole"), allow("lambda:CreateFunction", _fn_arn("dev-*")),
                    allow("lambda:InvokeFunction", _fn_arn("prod-*")))
    common = user("common", allow("iam:PassRole"), allow("lambda:CreateFunction", _fn_arn("dev-*")),
                  allow("lambda:InvokeFunction", f"arn:aws:lambda:*:{ACCOUNT}:function:*"))
    snap = aws_snap([disjoint, common], [role("fn", "lambda.amazonaws.com")])
    fn = f"arn:aws:iam::{ACCOUNT}:role/fn"
    plain = privesc.analyze(snap, entries=[_bind_entry(False)])
    assert reached(plain, f"arn:aws:iam::{ACCOUNT}:user/disjoint") == {fn: "derived"}   # v1: independent checks
    bound = privesc.analyze(snap, entries=[_bind_entry(True)])
    assert reached(bound, f"arn:aws:iam::{ACCOUNT}:user/disjoint") == {fn: "conditional"}  # never inflated, never dropped
    assert reached(bound, f"arn:aws:iam::{ACCOUNT}:user/common") == {fn: "derived"}
    edge = next(e for e in bound["graph"]["edges"] if e["source"] == f"arn:aws:iam::{ACCOUNT}:user/common")
    assert any(isinstance(r, dict) and r.get("bound_resource", "").startswith(_fn_arn("dev-")) for r in edge["evidence_refs"])
    disjoint_edge = next(e for e in bound["graph"]["edges"] if e["source"] == f"arn:aws:iam::{ACCOUNT}:user/disjoint")
    assert "bound_resource_not_verified" in disjoint_edge["technique_details"][0]["conditions"]


def test_bound_requirement_denied_on_the_common_resource():
    denied = user("denied", allow("iam:PassRole"), allow("lambda:CreateFunction", _fn_arn("*")),
                  allow("lambda:InvokeFunction", _fn_arn("*")),
                  {"Effect": "Deny", "Action": "lambda:InvokeFunction", "Resource": _fn_arn("*")})
    result = privesc.analyze(aws_snap([denied], [role("fn", "lambda.amazonaws.com")]), entries=[_bind_entry(True)])
    assert reached(result, f"arn:aws:iam::{ACCOUNT}:user/denied") == {}


def test_bind_validation():
    assert errors_of(_bind_entry()) == []
    bad = entry("aws-t-bind", "aws", {"all_of": [{"action": "a:B", "resource": "{target.arn}", "bind": "x"},
                                                 {"action": "a:C", "bind": "x"}]}, LAMBDA_TARGET)
    assert any("must not depend on the target" in e for e in errors_of(bad))
    assert any("snake_case" in e for e in errors_of(entry("aws-t-b", "aws", {"all_of": [{"action": "a:B", "bind": "Bad-Name"}]},
                                                          LAMBDA_TARGET)))
    _, warnings = validate_entry(entry("aws-t-b", "aws", {"all_of": [{"action": "a:B", "bind": "solo"}]}, LAMBDA_TARGET),
                                 hacktricks_root="/nonexistent-hacktricks")
    assert any("single requirement" in w for w in warnings)


def test_bind_default_is_conditional_for_other_providers():
    k8s = entry("k8s-t-bind", "k8s", {"all_of": [{"verb": "create", "resource": "pods", "namespace": "a", "bind": "pod"},
                                                 {"verb": "create", "resource": "pods", "subresource": "exec", "namespace": "a",
                                                  "bind": "pod"}]},
                {"kind": "k8s_service_account", "selector": {"k8s_sa_in_namespace": "a"}, "scope": "cluster"})
    assert errors_of(k8s) == []
    role_ = {"kind": "Role", "metadata": {"name": "r", "namespace": "a"}, "provenance": {"cluster_id": "c1"},
             "rules": [{"apiGroups": [""], "resources": ["pods", "pods/exec"], "verbs": ["create"]}]}
    rb = {"kind": "RoleBinding", "metadata": {"name": "rb", "namespace": "a"}, "provenance": {"cluster_id": "c1"},
          "roleRef": {"kind": "Role", "name": "r"}, "subjects": [{"kind": "User", "name": "dev"}]}
    sa = {"kind": "ServiceAccount", "metadata": {"name": "default", "namespace": "a"}, "provenance": {"cluster_id": "c1"}}
    snap = snapshot("k8s", [("role", "c1", [role_]), ("clusterrole", "c1", []), ("rolebinding", "c1", [rb]),
                            ("clusterrolebinding", "c1", []), ("serviceaccount", "c1", [sa]),
                            ("namespace", "c1", [{"kind": "Namespace", "metadata": {"name": "a"}, "provenance": {"cluster_id": "c1"}}]),
                            ("pod", "c1", []), ("node", "c1", [])])
    assert reached(privesc.analyze(snap, entries=[k8s]), "k8s:c1:user:dev") == {"k8s:c1:sa:a:default": "conditional"}


# ---------------------------------------------------------------- generic selectors
def test_generic_target_and_source_globs():
    pass_any = (allow("iam:PassRole"), allow("ec2:RunInstances"))
    snap = aws_snap([user("alice", *pass_any), user("bob", *pass_any)],
                    [role("app-web", "ec2.amazonaws.com"), role("app-batch", "ec2.amazonaws.com"),
                     role("AWSReservedSSO_Admin", "ec2.amazonaws.com", path="/aws-reserved/sso.amazonaws.com/")])
    base = {"kind": "aws_role", "scope": "same_account", "selector": {"trust_allows_service": "ec2.amazonaws.com"}}
    reqs = {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"}, {"action": "ec2:RunInstances"}]}
    by_id = entry("aws-t-glob", "aws", reqs, {**base, "selector": {**base["selector"], "target_id_glob": "*:role/app-*"}})
    by_name = entry("aws-t-name", "aws", reqs, {**base, "selector": {**base["selector"], "target_name_glob": ["*web"]}})
    excl = entry("aws-t-excl", "aws", reqs, {**base, "selector": {**base["selector"],
                                                                 "exclude_target_id_glob": "*:role/aws-reserved/*"}},
                 source_selector={"source_id_glob": "*:user/alice"})
    for e in (by_id, by_name, excl):
        assert errors_of(e) == [], e["id"]
    result = privesc.analyze(snap, entries=[by_id, by_name, excl])
    r = lambda name: f"arn:aws:iam::{ACCOUNT}:role/{name}"
    assert set(reached(result, ALICE, "aws-t-glob")) == {r("app-web"), r("app-batch")}
    assert set(reached(result, ALICE, "aws-t-name")) == {r("app-web")}
    assert set(reached(result, ALICE, "aws-t-excl")) == {r("app-web"), r("app-batch")}
    assert reached(result, f"arn:aws:iam::{ACCOUNT}:user/bob", "aws-t-excl") == {}
    bad = entry("aws-t-glob", "aws", reqs, {**base, "selector": {"target_id_glob": "{target.arn}"}})
    assert any("literal" in e for e in errors_of(bad))
    assert any("glob string" in e for e in errors_of(entry("aws-t-g", "aws", reqs, {**base, "selector": {"target_id_glob": []}})))


# ---------------------------------------------------------------- outcome / grants
def test_outcome_validation_and_defaults():
    ok = entry("aws-t-out", "aws", {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"}]},
               {**LAMBDA_TARGET, "outcome": "workload_execution"})
    assert errors_of(ok) == []
    assert any("membership needs a group" in e for e in errors_of(dict(ok, target={**LAMBDA_TARGET, "outcome": "membership"})))
    assert any("must be one of" in e for e in errors_of(dict(ok, target={**LAMBDA_TARGET, "outcome": "become"})))
    admin = dict(ok, target={**SELF_ADMIN, "outcome": "credentials"})
    assert any("principal (non-group)" in e for e in errors_of(admin))
    self_ok = dict(ok, requires={"all_of": [{"action": "iam:PutUserPolicy", "resource": "{source.arn}"}]})
    assert errors_of(dict(self_ok, target={**SELF_ADMIN, "outcome": "permission_grant", "grants": ["AdministratorAccess"]})) == []
    assert any("grants" in e for e in errors_of(dict(ok, target={**SELF_ADMIN, "grants": "x"})))
    group = {"kind": "k8s_group", "scope": "cluster", "outcome": "impersonation"}
    assert errors_of(entry("k8s-t-imp", "k8s", {"all_of": [{"verb": "impersonate", "resource": "groups"}]}, group)) == []
    assert default_outcome({"kind": "aws_group"}) == "membership"
    assert default_outcome(SELF_ADMIN) == "permission_grant"
    assert default_outcome({"kind": "gcp_scope_owner", "selector": {"any_principal_in_scope": True}}) == "scope_control"
    assert default_outcome({"kind": "entra_role"}) == "role_activation"
    assert default_outcome(LAMBDA_TARGET) == "identity"


def test_outcome_is_reported_on_edges_and_findings():
    authored = entry("aws-t-out", "aws", {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"},
                                                     {"action": "lambda:CreateFunction"}]},
                     {**LAMBDA_TARGET, "outcome": "workload_execution", "grants": ["execution role permissions"]})
    inferred = dict(authored, id="aws-t-inf", target=LAMBDA_TARGET)
    snap = aws_snap([user("alice", allow("iam:PassRole"), allow("lambda:CreateFunction"))], [role("fn", "lambda.amazonaws.com")])
    result = privesc.analyze(snap, entries=[authored, inferred])
    details = {d["id"]: d for e in result["graph"]["edges"] for d in e["technique_details"]}
    assert details["aws-t-out"]["outcome"] == "workload_execution" and details["aws-t-out"]["grants"] == ["execution role permissions"]
    assert "outcome_inferred" not in details["aws-t-out"]
    assert details["aws-t-inf"]["outcome"] == "identity" and details["aws-t-inf"]["outcome_inferred"] is True
    finding = next(f for f in result["findings"] if f["check_id"] == "aws-t-out")
    assert finding["evidence"]["technique"]["outcome"] == "workload_execution"


# ---------------------------------------------------------------- validator script sees nested leaves
def test_validate_script_reports_unknown_permissions_inside_nested_groups():
    import importlib.util
    import pathlib
    path = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "peaso_validate_privesc_catalog.py"
    spec = importlib.util.spec_from_file_location("peaso_validate_privesc_catalog", path)
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    e = entry("aws-t-nested", "aws", {"all_of": [{"action": "iam:PassRole"},
                                                {"any_of": [[{"action": "made:UpOne"}], {"all_of": [{"action": "made:UpTwo"}]}]}],
                                     "any_of": [[{"any_of": [{"action": "made:UpThree"}]}]]}, LAMBDA_TARGET)
    got = script.unknown_permissions([e], {"aws": {"iam:passrole"}})
    assert set(got) == {"made:UpOne", "made:UpTwo", "made:UpThree"}
    assert got["made:UpTwo"] == ["aws-t-nested"]
