"""Tests for the catalog-review follow-ups of the privilege-escalation evaluator."""
from __future__ import annotations

import json

from peaso import privesc
from peaso.privesc.versioned_catalog import _verified_prior
from peaso.privesc.effective_permissions import ANY, Node
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.effective_permissions.azure import AzureModel
from peaso.privesc.schema import validate_entry

ACCOUNT = "111111111111"
OTHER = "222222222222"


def snapshot(provider, collections):
    cols = [{"type": t, "scope": s, "service": t, "status": st[0] if st else "collected", "items": i, "error": None}
            for t, s, i, *st in collections]
    return {"schema_version": 1, "provider": provider, "scopes": sorted({c["scope"] for c in cols}),
            "collections": cols, "metadata": {}}


def entry(eid, provider, requires, target, **extra):
    return {"id": eid, "provider": provider, "service": "test", "title": eid, "source": "src/x.md",
            "summary": "s", "requires": requires, "target": target, "severity": "high", "mitigation": f"fix {eid}",
            "confidence": "derived", **extra}


def catalog_entry(eid):
    return next(e for e in privesc.catalog()["entries"] if e["id"] == eid)


def archived_catalog_entry(eid):
    assert eid not in {e["id"] for e in privesc.catalog()["entries"]}
    prior, _ = _verified_prior()
    return prior[eid]


def edges(result, source=None, technique=None):
    return [e for e in result["graph"]["edges"] if (source is None or e["source"] == source)
            and (technique is None or technique in e["techniques"])]


def reached(result, source, technique=None):
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    out = {}
    for edge in edges(result, source, technique):
        node = nodes.get(edge["target"], {})
        for member in (node.get("members") if node.get("kind") == "aggregate" and node.get("members") else [edge["target"]]):
            out[member] = edge["confidence"]
    return out


# AWS builders --------------------------------------------------------------------
def pol(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def user(name, *statements, account=ACCOUNT):
    return {"UserName": name, "Arn": f"arn:aws:iam::{account}:user/{name}", "GroupList": [], "AttachedManagedPolicies": [],
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": pol(*statements)}] if statements else []}


def role(name, trust, *statements, account=ACCOUNT, profile=False):
    return {"RoleName": name, "Arn": f"arn:aws:iam::{account}:role/{name}", "Path": "/", "AssumeRolePolicyDocument": trust,
            "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": pol(*statements)}] if statements else [],
            "AttachedManagedPolicies": [],
            "InstanceProfileList": [{"Arn": f"arn:aws:iam::{account}:instance-profile/{name}"}] if profile else []}


def trust_service(service):
    return pol({"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"})


def trust_aws(principal):
    return pol({"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"})


def aws_snap(users, roles=(), extra=(), scp=((), "empty")):
    scope = f"{ACCOUNT}/us-east-1"
    return snapshot("aws", [("iam_user", scope, list(users)), ("iam_role", scope, list(roles)), ("iam_group", scope, []),
                            ("iam_policy", scope, []), ("scp_policy", scope, list(scp[0]), scp[1]), *extra])


ALICE = f"arn:aws:iam::{ACCOUNT}:user/alice"
PASS_RUN = ({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"})
EC2_ENTRY = entry("aws-t-ec2", "aws", {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"},
                                                 {"action": "ec2:RunInstances", "resource": "*"}]},
                  {"kind": "aws_role", "selector": {"trust_allows_service": "ec2.amazonaws.com"}, "scope": "same_account"})


# 1. edge dedup -------------------------------------------------------------------------
def test_two_techniques_on_same_pair_share_one_edge():
    second = entry("aws-t-ec2-bis", "aws", {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"}]},
                   {"kind": "aws_role", "selector": {"trust_allows_service": "ec2.amazonaws.com"}, "scope": "same_account"},
                   confidence="conditional")
    snap = aws_snap([user("alice", *PASS_RUN)], [role("ec2-role", trust_service("ec2.amazonaws.com"))])
    result = privesc.analyze(snap, entries=[EC2_ENTRY, second])
    mine = edges(result, ALICE)
    assert len(mine) == 1
    edge = mine[0]
    assert set(edge["techniques"]) == {"aws-t-ec2", "aws-t-ec2-bis"}
    assert edge["confidence"] == "derived"                      # strongest technique wins
    details = {d["id"]: d for d in edge["technique_details"]}
    assert details["aws-t-ec2"]["confidence"] == "derived" and details["aws-t-ec2-bis"]["confidence"] == "conditional"
    assert details["aws-t-ec2"]["mitigation"] == "fix aws-t-ec2" and details["aws-t-ec2"]["evidence_refs"]
    findings = [f for f in result["findings"] if f["resource_id"] == ALICE]
    assert len(findings) == 2 and all(f["evidence"]["edge_ids"] == [edge["id"]] for f in findings)
    assert result["stats"]["distinct_paths"] == 1 and result["stats"]["multi_technique_edges"] == 1


# 4. shared resource intersection ---------------------------------------------------
SHARED = entry("aws-t-shared", "aws", {"all_of": [
    {"action": "lambda:UpdateFunctionCode", "resource": "{target.attached_resource_arn}"},
    {"action": "lambda:InvokeFunction", "resource": "{target.attached_resource_arn}"}]},
    {"kind": "aws_role", "selector": {"attached_to_service": "lambda"}, "scope": "same_account"})


def _fn(name, role_name, policy=None):
    item = {"FunctionName": name, "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{name}",
            "Role": f"arn:aws:iam::{ACCOUNT}:role/{role_name}"}
    if policy:
        item["Policy"] = {"Policy": json.dumps(policy)}
    return item


def _fn_arn(name):
    return f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{name}"


def test_shared_resource_requirements_must_hold_on_the_same_function():
    lam = role("fn-role", trust_service("lambda.amazonaws.com"))
    fns = ("lambda_function", f"{ACCOUNT}/us-east-1", [_fn("f1", "fn-role"), _fn("f2", "fn-role")])
    split = user("alice", {"Effect": "Allow", "Action": "lambda:UpdateFunctionCode", "Resource": _fn_arn("f1")},
                 {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": _fn_arn("f2")})
    assert edges(privesc.analyze(aws_snap([split], [lam], [fns]), entries=[SHARED]), ALICE) == []
    both = user("alice", {"Effect": "Allow", "Action": ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
                          "Resource": _fn_arn("f1")})
    result = privesc.analyze(aws_snap([both], [lam], [fns]), entries=[SHARED])
    (edge,) = edges(result, ALICE)
    assert edge["evidence_refs"][0] == {"shared_resource": _fn_arn("f1")}


# 5a. inherited SCPs ----------------------------------------------------------------------
FULL = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def _scp(pid, target, content):
    return {"Id": pid, "Name": pid, "TargetId": target, "Detail": {"Policy": {"Content": json.dumps(content)}}}


def _scp_snap(ou_policy, parents=True):
    scope = f"{ACCOUNT}/us-east-1"
    extra = [("organization_parent", scope, [{"ChildId": ACCOUNT, "ParentId": "ou-1"},
                                            {"ChildId": "ou-1", "ParentId": "r-root"}] if parents else [])]
    scps = [_scp("p-acct", ACCOUNT, FULL), _scp("p-ou", "ou-1", ou_policy), _scp("p-root", "r-root", FULL)]
    return aws_snap([user("alice", *PASS_RUN)], [role("ec2-role", trust_service("ec2.amazonaws.com"))], extra,
                    scp=(scps, "collected"))


def test_scp_deny_at_ou_removes_edge_and_full_path_is_derived():
    deny = {"Statement": [FULL["Statement"][0], {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}]}
    assert edges(privesc.analyze(_scp_snap(deny), entries=[EC2_ENTRY]), ALICE) == []
    result = privesc.analyze(_scp_snap(FULL), entries=[EC2_ENTRY])
    assert [e["confidence"] for e in edges(result, ALICE)] == ["derived"]


def test_scp_without_ou_path_is_conditional():
    result = privesc.analyze(_scp_snap(FULL, parents=False), entries=[EC2_ENTRY])
    (edge,) = edges(result, ALICE)
    assert edge["confidence"] == "conditional"
    assert "inherited_scps_not_evaluated" in edge["technique_details"][0]["conditions"]
    assert any(c["reason"] == "only directly attached SCPs evaluated" for c in result["coverage"])


# 5b. resource policies ----------------------------------------------------------------
UPDATE = entry("aws-t-update", "aws", {"all_of": [
    {"action": "lambda:UpdateFunctionCode", "resource": "{target.attached_resource_arn}"}]},
    {"kind": "aws_role", "selector": {"attached_to_service": "lambda"}, "scope": "same_account"})


def test_lambda_resource_policy_grants_without_identity_policy():
    rp = pol({"Effect": "Allow", "Principal": {"AWS": ALICE}, "Action": "lambda:UpdateFunctionCode", "Resource": _fn_arn("f1")})
    fns = ("lambda_function", f"{ACCOUNT}/us-east-1", [_fn("f1", "fn-role", rp)])
    snap = aws_snap([user("alice"), user("bob")], [role("fn-role", trust_service("lambda.amazonaws.com"))], [fns])
    result = privesc.analyze(snap, entries=[UPDATE])
    assert reached(result, ALICE) == {f"arn:aws:iam::{ACCOUNT}:role/fn-role": "derived"}
    assert edges(result, f"arn:aws:iam::{ACCOUNT}:user/bob") == []   # same policies, not named by the resource policy


def test_kms_identity_grant_needs_key_policy_delegation_and_cross_account_needs_both():
    key = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/k1"
    alice = user("alice", {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key})
    def model(policy):
        snap = aws_snap([alice], extra=[("kms_key", f"{ACCOUNT}/us-east-1", [{"KeyArn": key, "Policy": {"Policy": json.dumps(policy)}}])])
        m = AwsModel(snap)
        return m, m.principals[ALICE]
    m, a = model(pol({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"}, "Action": "kms:*", "Resource": "*"}))
    assert m._check_action(a, "kms:decrypt", key) is None
    m, a = model(pol({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "kms:*", "Resource": "*"}))
    assert m._check_action(a, "kms:decrypt", key) is not None
    # cross-account bucket: the bucket policy alone is not enough
    bucket = "arn:aws:s3:::other-bucket"
    snap = aws_snap([user("alice")], extra=[("bucket", f"{OTHER}/us-east-1", [{"Name": "other-bucket", "Policy": {"Policy": json.dumps(
        pol({"Effect": "Allow", "Principal": {"AWS": ALICE}, "Action": "s3:PutObject", "Resource": bucket + "/*"}))}}])])
    m = AwsModel(snap)
    assert m._check_action(m.principals[ALICE], "s3:putobject", bucket + "/x") is None


# ECR blocker --------------------------------------------------------------------------
def test_ecr_tag_immutability_blocker():
    repo = f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/app"
    def verdict(mutability, *statements, status="collected"):
        items = [{"repositoryArn": repo, "imageTagMutability": mutability}] if status == "collected" else []
        snap = aws_snap([user("alice", *statements)], extra=[("ecr_repository", f"{ACCOUNT}/us-east-1", items, status)])
        m = AwsModel(snap)
        return m.blocker("ecr_tag_immutability", m.principals[ALICE], {"selector": {"consumer_input_writable_via": "ecr:PutImage"}})
    push = {"Effect": "Allow", "Action": "ecr:PutImage", "Resource": repo}
    assert verdict("IMMUTABLE", push) == "blocked"
    assert verdict("MUTABLE", push) == "clear"
    assert verdict("IMMUTABLE", push, {"Effect": "Allow", "Action": "ecr:PutImageTagMutability", "Resource": repo}) == "clear"
    assert verdict("IMMUTABLE", push, status="denied") is None


# assumable_role_arn ----------------------------------------------------------------------
def test_source_assumable_role_arn_placeholder():
    target = role("app", trust_aws(ALICE))
    alice = user("alice", {"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": f"arn:aws:iam::{ACCOUNT}:role/app"})
    result = privesc.analyze(aws_snap([alice], [target]), entries=[catalog_entry("aws-iam-modify-assumable-role-policy")])
    # The placeholder already restricts the requirement to assumable roles: derived, not "not verified".
    assert reached(result, ALICE) == {f"aws_account_admin:{ACCOUNT}": "derived"}
    other = user("alice", {"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": f"arn:aws:iam::{ACCOUNT}:role/other"})
    assert edges(privesc.analyze(aws_snap([other], [target, role("other", trust_service("ec2.amazonaws.com"))]),
                                 entries=[catalog_entry("aws-iam-modify-assumable-role-policy")]), ALICE) == []


# assumable_by_pivot_role ----------------------------------------------------------------
def test_stackset_reaches_execution_roles_assumable_by_pivot():
    admin_arn = f"arn:aws:iam::{ACCOUNT}:role/stackset-admin"
    admin = role("stackset-admin", trust_service("cloudformation.amazonaws.com"),
                 {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::*:role/exec-*"})
    exec_a = role("exec-a", trust_aws(admin_arn))
    exec_b = role("exec-b", trust_aws(f"arn:aws:iam::{ACCOUNT}:root"), account=OTHER)
    unrelated = role("ec2-role", trust_service("ec2.amazonaws.com"))
    alice = user("alice", {"Effect": "Allow", "Action": "iam:PassRole", "Resource": admin_arn},
                 {"Effect": "Allow", "Action": ["cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"], "Resource": "*"})
    snap = aws_snap([alice], [admin, exec_a, unrelated], [("iam_role", f"{OTHER}/us-east-1", [exec_b])])
    result = privesc.analyze(snap, entries=[catalog_entry("aws-cloudformation-passrole-stackset")])
    assert set(reached(result, ALICE)) == {f"arn:aws:iam::{ACCOUNT}:role/exec-a", f"arn:aws:iam::{OTHER}:role/exec-b"}
    nopass = user("alice", {"Effect": "Allow", "Action": ["cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"],
                            "Resource": "*"})
    snap = aws_snap([nopass], [admin, exec_a])
    assert edges(privesc.analyze(snap, entries=[catalog_entry("aws-cloudformation-passrole-stackset")]), ALICE) == []
    scoped_create = user("alice", {"Effect": "Allow", "Action": "iam:PassRole", "Resource": admin_arn},
                         {"Effect": "Allow", "Action": "cloudformation:CreateStackSet",
                          "Resource": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stackset/example:*"},
                         {"Effect": "Allow", "Action": "cloudformation:CreateStackInstances", "Resource": "*"})
    snap = aws_snap([scoped_create], [admin, exec_a])
    assert edges(privesc.analyze(snap, entries=[catalog_entry("aws-cloudformation-passrole-stackset")]), ALICE) == []


# validator: target ARN on entity targets ------------------------------------------------
def test_validator_rejects_target_arn_on_entity_kind():
    bad = entry("aws-t-bad", "aws", {"all_of": [{"action": "iam:PutRolePolicy", "resource": "{target.arn}"}]},
                {"kind": "aws_account_admin", "selector": {"any_principal_in_scope": True}, "scope": "same_account"})
    errors, _ = validate_entry(bad, hacktricks_root="/nonexistent")
    assert any("cannot resolve on entity target kind aws_account_admin" in e for e in errors)
    good = dict(bad, requires={"all_of": [{"action": "iam:PutRolePolicy", "resource": "{source.assumable_role_arn}"}]})
    assert validate_entry(good, hacktricks_root="/nonexistent")[0] == []


def test_validator_gcp_k8s_service_account_needs_join_selector():
    base = entry("gcp-t-ksa", "gcp", {"all_of": [{"permission": "container.secrets.list", "resource": "{target.scope}"}]},
                 {"kind": "k8s_service_account", "selector": {"k8s_sa_has_token_secret": True}, "scope": "cluster"})
    assert validate_entry(base, hacktricks_root="/nonexistent")[0] == []
    errors, _ = validate_entry(hacktricks_root="/nonexistent", entry=dict(base, target={"kind": "k8s_service_account", "selector": {}, "scope": "cluster"}))
    assert any("k8s_sa_has_token_secret" in e for e in errors)


# Azure controlled user ------------------------------------------------------------------
def test_controlled_user_placeholder():
    model = AzureModel(snapshot("azure", []))
    me = Node("u1", "azure_user", "azure", "tenant", "u1")
    sp = Node("sp1", "azure_service_principal", "azure", "tenant", "sp1")
    for name in ("{source.controlled_user}", "{target.user}"):
        assert model.resolve(name, me, None)[0] == ["dir:u1"]
        refs, floor = model.resolve(name, sp, None)
        assert refs == [ANY] and floor == ("conditional", "controlled_user_not_identified")


# GCP ------------------------------------------------------------------------------------
def gcp_snap(bindings, sas=(), roles=(), extra=(), ancestry=()):
    return snapshot("gcp", [
        ("project", "projects/p1", [{"projectId": "p1", "name": "projects/123", "_ancestry": list(ancestry)}]),
        ("iam_policy", "projects/p1", [{"name": "projects/p1", "bindings": bindings}]),
        ("iam_role", "projects/p1", list(roles)), ("service_account", "projects/p1", list(sas)),
        ("iam_deny_policy", "projects/p1", [], "empty"), *extra])


def gsa(email, policy=None):
    return {"email": email, "projectId": "p1", "name": f"projects/p1/serviceAccounts/{email}", "iamPolicy": policy or {}}


def test_gcp_implicit_delegation_chain():
    a, b, c = (f"{n}@p1.iam.gserviceaccount.com" for n in ("a", "b", "c"))
    delegator = {"name": "projects/p1/roles/delegator", "includedPermissions": ["iam.serviceAccounts.implicitDelegation"]}
    minter = {"name": "projects/p1/roles/minter", "includedPermissions": ["iam.serviceAccounts.getAccessToken"]}
    sas = [gsa(a, {"bindings": [{"role": "projects/p1/roles/delegator", "members": ["user:alice@x.com"]}]}),
           gsa(b, {"bindings": [{"role": "projects/p1/roles/delegator", "members": [f"serviceAccount:{a}"]}]}),
           gsa(c, {"bindings": [{"role": "projects/p1/roles/minter", "members": [f"serviceAccount:{b}"]}]})]
    chain = entry("gcp-t-delegation", "gcp", {"all_of": [{"permission": "iam.serviceAccounts.implicitDelegation", "resource": "*"}]},
                  {"kind": "gcp_service_account", "selector": {"gcp_implicit_delegation_chain": True}, "scope": "any"})
    result = privesc.analyze(gcp_snap([], sas, [delegator, minter]), entries=[chain])
    assert reached(result, "user:alice@x.com") == {f"serviceAccount:{c}": "derived"}   # delegates a, b are not targets


GKE = "projects/p1/locations/us-central1/clusters/c1"
CLUSTER = ("gke_cluster", "projects/p1", [{"name": "c1", "location": "us-central1",
                                           "selfLink": f"https://container.googleapis.com/v1/{GKE}"}])
SECRETS = {"name": "projects/p1/roles/secrets", "includedPermissions": ["container.secrets.list"]}
TOKEN = entry("gcp-t-token-secret", "gcp", {"all_of": [{"permission": "container.secrets.list", "resource": "{target.scope}"}]},
              {"kind": "k8s_service_account", "selector": {"k8s_sa_has_token_secret": True}, "scope": "cluster"})


def _k8s(secrets=None):
    def obj(kind, name, ns, **body):
        return {"kind": kind, "metadata": {"name": name, "namespace": ns, **body.pop("meta", {})},
                "provenance": {"cluster_id": GKE}, **body}
    cols = [("serviceaccount", "c1", [obj("ServiceAccount", n, "a") for n in ("builder", "default")]),
            ("role", "c1", []), ("clusterrole", "c1", []), ("rolebinding", "c1", []), ("clusterrolebinding", "c1", [])]
    if secrets is not None:
        cols.append(("secret", "c1", [obj("Secret", "builder-token", "a", type="kubernetes.io/service-account-token",
                                          meta={"annotations": {"kubernetes.io/service-account.name": "builder"}}),
                                      obj("Secret", "other", "a", type="Opaque")]))
    return snapshot("k8s", cols)


def test_gcp_token_secret_targets_without_join_are_unresolved():
    snap = gcp_snap([{"role": "projects/p1/roles/secrets", "members": ["user:alice@x.com"]}], roles=[SECRETS], extra=[CLUSTER])
    result = privesc.analyze(snap, entries=[TOKEN], include_unknown=True)
    got = reached(result, "user:alice@x.com")
    assert len(got) == 1 and next(iter(got)).startswith("unresolved:k8s_service_account:") and list(got.values()) == ["unknown"]
    assert edges(privesc.analyze(gcp_snap([], roles=[SECRETS], extra=[CLUSTER]), entries=[TOKEN])) == []


def test_gcp_token_secret_targets_joined_with_k8s_snapshot():
    snap = gcp_snap([{"role": "projects/p1/roles/secrets", "members": ["user:alice@x.com"]}], roles=[SECRETS], extra=[CLUSTER])
    result = privesc.analyze(snap, entries=[TOKEN], related_snapshots=[_k8s(secrets=True)])
    assert reached(result, "user:alice@x.com") == {f"k8s:{GKE}:sa:a:builder": "derived"}
    result = privesc.analyze(snap, entries=[TOKEN], related_snapshots=[_k8s()], include_unknown=True)
    # Joined snapshot without Secret metadata: not proven, one unresolved placeholder (no members).
    got = reached(result, "user:alice@x.com")
    assert list(got.values()) == ["unknown"] and next(iter(got)).startswith("unresolved:k8s_service_account:")
    node = next(n for n in result["graph"]["nodes"] if n["id"] == next(iter(got)))
    assert node["label"].startswith("Unresolved: ") and node["underlying_count"] == 0 and node["members"] == []


def test_gcp_token_secret_join_matches_collector_origin_digest_and_secret_metadata():
    """Real K8s collector shape: items carry no cluster_id, the snapshot metadata holds
    `k8s-cluster:<sha256(https://endpoint)>`, and Secrets are collected as `secret_metadata`."""
    import hashlib
    cluster = ("gke_cluster", "projects/p1", [{**CLUSTER[2][0], "endpoint": "34.1.2.3"}])
    cid = "k8s-cluster:" + hashlib.sha256(b"https://34.1.2.3").hexdigest()
    def obj(kind, name, **body):
        return {"kind": kind, "metadata": {"name": name, "namespace": "a", **body.pop("meta", {})}, **body}
    k8s = snapshot("k8s", [
        ("serviceaccount", "*", [obj("ServiceAccount", n) for n in ("builder", "default")]),
        ("secret_metadata", "*", [obj("PartialObjectMetadata", "builder-token", type="kubernetes.io/service-account-token",
                                      meta={"annotations": {"kubernetes.io/service-account.name": "builder"}})])])
    k8s["metadata"] = {"cluster_id": cid, "context": "gke_p1_us-central1_c1"}
    snap = gcp_snap([{"role": "projects/p1/roles/secrets", "members": ["user:alice@x.com"]}], roles=[SECRETS], extra=[cluster])
    result = privesc.analyze(snap, entries=[TOKEN], related_snapshots=[k8s])
    assert reached(result, "user:alice@x.com") == {f"k8s:{cid}:sa:a:builder": "derived"}


def test_gcp_workspace_super_admin_reaches_org_owner_only():
    ws = archived_catalog_entry("gcp-workspace-super-admin-org-admin")
    ancestry = [{"resourceId": {"type": "project", "id": "p1"}}, {"resourceId": {"type": "organization", "id": "42"}}]
    users = ("workspace_user", "customers/C1", [{"primaryEmail": "boss@x.com", "id": "1", "isAdmin": True},
                                                {"primaryEmail": "alice@x.com", "id": "2", "isAdmin": False}])
    result = privesc.analyze(gcp_snap([{"role": "roles/viewer", "members": ["user:alice@x.com"]}], extra=[users],
                                      ancestry=ancestry), entries=[ws])
    assert reached(result, "user:boss@x.com") == {"gcp_scope_owner:organizations/42": "derived"}
    assert edges(result, "user:alice@x.com") == []
    result = privesc.analyze(gcp_snap([{"role": "roles/viewer", "members": ["user:alice@x.com"]}], ancestry=ancestry), entries=[ws])
    assert result["graph"]["edges"] == []
    assert any(c["reason"] == "gcp_workspace_admin_role not evaluated" for c in result["coverage"])


# K8s ------------------------------------------------------------------------------------
def _k8s_cluster(ns_annotations=None, sa_annotations=None):
    def obj(kind, name, ns=None, annotations=None, **body):
        meta = {"name": name, **({"namespace": ns} if ns else {}), **({"annotations": annotations} if annotations else {})}
        return {"kind": kind, "metadata": meta, "provenance": {"cluster_id": "c1"}, **body}
    return snapshot("k8s", [
        ("role", "c1", [obj("Role", "pod-creator", "a", rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}])]),
        ("clusterrole", "c1", []),
        ("rolebinding", "c1", [obj("RoleBinding", "rb", "a", roleRef={"kind": "Role", "name": "pod-creator"},
                                   subjects=[{"kind": "User", "name": "dev"}])]),
        ("clusterrolebinding", "c1", []),
        ("serviceaccount", "c1", [obj("ServiceAccount", "app", "a", sa_annotations)]),
        ("namespace", "c1", [obj("Namespace", "a", annotations=ns_annotations), obj("Namespace", "b")]),
        ("pod", "c1", []), ("node", "c1", [])])


def test_related_snapshot_joins_irsa_identity_to_iam_role():
    arn = f"arn:aws:iam::{ACCOUNT}:role/app-web"
    k8s = _k8s_cluster(sa_annotations={"eks.amazonaws.com/role-arn": arn})
    aws = aws_snap([], [role("app-web", trust_service("ec2.amazonaws.com"))])
    result = privesc.analyze(k8s, related_snapshots=[aws])
    cross = edges(result, f"cloud:irsa:{arn}", "cloud-identity-join")
    assert [e["target"] for e in cross] == [arn]
    assert result["stats"]["cross_snapshot_edges"] >= 1 and result["stats"]["related_snapshots"] == ["aws"]
    joined = next(n for n in result["graph"]["nodes"] if n["id"] == arn)
    assert joined["provider"] == "aws" and joined["attrs"]["related_snapshot"]
    assert edges(privesc.analyze(k8s), f"cloud:irsa:{arn}", "cloud-identity-join") == []
