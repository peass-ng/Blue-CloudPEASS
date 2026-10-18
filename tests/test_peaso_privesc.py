"""Tests for the read-only privilege-escalation evaluator (peaso.privesc)."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from peaso import privesc
from peaso.privesc import queries
from peaso.privesc.schema import load_catalog

FIXTURE_CATALOG = Path(__file__).parent / "fixtures" / "privesc" / "catalog"
ACCOUNT = "111111111111"


# --------------------------------------------------------------------------- builders
def snapshot(provider, collections, metadata=None):
    cols = []
    for ctype, scope, items, *status in collections:
        cols.append({"type": ctype, "scope": scope, "service": ctype, "status": status[0] if status else "collected",
                     "items": items, "error": None})
    return {"schema_version": 1, "provider": provider, "scopes": sorted({c["scope"] for c in cols}),
            "collections": cols, "metadata": metadata or {}}


def run(snap, **kw):
    return privesc.analyze(snap, FIXTURE_CATALOG, **kw)


def edges_from(result, source, technique=None):
    return [e for e in result["graph"]["edges"] if e["source"] == source
            and (technique is None or technique in e["techniques"])]


def reached(result, source, technique=None):
    """Concrete principals reached from source (aggregates expanded)."""
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    out = {}
    for edge in edges_from(result, source, technique):
        node = nodes.get(edge["target"], {})
        members = node.get("members") if node.get("kind") == "aggregate" else [edge["target"]]
        for member in members or []:
            out[member] = edge["confidence"]
    return out


# AWS ----------------------------------------------------------------------------
def aws_policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def aws_trust(service):
    return aws_policy({"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"})


def aws_user(name, *statements):
    return {"UserName": name, "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}", "GroupList": [],
            "UserPolicyList": [{"PolicyName": f"{name}-inline", "PolicyDocument": aws_policy(*statements)}] if statements else [],
            "AttachedManagedPolicies": []}


def aws_role(name, service, profile=True):
    role = {"RoleName": name, "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}", "Path": "/",
            "AssumeRolePolicyDocument": aws_trust(service), "RolePolicyList": [], "AttachedManagedPolicies": [],
            "InstanceProfileList": []}
    if profile:
        role["InstanceProfileList"] = [{"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/{name}"}]
    return role


def aws_snapshot(users, roles=(), groups=(), extra=(), scp_status="collected"):
    scope = f"{ACCOUNT}/us-east-1"
    cols = [("iam_user", scope, list(users)), ("iam_role", scope, list(roles)), ("iam_group", scope, list(groups)),
            ("iam_policy", scope, []), ("scp_policy", scope, [], scp_status), *extra]
    return snapshot("aws", cols)


PASS_RUN = [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}]


def test_aws_passrole_runinstances_reaches_only_ec2_role_with_profile():
    snap = aws_snapshot([aws_user("alice", *PASS_RUN)], [
        aws_role("ec2-role", "ec2.amazonaws.com"),
        aws_role("ec2-noprofile", "ec2.amazonaws.com", profile=False),
        aws_role("lambda-role", "lambda.amazonaws.com"),
    ], scp_status="empty")
    result = run(snap)
    alice = f"arn:aws:iam::{ACCOUNT}:user/alice"
    hit = reached(result, alice, "aws-ec2-passrole-runinstances")
    assert set(hit) == {f"arn:aws:iam::{ACCOUNT}:role/ec2-role"}
    assert hit[f"arn:aws:iam::{ACCOUNT}:role/ec2-role"] == "derived"
    finding = next(f for f in result["findings"] if f["check_id"] == "aws-ec2-passrole-runinstances")
    assert finding["category"] == "privesc" and finding["resource_id"] == alice
    assert finding["frameworks"] == ["HackTricks Cloud Best Practices"]
    assert finding["evidence"]["granting_statements"]
    # lambda-role is not reached by the EC2 technique (no lambda:CreateFunction either)
    assert f"arn:aws:iam::{ACCOUNT}:role/lambda-role" not in reached(result, alice)


def test_aws_explicit_deny_removes_edge():
    deny = {"Effect": "Deny", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{ACCOUNT}:role/ec2-role"}
    snap = aws_snapshot([aws_user("alice", *PASS_RUN, deny)], [aws_role("ec2-role", "ec2.amazonaws.com")], scp_status="empty")
    result = run(snap)
    assert reached(result, f"arn:aws:iam::{ACCOUNT}:user/alice", "aws-ec2-passrole-runinstances") == {}


@pytest.mark.parametrize("condition,expected", [
    # undecidable from a snapshot (MFA is a property of the session): conditional, not FAIL
    ({"Bool": {"aws:MultiFactorAuthPresent": "true"}}, "conditional"),
    # proven by the technique: the role is passed to EC2
    ({"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}, "derived"),
    # proven to exclude the technique: the edge is dropped
    ({"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}, None),
])
def test_aws_condition_makes_edge_conditional(condition, expected):
    cond = [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*", "Condition": condition}, PASS_RUN[1]]
    snap = aws_snapshot([aws_user("alice", *cond)], [aws_role("ec2-role", "ec2.amazonaws.com")], scp_status="empty")
    hit = reached(run(snap), f"arn:aws:iam::{ACCOUNT}:user/alice", "aws-ec2-passrole-runinstances")
    assert hit == ({f"arn:aws:iam::{ACCOUNT}:role/ec2-role": expected} if expected else {})


def test_aws_scp_not_collected_is_conditional_with_coverage():
    snap = aws_snapshot([aws_user("alice", *PASS_RUN)], [aws_role("ec2-role", "ec2.amazonaws.com")], scp_status="denied")
    result = run(snap)
    hit = reached(result, f"arn:aws:iam::{ACCOUNT}:user/alice", "aws-ec2-passrole-runinstances")
    assert hit == {f"arn:aws:iam::{ACCOUNT}:role/ec2-role": "conditional"}
    assert any(c["kind"] == "guardrail" and c["status"] == "denied" for c in result["coverage"])


def test_aws_denied_role_collection_gives_unknown_and_coverage():
    scope = f"{ACCOUNT}/us-east-1"
    snap = snapshot("aws", [("iam_user", scope, [aws_user("alice", *PASS_RUN)]), ("iam_role", scope, [], "denied"),
                            ("iam_group", scope, []), ("iam_policy", scope, []), ("scp_policy", scope, [], "empty")])
    # Missing role inventory is diagnostic only when unknown reaches are requested.
    assert not edges_from(run(snap), f"arn:aws:iam::{ACCOUNT}:user/alice", "aws-ec2-passrole-runinstances")
    result = run(snap, include_unknown=True)
    alice = f"arn:aws:iam::{ACCOUNT}:user/alice"
    edges = edges_from(result, alice, "aws-ec2-passrole-runinstances")
    assert edges and all(e["confidence"] == "unknown" for e in edges)
    assert any(c["status"] == "denied" and "iam_role" in c["reason"] for c in result["coverage"])


def test_aws_lambda_passrole_does_not_reach_ec2_role():
    stmts = [{"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}]
    snap = aws_snapshot([aws_user("bob", *stmts)], [aws_role("ec2-role", "ec2.amazonaws.com"),
                                                     aws_role("lambda-role", "lambda.amazonaws.com", profile=False)],
                        scp_status="empty")
    hit = reached(run(snap), f"arn:aws:iam::{ACCOUNT}:user/bob")
    assert f"arn:aws:iam::{ACCOUNT}:role/lambda-role" in hit
    assert f"arn:aws:iam::{ACCOUNT}:role/ec2-role" not in hit


def test_aws_aggregation_of_many_targets():
    users = [aws_user("admin-ish", {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"})]
    users += [aws_user(f"u{i}") for i in range(30)]
    result = run(aws_snapshot(users, scp_status="empty"))
    src = f"arn:aws:iam::{ACCOUNT}:user/admin-ish"
    edges = edges_from(result, src, "aws-iam-createaccesskey-other-user")
    assert len(edges) == 1
    agg = next(n for n in result["graph"]["nodes"] if n["id"] == edges[0]["target"])
    assert agg["kind"] == "aggregate" and agg["underlying_count"] >= 30
    assert len(reached(result, src, "aws-iam-createaccesskey-other-user")) >= 30


def test_aws_admin_is_reported_and_queryable():
    admin = aws_user("root-like", {"Effect": "Allow", "Action": "*", "Resource": "*"})
    alice = aws_user("alice", *PASS_RUN)
    role = aws_role("ec2-admin", "ec2.amazonaws.com")
    role["AttachedManagedPolicies"] = [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "PolicyName": "AdministratorAccess"}]
    result = run(aws_snapshot([admin, alice], [role], scp_status="empty"))
    paths = queries.reach_admin(result["graph"])
    by = {r["principal"]: r for r in paths}
    assert by[f"arn:aws:iam::{ACCOUNT}:user/alice"]["distance"] == 2
    sp = queries.shortest_paths(result["graph"], f"arn:aws:iam::{ACCOUNT}:user/alice")
    assert sp and sp[0]["length"] == 2
    card = queries.principal_card(result["graph"], f"arn:aws:iam::{ACCOUNT}:user/alice", result["findings"])
    assert "aws-ec2-passrole-runinstances" in card["techniques"] and card["findings"]


def test_queries_are_cycle_safe_and_bounded():
    a = aws_user("a", {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": f"arn:aws:iam::{ACCOUNT}:user/b"})
    b = aws_user("b", {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": f"arn:aws:iam::{ACCOUNT}:user/a"})
    c = aws_user("c", {"Effect": "Allow", "Action": "*", "Resource": "*"})
    result = run(aws_snapshot([a, b, c], scp_status="empty"))
    ua, ub = (f"arn:aws:iam::{ACCOUNT}:user/{n}" for n in "ab")
    assert reached(result, ua) == {ub: "derived"} and reached(result, ub) == {ua: "derived"}
    assert queries.shortest_paths(result["graph"], ua) == []          # cycle, no admin reachable
    path = queries.shortest_paths(result["graph"], ua, ub, max_depth=1)
    assert path and path[0]["length"] == 1
    assert ua not in {r["principal"] for r in queries.reach_admin(result["graph"])}
    broad = queries.broad_reach(result["graph"], min_targets=1)
    assert {r["principal"] for r in broad} >= {ua, ub}


# GCP ----------------------------------------------------------------------------
GCP_CREATE_ROLE = {"name": "projects/p1/roles/vmCreator", "includedPermissions": [
    "compute.instances.create", "compute.disks.create", "compute.instances.setMetadata",
    "compute.instances.setServiceAccount", "compute.subnetworks.use"]}


def gcp_sa(email, project="p1", policy=None):
    return {"email": email, "projectId": project, "name": f"projects/{project}/serviceAccounts/{email}",
            "iamPolicy": policy or {}}


def gcp_snapshot(project_bindings, sas, roles=(GCP_CREATE_ROLE,)):
    return snapshot("gcp", [
        ("project", "projects/p1", [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", "projects/p1", [{"name": "projects/p1", "bindings": project_bindings}]),
        ("iam_role", "projects/p1", list(roles)),
        ("service_account", "projects/p1", list(sas)),
        ("iam_deny_policy", "projects/p1", [], "empty"),
    ])


SA1 = "sa1@p1.iam.gserviceaccount.com"
SA2 = "sa2@p1.iam.gserviceaccount.com"
SA3 = "sa3@p1.iam.gserviceaccount.com"


def test_gcp_actas_project_level_reaches_all_sas_in_project():
    snap = gcp_snapshot([{"role": "projects/p1/roles/vmCreator", "members": ["user:alice@x.com"]},
                         {"role": "roles/iam.serviceAccountUser", "members": ["user:alice@x.com"]}],
                        [gcp_sa(SA1), gcp_sa(SA2), gcp_sa(SA3)])
    hit = reached(run(snap), "user:alice@x.com", "gcp-compute-instances-create-actas")
    assert {f"serviceAccount:{s}" for s in (SA1, SA2, SA3)} <= set(hit)
    assert set(hit.values()) == {"derived"}


def test_gcp_actas_on_one_sa_reaches_only_that_sa():
    sa1 = gcp_sa(SA1, policy={"bindings": [{"role": "roles/iam.serviceAccountUser", "members": ["user:alice@x.com"]}]})
    snap = gcp_snapshot([{"role": "projects/p1/roles/vmCreator", "members": ["user:alice@x.com"]}],
                        [sa1, gcp_sa(SA2), gcp_sa(SA3)])
    hit = reached(run(snap), "user:alice@x.com", "gcp-compute-instances-create-actas")
    assert set(hit) == {f"serviceAccount:{SA1}"}


def test_gcp_conditional_binding_and_missing_role_coverage():
    snap = gcp_snapshot([{"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:bob@x.com"],
                          "condition": {"title": "business-hours", "expression": "request.time < x"}},
                         {"role": "roles/some.uncollected", "members": ["user:bob@x.com"]}],
                        [gcp_sa(SA1)])
    result = run(snap)
    hit = reached(result, "user:bob@x.com", "gcp-iam-serviceaccounts-getaccesstoken")
    assert hit == {f"serviceAccount:{SA1}": "conditional"}
    assert any(c["kind"] == "roles" and "roles/some.uncollected" in c["reason"] for c in result["coverage"])


def test_gcp_custom_role_bound_to_source_uses_real_catalog_entry():
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-iam-roles-update-own-custom-role")
    role = {"name": "projects/p1/roles/selfEdit", "includedPermissions": ["iam.roles.update"]}
    snap = gcp_snapshot([{"role": "projects/p1/roles/selfEdit", "members": ["user:carol@x.com"]},
                         {"role": "roles/iam.roleAdmin", "members": ["user:dave@x.com"]}], [gcp_sa(SA1)], roles=(role,))
    result = privesc.analyze(snap, entries=[entry])
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    carol = [nodes[e["target"]]["scope"] for e in edges_from(result, "user:carol@x.com")]
    assert carol == ["projects/p1"]
    assert edges_from(result, "user:dave@x.com") == []          # can update roles, but none is bound to dave


# Kubernetes ---------------------------------------------------------------------
def k8s_obj(kind, name, ns=None, **body):
    meta = {"name": name}
    if ns:
        meta["namespace"] = ns
    return {"kind": kind, "metadata": meta, "provenance": {"cluster_id": "c1"}, **body}


def k8s_snapshot(extra_roles=(), extra_bindings=()):
    roles = [k8s_obj("Role", "pod-creator", "a", rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]),
             *extra_roles]
    bindings = [k8s_obj("RoleBinding", "rb", "a", roleRef={"kind": "Role", "name": "pod-creator"},
                        subjects=[{"kind": "User", "name": "dev"}]), *extra_bindings]
    sas = [k8s_obj("ServiceAccount", n, ns) for ns in ("a", "b") for n in ("default", "builder")]
    return snapshot("k8s", [
        ("role", "c1", [r for r in roles if r["kind"] == "Role"]),
        ("clusterrole", "c1", [r for r in roles if r["kind"] == "ClusterRole"]),
        ("rolebinding", "c1", [b for b in bindings if b["kind"] == "RoleBinding"]),
        ("clusterrolebinding", "c1", [b for b in bindings if b["kind"] == "ClusterRoleBinding"]),
        ("serviceaccount", "c1", sas),
        ("namespace", "c1", [k8s_obj("Namespace", "a"), k8s_obj("Namespace", "b")]),
        ("pod", "c1", []), ("node", "c1", []),
    ])


def test_k8s_pod_create_in_ns_a_does_not_reach_ns_b():
    hit = reached(run(k8s_snapshot()), "k8s:c1:user:dev", "k8s-workloads-pods-create")
    assert set(hit) == {"k8s:c1:sa:a:default", "k8s:c1:sa:a:builder"}


def test_k8s_clusterrole_aggregation_grants_pod_create():
    agg = k8s_obj("ClusterRole", "aggregated", aggregationRule={"clusterRoleSelectors": [{"matchLabels": {"agg": "yes"}}]}, rules=[])
    part = k8s_obj("ClusterRole", "part", rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}])
    part["metadata"]["labels"] = {"agg": "yes"}
    rb = k8s_obj("RoleBinding", "rb2", "b", roleRef={"kind": "ClusterRole", "name": "aggregated"},
                 subjects=[{"kind": "User", "name": "ops"}])
    hit = reached(run(k8s_snapshot([agg, part], [rb])), "k8s:c1:user:ops", "k8s-workloads-pods-create")
    assert set(hit) == {"k8s:c1:sa:b:default", "k8s:c1:sa:b:builder"}


def test_k8s_resource_names_restrict_create():
    role = k8s_obj("Role", "named", "b", rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"],
                                               "resourceNames": ["x"]}])
    rb = k8s_obj("RoleBinding", "rb3", "b", roleRef={"kind": "Role", "name": "named"}, subjects=[{"kind": "User", "name": "eve"}])
    assert reached(run(k8s_snapshot([role], [rb])), "k8s:c1:user:eve", "k8s-workloads-pods-create") == {}


def test_k8s_absent_but_bound_sa_is_virtual_node():
    snap = k8s_snapshot(extra_bindings=[k8s_obj("ClusterRoleBinding", "ghost", roleRef={"kind": "ClusterRole", "name": "x"},
                                                subjects=[{"kind": "ServiceAccount", "name": "ghost", "namespace": "a"}])])
    from peaso.privesc.effective_permissions.k8s import K8sModel
    model = K8sModel(snap)
    candidates = {n.id: n for n in model.targets("k8s_service_account")}
    assert set(model.selector("k8s_sa_absent_but_bound", True, candidates, None)) == {"k8s:c1:sa:a:ghost"}


def test_k8s_cluster_wide_requirement_needs_clusterrolebinding():
    from peaso.privesc.effective_permissions import ANY
    from peaso.privesc.effective_permissions.k8s import K8sModel
    crb = k8s_obj("ClusterRoleBinding", "crb", roleRef={"kind": "ClusterRole", "name": "lister"}, subjects=[{"kind": "User", "name": "ops"}])
    lister = k8s_obj("ClusterRole", "lister", rules=[{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}])
    model = K8sModel(k8s_snapshot([lister], [crb]))
    req = {"verb": "create", "resource": "pods", "namespace": "*"}
    assert model.check(model.principals["k8s:c1:user:dev"], req, ANY) is None          # RoleBinding in ns a only
    assert model.check(model.principals["k8s:c1:user:dev"], {"verb": "create", "resource": "pods"}, ANY) is not None
    assert model.check(model.principals["k8s:c1:user:ops"], {"verb": "list", "resource": "secrets", "namespace": "*"}, ANY)


# Azure --------------------------------------------------------------------------
SUB = "/subscriptions/00000000-0000-0000-0000-00000000aaaa"
RG = f"{SUB}/resourceGroups/rg1"
WRITER_ROLE = "11111111-1111-1111-1111-111111111111"


def azure_snapshot(assignments, deny_status="empty"):
    role_def = {"id": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{WRITER_ROLE}",
                "properties": {"roleName": "RA writer", "type": "CustomRole", "assignableScopes": [SUB],
                               "permissions": [{"actions": ["Microsoft.Authorization/roleAssignments/write"]}]}}
    users = [{"id": "u-alice", "displayName": "alice", "userPrincipalName": "alice@t.com", "accountEnabled": True, "userType": "Member"}]
    return snapshot("azure", [
        ("subscription", SUB, [{"id": SUB, "subscriptionId": SUB.rsplit("/", 1)[-1]}]),
        ("resource_group", SUB, [{"id": RG, "name": "rg1"}, {"id": f"{SUB}/resourceGroups/rg2", "name": "rg2"}]),
        ("role_definition", SUB, [role_def]),
        ("role_assignment", SUB, [{"id": f"{a[1]}/providers/Microsoft.Authorization/roleAssignments/{i}",
                                   "properties": {"principalId": a[0], "principalType": "User", "scope": a[1],
                                                  "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{a[2]}"}}
                                  for i, a in enumerate(assignments)]),
        ("deny_assignment", SUB, [], deny_status),
        ("directory_user", "/tenants/t", users),
        ("directory_group", "/tenants/t", []),
        ("directory_service_principal", "/tenants/t", []),
        ("directory_role_assignment", "/tenants/t", []),
        ("directory_role_definition", "/tenants/t", []),
    ], metadata={"tenant_id": "t"})


def _azure_owner_targets(result, technique=None):
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    edges = edges_from(result, "u-alice", technique)
    return edges, [nodes[e["target"]] for e in edges]


def test_azure_roleassignments_write_at_rg_only_owns_rg():
    # Default: the source already administers the RG, so the graph carries one admin-equivalent edge.
    result = run(azure_snapshot([("u-alice", RG, WRITER_ROLE)]))
    edges, targets = _azure_owner_targets(result)
    assert [t["type"] for t in targets] == ["azure_scope_owner"]
    assert targets[0]["scope"] == RG.lower() and edges[0]["confidence"] == "derived"
    # With admin sources kept, the technique edge itself reaches only the RG scope owner (not rg2, not the sub).
    result = run(azure_snapshot([("u-alice", RG, WRITER_ROLE)]), include_admin_sources=True)
    edges, targets = _azure_owner_targets(result, "azure-authorization-roleassignments-write")
    assert {t["scope"] for t in targets} == {RG.lower()}
    assert any(f["check_id"] == "azure-authorization-roleassignments-write" for f in result["findings"])


def test_azure_deny_not_collected_is_conditional():
    result = run(azure_snapshot([("u-alice", SUB, WRITER_ROLE)], deny_status="denied"), include_admin_sources=True)
    edges, targets = _azure_owner_targets(result, "azure-authorization-roleassignments-write")
    assert edges and all(e["confidence"] == "conditional" for e in edges)
    # subscription ownership subsumes the RGs below it: only the top-most scope is emitted
    assert {t["scope"] for t in targets} == {SUB.lower()}
    assert any(c["kind"] == "guardrail" and "deny_assignment" in c["reason"] for c in result["coverage"])


# Catalog / API ------------------------------------------------------------------
def test_fixture_catalog_is_valid():
    loaded = load_catalog(FIXTURE_CATALOG)
    assert loaded["errors"] == []
    assert len(loaded["entries"]) == 7


def test_real_catalog_loads_and_empty_snapshots_analyze():
    for provider in ("aws", "gcp", "azure", "k8s"):
        result = privesc.analyze(snapshot(provider, []))
        assert set(result) == {"findings", "graph", "coverage", "stats"}
        assert result["findings"] == [] and result["coverage"]


def test_unsupported_provider():
    assert privesc.analyze({"provider": "oci", "collections": []})["coverage"][0]["status"] == "unsupported"


# Performance --------------------------------------------------------------------
def test_perf_10k_principals():
    """10k IAM users and roles against the full AWS catalog in seconds."""
    users = []
    for i in range(7000):
        statements = [{"Effect": "Allow", "Action": ["s3:GetObject", "ec2:Describe*"], "Resource": "*"}]
        if i % 50 == 0:
            statements += PASS_RUN
        if i % 500 == 0:
            statements.append({"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"})
        users.append(aws_user(f"user{i}", *statements))
    roles = [aws_role(f"role{i}", "ec2.amazonaws.com" if i % 3 == 0 else "lambda.amazonaws.com", profile=i % 2 == 0)
             for i in range(3000)]
    snap = aws_snapshot(users, roles, scp_status="empty")
    started = time.perf_counter()
    result = privesc.analyze(snap)
    elapsed = time.perf_counter() - started
    print(f"\n10k principals: {elapsed:.2f}s stats={result['stats']['timing_seconds']} "
          f"nodes={result['stats']['nodes']} edges={result['stats']['edges']}")
    assert result["stats"]["principals"] == 10000
    assert edges_from(result, f"arn:aws:iam::{ACCOUNT}:user/user0", "aws-ec2-passrole-runinstances")
    assert len(result["graph"]["edges"]) < 20000
    assert elapsed < 30, elapsed


def _timed(snap):
    started = time.perf_counter()
    result = privesc.analyze(snap)
    return result, time.perf_counter() - started


def test_perf_10k_principals_gcp_k8s_azure():
    """10k principals per provider against the full catalog (timings printed with -s)."""
    members = [f"user:u{i}@x.com" for i in range(8000)]
    gcp, gcp_t = _timed(gcp_snapshot([
        {"role": "roles/viewer", "members": members},
        {"role": "roles/iam.serviceAccountUser", "members": members[::100]},
        {"role": "projects/p1/roles/vmCreator", "members": members[::50]}],
        [gcp_sa(f"sa{i}@p1.iam.gserviceaccount.com") for i in range(2000)]))
    assert gcp["stats"]["principals"] == 10000
    assert len(reached(gcp, "user:u0@x.com", "gcp-compute-instances-create-actas")) == 2000

    nss = [f"ns{i}" for i in range(100)]
    role = k8s_obj("ClusterRole", "pc", rules=[{"apiGroups": [""], "resources": ["pods", "secrets"], "verbs": ["create", "get", "list"]}])
    rbs = [k8s_obj("RoleBinding", f"rb{i}", nss[i % 100], roleRef={"kind": "ClusterRole", "name": "pc"},
                   subjects=[{"kind": "User", "name": f"dev{i}"}]) for i in range(200)]
    k8s, k8s_t = _timed(snapshot("k8s", [
        ("role", "c1", []), ("clusterrole", "c1", [role]), ("rolebinding", "c1", rbs), ("clusterrolebinding", "c1", []),
        ("serviceaccount", "c1", [k8s_obj("ServiceAccount", f"sa{j}", ns) for ns in nss for j in range(100)]),
        ("namespace", "c1", [k8s_obj("Namespace", n) for n in nss]), ("pod", "c1", []), ("node", "c1", [])]))
    assert k8s["stats"]["principals"] >= 10000
    assert set(reached(k8s, "k8s:c1:user:dev0", "k8s-workloads-pods-create")) == {f"k8s:c1:sa:ns0:sa{j}" for j in range(100)}

    rgs = [{"id": f"{SUB}/resourceGroups/rg{i}", "name": f"rg{i}"} for i in range(200)]
    contributor = "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
    vms = [{"id": f"{rgs[i % 200]['id']}/providers/Microsoft.Compute/virtualMachines/vm{i}", "type": "Microsoft.Compute/virtualMachines",
            "name": f"vm{i}", "identity": {"principalId": f"mi{i}", "type": "SystemAssigned"}} for i in range(500)]
    azure, azure_t = _timed(snapshot("azure", [
        ("subscription", SUB, [{"id": SUB}]), ("resource_group", SUB, rgs), ("role_definition", SUB, []),
        ("role_assignment", SUB, [{"id": f"a{i}", "properties": {"principalId": f"u{i}", "principalType": "User",
                                   "scope": rgs[i % 200]["id"], "roleDefinitionId": contributor}} for i in range(0, 10000, 30)]),
        ("deny_assignment", SUB, [], "empty"), ("vm", SUB, vms),
        ("directory_user", "/tenants/t", [{"id": f"u{i}", "displayName": f"u{i}", "userPrincipalName": f"u{i}@t.com"} for i in range(10000)]),
        ("directory_group", "/tenants/t", []), ("directory_service_principal", "/tenants/t", []),
        ("directory_role_assignment", "/tenants/t", []), ("directory_role_definition", "/tenants/t", []),
        ("directory_membership", "/tenants/t/groups/g", [])], metadata={"tenant_id": "t"}))
    assert azure["stats"]["principals"] >= 10000
    assert "mi0" in reached(azure, "u0", "azure-vm-runcommand-action")
    print(f"\ngcp {gcp_t:.2f}s edges={gcp['stats']['edges']}; k8s {k8s_t:.2f}s edges={k8s['stats']['edges']}; "
          f"azure {azure_t:.2f}s edges={azure['stats']['edges']}")
    assert max(gcp_t, k8s_t, azure_t) < 30


def test_unknown_privesc_findings_always_carry_a_reason():
    scope = f"{ACCOUNT}/us-east-1"
    snap = snapshot("aws", [("iam_user", scope, [aws_user("alice", *PASS_RUN)]), ("iam_role", scope, [], "denied"),
                            ("iam_group", scope, []), ("iam_policy", scope, []), ("scp_policy", scope, [], "empty")])
    assert not [f for f in run(snap)["findings"] if f["status"] == "UNKNOWN"]
    unknown = [f for f in run(snap, include_unknown=True)["findings"] if f["status"] == "UNKNOWN"]
    assert unknown
    for finding in unknown:
        assert finding["evidence"]["reason"].startswith("missing_facts: ") and finding["evidence"]["reason"] != "missing_facts: "
        assert finding["evidence"]["facts_needed"]
    # Proven and conditional findings keep their evidence shape (no reason key added).
    derived = run(aws_snapshot([aws_user("bob", *PASS_RUN)], [aws_role("ec2-role", "ec2.amazonaws.com")], scp_status="empty"))
    assert all("reason" not in f["evidence"] for f in derived["findings"] if f["status"] != "UNKNOWN")
