"""Regressions found by the independent semantic review of the privesc catalog (gate-privesc-semantic-review)."""
from __future__ import annotations

from peaso import privesc


def _snapshot(collections):
    cols = [{"type": t, "scope": "*", "service": t, "status": "collected", "items": items, "error": None}
            for t, items in collections]
    return {"schema_version": 1, "provider": "k8s", "scopes": ["*"], "collections": cols, "metadata": {}}


def _kobj(kind, name, ns=None, **body):
    meta = {"name": name, **({"namespace": ns} if ns else {})}
    return {"kind": kind, "metadata": meta, "provenance": {"cluster_id": "c1"}, **body}


def _k8s(roles, bindings):
    return _snapshot([
        ("role", [r for r in roles if r["kind"] == "Role"]),
        ("clusterrole", [r for r in roles if r["kind"] == "ClusterRole"]),
        ("rolebinding", [b for b in bindings if b["kind"] == "RoleBinding"]),
        ("clusterrolebinding", [b for b in bindings if b["kind"] == "ClusterRoleBinding"]),
        ("serviceaccount", [_kobj("ServiceAccount", "default", "a")]),
        ("namespace", [_kobj("Namespace", n) for n in ("a", "b")]),
        ("pod", []), ("node", []),
        ("api_discovery", [{"groups": [{"name": "rbac.authorization.k8s.io"}], "provenance": {"cluster_id": "c1"}}]),
    ])


def _escalate_edges(binding_kind):
    """ops can escalate+update the ClusterRole 'tenant', which is bound to ops by a binding of binding_kind."""
    tenant = _kobj("ClusterRole", "tenant", rules=[{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}])
    editor = _kobj("ClusterRole", "tenant-editor", rules=[{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"],
                                                           "resourceNames": ["tenant"], "verbs": ["escalate", "update"]}])
    editor_crb = _kobj("ClusterRoleBinding", "editor", roleRef={"kind": "ClusterRole", "name": "tenant-editor"},
                       subjects=[{"kind": "User", "name": "ops"}])
    ns = "a" if binding_kind == "RoleBinding" else None
    tenant_binding = _kobj(binding_kind, "tenant", ns, roleRef={"kind": "ClusterRole", "name": "tenant"},
                           subjects=[{"kind": "User", "name": "ops"}])
    entries = [e for e in privesc.catalog()["entries"] if e["id"] == "k8s-rbac-escalate-bound-clusterrole"]
    result = privesc.analyze(_k8s([tenant, editor], [editor_crb, tenant_binding]), entries=entries)
    return [e for e in result["graph"]["edges"] if e["source"] == "k8s:c1:user:ops"
            and "k8s-rbac-escalate-bound-clusterrole" in e["techniques"]]


def test_escalate_clusterrole_bound_cluster_wide_reaches_cluster_admin():
    assert _escalate_edges("ClusterRoleBinding")


def test_escalate_clusterrole_bound_only_by_rolebinding_is_not_cluster_admin():
    # A RoleBinding confines the ClusterRole to namespace a: rewriting its rules never grants cluster-wide power to ops.
    assert _escalate_edges("RoleBinding") == []


def _escalate_role_reach(bound_ns):
    """dev holds escalate+update on every Role in namespace b; its own Role 'team' is bound in bound_ns."""
    team = _kobj("Role", "team", bound_ns, rules=[{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}])
    team_rb = _kobj("RoleBinding", "team", bound_ns, roleRef={"kind": "Role", "name": "team"}, subjects=[{"kind": "User", "name": "dev"}])
    # A ClusterRole bound by a RoleBinding: grants escalate/update on Roles in b, but is not itself a bound Role.
    editor = _kobj("ClusterRole", "role-editor", rules=[{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"],
                                                        "verbs": ["escalate", "update"]}])
    editor_rb = _kobj("RoleBinding", "role-editor", "b", roleRef={"kind": "ClusterRole", "name": "role-editor"},
                      subjects=[{"kind": "User", "name": "dev"}])
    snap = _k8s([team, editor], [team_rb, editor_rb])
    for col in snap["collections"]:
        if col["type"] == "serviceaccount":
            col["items"] = [_kobj("ServiceAccount", "default", n) for n in ("a", "b")]
    entries = [e for e in privesc.catalog()["entries"] if e["id"] == "k8s-rbac-escalate-bound-role-namespace"]
    result = privesc.analyze(snap, entries=entries)
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    out = set()
    for e in result["graph"]["edges"]:
        if e["source"] == "k8s:c1:user:dev" and "k8s-rbac-escalate-bound-role-namespace" in e["techniques"]:
            node = nodes.get(e["target"], {})
            out.update(node.get("members") or [e["target"]] if node.get("kind") == "aggregate" else [e["target"]])
    return out


def test_escalate_role_bound_in_same_namespace_reaches_its_service_accounts():
    assert "k8s:c1:sa:b:default" in _escalate_role_reach("b")


def test_escalate_role_bound_in_other_namespace_does_not_reach():
    # The only Role bound to dev lives in namespace a; rewriting roles in b gives dev nothing in b.
    assert _escalate_role_reach("a") == set()
