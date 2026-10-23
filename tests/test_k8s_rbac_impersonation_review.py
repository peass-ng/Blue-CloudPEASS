"""Traditional impersonation joins the exact identity and required group header."""

from peaso import privesc

from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import C, crb, crole, k8s_snap, node, sa, user


def run(technique, roles, bindings, *, sas=(), nodes=()):
    entry = next(item for item in privesc.catalog()["entries"] if item["id"] == technique)
    return privesc.analyze(k8s_snap(clusterroles=roles, crbs=bindings, sas=sas, nodes=nodes), entries=[entry])


def test_serviceaccount_impersonation_uses_exact_name_and_namespace():
    technique = "k8s-rbac-impersonate-serviceaccounts"
    role = crole("imp", [{"apiGroups": [""], "resources": ["serviceaccounts"],
                          "resourceNames": ["worker"], "verbs": ["impersonate"]}])
    bindings = [crb("imp-bind", "imp", user("dev"))]
    result = run(technique, [role], bindings, sas=[sa("worker", "a"), sa("other", "a")])
    assert set(reached(result, f"k8s:{C}:user:dev", technique)) == {f"k8s:{C}:sa:a:worker"}
    role["rules"][0]["resourceNames"] = ["other"]
    result = run(technique, [role], bindings, sas=[sa("worker", "a")])
    assert reached(result, f"k8s:{C}:user:dev", technique) == {}


def test_group_impersonation_requires_user_header_permission():
    technique = "k8s-rbac-impersonate-groups"
    groups = crole("groups", [{"apiGroups": [""], "resources": ["groups"],
                               "resourceNames": ["operators"], "verbs": ["impersonate"]}])
    users = crole("users", [{"apiGroups": [""], "resources": ["users"],
                             "resourceNames": ["alice"], "verbs": ["impersonate"]}])
    target = crole("target", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    bindings = [crb("g-bind", "groups", user("dev")),
                crb("target-bind", "target", {"kind": "Group", "name": "operators"})]
    assert reached(run(technique, [groups, target], bindings), f"k8s:{C}:user:dev", technique) == {}
    bindings.append(crb("u-bind", "users", user("dev")))
    assert set(reached(run(technique, [groups, users, target], bindings),
                       f"k8s:{C}:user:dev", technique)) == {f"k8s:{C}:group:operators"}


def test_node_impersonation_requires_system_nodes_group_and_exact_user():
    technique = "k8s-rbac-impersonate-node"
    users = crole("users", [{"apiGroups": [""], "resources": ["users"],
                             "resourceNames": ["system:node:n1"], "verbs": ["impersonate"]}])
    groups = crole("groups", [{"apiGroups": [""], "resources": ["groups"],
                               "resourceNames": ["system:nodes"], "verbs": ["impersonate"]}])
    bindings = [crb("u-bind", "users", user("dev"))]
    assert reached(run(technique, [users, groups], bindings, nodes=[node("n1")]),
                   f"k8s:{C}:user:dev", technique) == {}
    bindings.append(crb("g-bind", "groups", user("dev")))
    assert set(reached(run(technique, [users, groups], bindings, nodes=[node("n1"), node("n2")]),
                       f"k8s:{C}:user:dev", technique)) == {f"k8s:{C}:node:n1"}
