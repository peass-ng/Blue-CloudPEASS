"""Binding the named cluster-admin role requires its collected useful rules."""

from peaso import privesc

from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import C, crb, crole, k8s_snap, sa, user


def test_named_cluster_admin_role_must_exist_and_reach_the_sa():
    technique = "k8s-rbac-bind-rolebinding-namespace"
    entry = next(item for item in privesc.catalog()["entries"] if item["id"] == technique)
    writer = crole("writer", [{"apiGroups": ["rbac.authorization.k8s.io"],
                               "resources": ["clusterroles"], "resourceNames": ["cluster-admin"],
                               "verbs": ["bind"]},
                              {"apiGroups": ["rbac.authorization.k8s.io"],
                               "resources": ["rolebindings"], "verbs": ["create"]}])
    bindings = [crb("writer-binding", "writer", user("dev"))]

    def targets(roles):
        result = privesc.analyze(k8s_snap(clusterroles=[writer, *roles], crbs=bindings,
                                         sas=[sa("worker", "a")]), entries=[entry])
        return reached(result, f"k8s:{C}:user:dev", technique)

    assert targets([]) == {}
    weak = crole("cluster-admin", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}])
    assert targets([weak]) == {}
    weak["rules"][0]["verbs"] = ["create"]
    assert set(targets([weak])) == {f"k8s:{C}:sa:a:worker"}
