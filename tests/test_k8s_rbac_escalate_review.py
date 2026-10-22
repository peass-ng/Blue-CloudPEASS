"""RBAC escalate and role write must authorize the same bound role."""

from peaso import privesc

from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import C, crb, crole, k8s_snap, sa, user


def test_clusterrole_escalate_and_patch_cannot_join_different_names():
    technique = "k8s-rbac-escalate-bound-clusterrole"
    entry = next(item for item in privesc.catalog()["entries"] if item["id"] == technique)
    first = crole("first", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}])
    second = crole("second", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}])
    editor = crole("editor", [{"apiGroups": ["rbac.authorization.k8s.io"],
                               "resources": ["clusterroles"], "verbs": ["escalate"], "resourceNames": ["first"]},
                              {"apiGroups": ["rbac.authorization.k8s.io"],
                               "resources": ["clusterroles"], "verbs": ["patch"], "resourceNames": ["second"]}])
    binds = [crb("first-bind", "first", user("dev")), crb("second-bind", "second", user("dev")),
             crb("editor-bind", "editor", user("dev"))]

    def path():
        return reached(privesc.analyze(k8s_snap(clusterroles=[first, second, editor], crbs=binds),
                                       entries=[entry]), f"k8s:{C}:user:dev", technique)

    assert path() == {}
    editor["rules"][1]["resourceNames"] = ["first"]
    assert path()


def test_namespaced_role_escalate_and_patch_cannot_join_different_names():
    technique = "k8s-rbac-escalate-bound-role-namespace"
    entry = next(item for item in privesc.catalog()["entries"] if item["id"] == technique)
    first = {"kind": "Role", "metadata": {"name": "first", "namespace": "a"},
             "provenance": {"cluster_id": C}, "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]}
    second = {"kind": "Role", "metadata": {"name": "second", "namespace": "a"},
              "provenance": {"cluster_id": C}, "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]}
    editor = crole("editor", [{"apiGroups": ["rbac.authorization.k8s.io"],
                               "resources": ["roles"], "verbs": ["escalate"], "resourceNames": ["first"]},
                              {"apiGroups": ["rbac.authorization.k8s.io"],
                               "resources": ["roles"], "verbs": ["patch"], "resourceNames": ["second"]}])
    role_binds = [
        {"kind": "RoleBinding", "metadata": {"name": "first-bind", "namespace": "a"},
         "provenance": {"cluster_id": C}, "roleRef": {"kind": "Role", "name": "first"},
         "subjects": [user("dev")]},
        {"kind": "RoleBinding", "metadata": {"name": "second-bind", "namespace": "a"},
         "provenance": {"cluster_id": C}, "roleRef": {"kind": "Role", "name": "second"},
         "subjects": [user("dev")]},
    ]
    binds = [*role_binds, crb("editor-bind", "editor", user("dev"))]

    def path():
        snap = k8s_snap(clusterroles=[editor], crbs=[binds[-1]], rbs=role_binds,
                        sas=[sa("worker", "a")])
        snap["collections"][0]["items"] = [first, second]
        return reached(privesc.analyze(snap, entries=[entry]), f"k8s:{C}:user:dev", technique)

    assert path() == {}
    editor["rules"][1]["resourceNames"] = ["first"]
    assert set(path()) == {f"k8s:{C}:sa:a:worker"}
