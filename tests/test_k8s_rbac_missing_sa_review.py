"""Missing ServiceAccount routes need a real namespace and an added right."""

from peaso import privesc

from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import C, crb, crole, k8s_snap, user


def _entry(technique):
    return next(item for item in privesc.catalog()["entries"] if item["id"] == technique)


def _binding(role="power", namespace="a"):
    return crb("missing", role, {"kind": "ServiceAccount", "name": "missing", "namespace": namespace})


def test_dangling_serviceaccount_requires_existing_namespace_and_resolved_gain():
    entry = _entry("k8s-rbac-dangling-serviceaccount-reference")
    writer = crole("writer", [{"apiGroups": [""], "resources": ["serviceaccounts", "pods"], "verbs": ["create"]}])
    power = crole("power", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    source = crb("writer-binding", "writer", user("dev"))

    def targets(roles, bindings, namespaces=("a",)):
        snap = k8s_snap(clusterroles=[writer, *roles], crbs=[source, *bindings], namespaces=namespaces)
        return reached(privesc.analyze(snap, entries=[entry]), f"k8s:{C}:user:dev", entry["id"])

    wanted = f"k8s:{C}:sa:a:missing"
    assert wanted in targets([power], [_binding()])
    assert targets([], [_binding()]) == {}  # no referenced role rules
    assert targets([power], [_binding(namespace="gone")]) == {}  # namespace does not exist
    assert targets([writer], [_binding(role="writer")]) == {}  # source already holds the bound rights


def test_absent_namespace_requires_a_useful_binding_or_host_scc():
    entry = _entry("k8s-rbac-serviceaccount-in-absent-namespace")
    writer = crole("writer", [{"apiGroups": [""], "resources": ["namespaces", "serviceaccounts", "pods"],
                                "verbs": ["create"]}])
    power = crole("power", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    source = crb("writer-binding", "writer", user("dev"))

    def targets(roles=(), bindings=(), sccs=()):
        snap = k8s_snap(clusterroles=[writer, *roles], crbs=[source, *bindings], sccs=sccs)
        return reached(privesc.analyze(snap, entries=[entry]), f"k8s:{C}:user:dev", entry["id"])

    wanted = f"k8s:{C}:sa:gone:missing"
    assert wanted in targets([power], [_binding(namespace="gone")])
    assert targets([], [_binding(namespace="gone")]) == {}  # broken role reference
    weak_scc = {"kind": "SecurityContextConstraints", "metadata": {"name": "weak"},
                "provenance": {"cluster_id": C}, "users": ["system:serviceaccount:gone:missing"]}
    assert targets(sccs=[weak_scc]) == {}
    host_scc = {**weak_scc, "allowPrivilegedContainer": True}
    assert wanted in targets(sccs=[host_scc])
