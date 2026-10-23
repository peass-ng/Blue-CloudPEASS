"""Run the four bounded RBAC grant routes against the active catalog entries."""

from __future__ import annotations

import pytest

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import crb, crole, k8s_snap, rb, user


CREATE_CLUSTER = "k8s-rbac-bind-existing-clusterrole-new-permission"
CREATE_NAMESPACE = "k8s-rbac-bind-existing-role-new-permission"
MODIFY_CLUSTER = "k8s-rbac-modify-existing-clusterrolebinding-new-permission"
MODIFY_NAMESPACE = "k8s-rbac-modify-existing-rolebinding-new-permission"
ENTRIES = {item["id"]: item for item in privesc.catalog()["entries"]}
SOURCE = "k8s:c1:user:dev"


def targets(technique, *, bind=True, write=True, existing=True):
    cluster = technique in (CREATE_CLUSTER, MODIFY_CLUSTER)
    modifying = technique in (MODIFY_CLUSTER, MODIFY_NAMESPACE)
    verb = "patch" if modifying else "create"
    rules = []
    if bind:
        rules.append({"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"],
                      "resourceNames": ["target"], "verbs": ["bind"]})
    if write:
        rules.append({"apiGroups": ["rbac.authorization.k8s.io"],
                      "resources": ["clusterrolebindings" if cluster else "rolebindings"],
                      "verbs": [verb]})
    writer = crole("writer", rules)
    target = crole("target", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    cluster_bindings = [crb("writer-binding", "writer", user("dev"))]
    namespace_bindings = []
    if modifying and existing:
        binding = (crb("existing", "target", user("other")) if cluster
                   else rb("existing", "a", "target", user("other")))
        (cluster_bindings if cluster else namespace_bindings).append(binding)
    # Namespace a is collected, but contains no service account or Secret.
    snapshot = k8s_snap(clusterroles=[writer, target], crbs=cluster_bindings,
                        rbs=namespace_bindings)
    result = privesc.analyze(snapshot, entries=[ENTRIES[technique]])
    return reached(result, SOURCE, technique)


@pytest.mark.parametrize("technique,namespace", [
    (CREATE_CLUSTER, "*"), (CREATE_NAMESPACE, "a"),
    (MODIFY_CLUSTER, "*"), (MODIFY_NAMESPACE, "a"),
])
def test_exact_role_gain_reaches_collected_scope_without_service_account(technique, namespace):
    got = targets(technique)
    assert len(got) == 1
    assert next(iter(got)).startswith(f"k8s:role-gain:c1:{namespace}:")
    assert set(got.values()) == {"conditional"}


@pytest.mark.parametrize("technique", [CREATE_CLUSTER, CREATE_NAMESPACE,
                                           MODIFY_CLUSTER, MODIFY_NAMESPACE])
def test_role_gain_needs_bind_and_exact_binding_write(technique):
    assert targets(technique, bind=False) == {}
    assert targets(technique, write=False) == {}
    if technique in (MODIFY_CLUSTER, MODIFY_NAMESPACE):
        assert targets(technique, existing=False) == {}
