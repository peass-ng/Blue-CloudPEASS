"""Selected Group semantics for the registered Kubernetes system:masters check."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from peaso.checks.facts import MemoIndex


CHECK = "k8s.cis.avoid_use_of_system_masters_group"
CLUSTER = "fixture-cluster"
GROUP = {"kind": "Group", "name": "system:masters", "apiGroup": "rbac.authorization.k8s.io"}


def binding(kind, name, subjects, namespace="apps"):
    location = namespace if kind == "rolebinding" else "_cluster"
    return {
        "id": f"k8s://{CLUSTER}/{kind}/{location}/{name}",
        "metadata": {"name": name, **({"namespace": namespace} if kind == "rolebinding" else {})},
        "provenance": {"cluster_id": CLUSTER, "evidence": "read-only list"},
        "subjects": subjects,
    }


def complete(cluster=(), namespaced=(), *, status=None, scope="*"):
    context = {"provider": "k8s", "scope": scope, "metadata": {"cluster_id": CLUSTER}}
    index = MemoIndex(context=context, collections={})
    for kind, rows in (("clusterrolebinding", cluster), ("rolebinding", namespaced)):
        rows = list(rows)
        state = (status or {}).get(kind, "collected" if rows else "empty")
        index["collections"][kind] = [{"type": kind, "scope": scope, "status": state, "items": rows}]
        index[kind] = [{"type": kind, "scope": scope, "provider": "k8s", "data": row} for row in rows]
    return index


def verdict(index):
    return evaluate_check(CHECK, index["context"], index)


def test_native_shape_irrelevant_gke_users_do_not_mask_selected_group():
    # Inert synthetic counterpart of the saved capture: twelve ClusterRoleBinding
    # Users and one RoleBinding User carry a namespace despite their known kind.
    users = [binding("clusterrolebinding", f"managed-{i}", [
        {"kind": "User", "name": f"system:managed-{i}", "namespace": "kube-system"}])
        for i in range(12)]
    selected = binding("clusterrolebinding", "cluster-admin", [GROUP])
    namespaced = binding("rolebinding", "managed", [
        {"kind": "User", "name": "system:managed", "namespace": "kube-system"}],
        namespace="kube-system")
    status, evidence = verdict(complete(users + [selected], [namespaced]))
    assert status == "FAIL"
    assert evidence["affected_bindings"] == [{"kind": "clusterrolebinding", "binding_id": selected["id"]}]


def test_selected_group_in_rolebinding_and_native_apigroup_default():
    selected = binding("rolebinding", "selected", [{"kind": "Group", "name": "system:masters"}])
    status, evidence = verdict(complete(namespaced=[selected]))
    assert status == "FAIL"
    assert evidence["affected_bindings"] == [{"kind": "rolebinding", "binding_id": selected["id"]}]


def test_irrelevant_malformed_fields_preserve_observed_absence_unknown():
    other = binding("clusterrolebinding", "other", [
        {"kind": "User", "name": "system:masters", "namespace": "kube-system", "apiGroup": "wrong"},
        {"kind": "User", "namespace": "kube-system"},
        {"kind": "ServiceAccount"},
        {"kind": "Group", "name": "other", "apiGroup": "wrong", "namespace": "bad"},
    ])
    status, evidence = verdict(complete(cluster=[other]))
    assert status == "UNKNOWN"
    assert "no system:masters subject" in evidence["reason"]


@pytest.mark.parametrize("subject", [
    {"kind": "Group", "name": "system:masters", "apiGroup": "wrong"},
    {"kind": "Group", "name": "system:masters", "namespace": "kube-system"},
    {"kind": "Group", "name": "system:masters", "apiGroup": None},
    {"kind": "Group", "name": "system:masters", "namespace": None},
    {"kind": "Group"},
    {"name": "system:masters"},
    None,
])
def test_malformed_relevant_or_ambiguous_subject_stays_unknown(subject):
    row = binding("clusterrolebinding", "bad", [subject, GROUP])
    assert verdict(complete(cluster=[row]))[0] == "UNKNOWN"


@pytest.mark.parametrize("kind", ["clusterrolebinding", "rolebinding"])
@pytest.mark.parametrize("state", ["denied", "partial"])
def test_both_inventories_must_be_complete_even_with_group(kind, state):
    selected = binding("clusterrolebinding", "selected", [GROUP])
    assert verdict(complete(cluster=[selected], status={kind: state}))[0] == "UNKNOWN"


def test_stale_provenance_wrapper_mismatch_and_cross_scope_stay_unknown():
    selected = binding("clusterrolebinding", "selected", [GROUP])
    stale = deepcopy(selected)
    stale["provenance"]["evidence"] = "stale cache"
    assert verdict(complete(cluster=[stale]))[0] == "UNKNOWN"
    mismatch = complete(cluster=[selected])
    mismatch["clusterrolebinding"][0]["data"] = binding("clusterrolebinding", "different", [GROUP])
    assert verdict(mismatch)[0] == "UNKNOWN"
    foreign = deepcopy(selected)
    foreign["provenance"]["cluster_id"] = "foreign-cluster"
    assert verdict(complete(cluster=[foreign]))[0] == "UNKNOWN"
    out_of_scope = binding("rolebinding", "selected", [GROUP], namespace="other")
    assert verdict(complete(namespaced=[out_of_scope], scope="apps"))[0] == "UNKNOWN"
    index = complete()
    assert evaluate_check(CHECK, {**index["context"], "scope": "other"}, index)[0] == "UNKNOWN"
