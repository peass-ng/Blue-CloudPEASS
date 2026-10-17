"""Offline admission fixtures for the one signed namespace policy declaration check."""
from __future__ import annotations

import copy
from pathlib import Path
import pytest

import peaso.checks
from peaso.checks import CHECKS, evaluate_check
from peaso.checks import k8s_namespace_policy_presence
from peaso.collectors.k8s import _native, _owner_policy_metadata
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CHECK_ID = "k8s.cis.namespace_has_networkpolicy"
NOW = "2026-10-13T09:00:00+00:00"


@pytest.fixture(scope="module")
def candidate():
    root = Path(__file__).resolve().parents[1]
    assert Path(peaso.checks.__file__).resolve() == (root / "peaso/checks/__init__.py").resolve()
    assert Path(k8s_namespace_policy_presence.__file__).resolve() == (root / "peaso/checks/k8s_namespace_policy_presence.py").resolve()
    matched = [check for check in CHECKS if check.id == CHECK_ID]
    assert len(matched) == 1
    assert matched[0].__module__ == "peaso.checks"
    return matched[0]


def namespace(cluster="cluster-a", name="apps", scope="*"):
    return _native({"apiVersion": "v1", "metadata": {"name": name, "uid": f"ns-{cluster}-{name}"}},
                   "namespace", cluster, scope, False)


def policy(cluster="cluster-a", namespace_name="apps", name="allow-all", scope="*"):
    return _native({"apiVersion": "networking.k8s.io/v1", "metadata": {"name": name,
                    "namespace": namespace_name, "uid": f"np-{cluster}-{namespace_name}-{name}"},
                    "spec": {"podSelector": {}, "ingress": [{}], "policyTypes": ["Ingress"]}},
                   "networkpolicy", cluster, scope, True)


def snapshot(cluster="cluster-a", name="apps", *, policies=None, scope="*", namespace_status="collected",
             policy_status=None, system=("kube-public",), owner=True, namespace_item=None):
    ns = copy.deepcopy(namespace_item) if namespace_item is not None else namespace(cluster, name, scope)
    policies = [] if policies is None else copy.deepcopy(policies)
    if policy_status is None:
        policy_status = "collected" if policies else "empty"
    operator = {"cluster_id": cluster, "max_policy_items": 10, "observed_at": NOW, "max_age_seconds": 300}
    if system is not None:
        operator["system_namespaces"] = list(system)
    owner_meta = _owner_policy_metadata({"compliance_policy": operator}, cluster, NOW) if owner else {"status": "unknown"}
    return make_snapshot("k8s", [scope], [
        {"type": "namespace", "scope": scope, "service": "kubernetes", "status": namespace_status,
         "items": [ns] if namespace_status in ("collected", "partial") else []},
        {"type": "networkpolicy", "scope": scope, "service": "kubernetes", "status": policy_status,
         "items": policies},
    ], created_at=NOW, metadata={"cluster_id": cluster, "compliance_policy": owner_meta})


def finding(candidate, snap, *, checks=(CHECK_ID,)):
    report = evaluate_snapshot(snap, checks=list(checks))
    rows = [entry for entry in report["findings"] if entry["check_id"] == CHECK_ID]
    assert rows
    resource_rows = [entry for entry in rows if entry["resource_id"] != "inventory:namespace"]
    assert len(resource_rows) <= 1
    return (resource_rows or rows)[0], report


def test_declared_policy_passes_only_presence(candidate):
    row, report = finding(candidate, snapshot(policies=[policy()]))
    assert row["status"] == "PASS"
    assert row["evidence"]["network_policy_count"] == 1
    assert "CNI enforcement" in row["evidence"]["semantics"]
    assert report["coverage"]


def test_authoritative_empty_fails_and_scope_is_immutable(candidate):
    row, _ = finding(candidate, snapshot())
    assert row["status"] == "FAIL" and row["evidence"]["network_policy_count"] == 0
    scoped, _ = finding(candidate, snapshot(scope="apps"))
    assert scoped["status"] == "FAIL"


@pytest.mark.parametrize("namespace_status,policy_status", [
    ("partial", "empty"), ("denied", "empty"), ("collected", "partial"),
    ("collected", "denied"), ("collected", "not_collected"),
])
def test_incomplete_dependency_is_unknown(candidate, namespace_status, policy_status):
    row, _ = finding(candidate, snapshot(namespace_status=namespace_status, policy_status=policy_status))
    assert row["status"] in {"UNKNOWN", "DENIED"}


def test_missing_or_foreign_operator_exemption_is_unknown(candidate):
    missing, _ = finding(candidate, snapshot(system=None))
    assert missing["status"] == "UNKNOWN"
    foreign = snapshot()
    foreign["metadata"]["compliance_policy"]["cluster_id"] = "cluster-b"
    foreign.pop("snapshot_id")
    foreign = make_snapshot("k8s", foreign["scopes"], foreign["collections"], created_at=NOW,
                            metadata=foreign["metadata"])
    row, _ = finding(candidate, foreign)
    assert row["status"] == "UNKNOWN"


def test_explicit_system_only_and_no_implicit_kube_system_exemption(candidate):
    explicit, _ = finding(candidate, snapshot(name="kube-public", system=("kube-public",)))
    assert explicit["status"] == "NOT_APPLICABLE"
    non_exempt, _ = finding(candidate, snapshot(name="kube-system", system=("kube-public",)))
    assert non_exempt["status"] == "FAIL"


def test_foreign_namespace_policy_does_not_satisfy_presence(candidate):
    row, _ = finding(candidate, snapshot(policies=[policy(namespace_name="other")]))
    assert row["status"] == "FAIL"


def test_foreign_cluster_and_mutated_id_are_unknown(candidate):
    foreign = policy()
    foreign["provenance"]["cluster_id"] = "cluster-b"
    row, _ = finding(candidate, snapshot(policies=[foreign]))
    assert row["status"] == "UNKNOWN"
    malformed = policy()
    malformed["id"] = "k8s://cluster-b/networkpolicy/apps/forged"
    row, _ = finding(candidate, snapshot(policies=[malformed]))
    assert row["status"] == "UNKNOWN"


def test_equal_namespace_names_in_separate_clusters_do_not_collide(candidate):
    first, _ = finding(candidate, snapshot(cluster="cluster-a", policies=[policy("cluster-a")]))
    second, _ = finding(candidate, snapshot(cluster="cluster-b"))
    assert first["status"] == "PASS" and second["status"] == "FAIL"
    assert first["resource_id"] != second["resource_id"]


def test_existing_inventory_remains_manual_on_presence(candidate):
    _, report = finding(candidate, snapshot(policies=[policy()]),
                        checks=(CHECK_ID, "k8s.network.namespace_policy_inventory"))
    existing = [entry for entry in report["findings"]
                if entry["check_id"] == "k8s.network.namespace_policy_inventory"]
    assert len(existing) == 1 and existing[0]["status"] == "MANUAL"


def test_managed_system_and_unrelated_check_keep_original_wrapper(candidate):
    snap = snapshot(name="kube-system", system=("kube-public",))
    target, report = finding(candidate, snap, checks=(CHECK_ID, "k8s.network.namespace_policy_inventory"))
    prior = [row for row in report["findings"] if row["check_id"] == "k8s.network.namespace_policy_inventory"]
    assert len(prior) == 1 and prior[0]["status"] == "NOT_APPLICABLE"
    assert prior[0]["resource_id"] == target["resource_id"]
    listed = [check for check in CHECKS if check.id == "k8s.network.namespace_policy_inventory"]
    assert len(listed) == 1
    assert evaluate_check(listed[0].id, namespace(name="kube-system"), {
        "context": {"provider": "k8s", "scope": "*", "metadata": {"cluster_id": "cluster-a"}},
        "collections": {"networkpolicy": [{"scope": "*", "type": "networkpolicy", "status": "empty", "items": []}]},
        "networkpolicy": [],
    })[0] == "NOT_APPLICABLE"


def test_multiple_namespaces_share_one_validated_scope(candidate, monkeypatch):
    traversals = {"namespace": 0, "networkpolicy": 0, "system": 0}
    inventory = k8s_namespace_policy_presence._inventory
    system_namespaces = k8s_namespace_policy_presence._system_namespaces

    def counted_inventory(index, kind, scope):
        traversals[kind] += 1
        return inventory(index, kind, scope)

    def counted_system(context, cluster):
        traversals["system"] += 1
        return system_namespaces(context, cluster)

    monkeypatch.setattr(k8s_namespace_policy_presence, "_inventory", counted_inventory)
    monkeypatch.setattr(k8s_namespace_policy_presence, "_system_namespaces", counted_system)
    owner_meta = _owner_policy_metadata({"compliance_policy": {
        "cluster_id": "cluster-a", "max_policy_items": 10, "observed_at": NOW,
        "max_age_seconds": 300, "system_namespaces": ["kube-public"]}}, "cluster-a", NOW)
    snap = make_snapshot("k8s", ["*"], [
        {"type": "namespace", "scope": "*", "service": "kubernetes", "status": "collected",
         "items": [namespace(name=name) for name in ("apps", "batch", "empty")]},
        {"type": "networkpolicy", "scope": "*", "service": "kubernetes", "status": "collected",
         "items": [policy(namespace_name="apps", name="one"),
                   policy(namespace_name="apps", name="two"), policy(namespace_name="batch")]},
    ], created_at=NOW, metadata={"cluster_id": "cluster-a", "compliance_policy": owner_meta})
    report = evaluate_snapshot(snap, checks=[CHECK_ID])
    observed = {row["evidence"]["namespace"]: (row["status"], row["evidence"]["network_policy_count"])
                for row in report["findings"] if row["check_id"] == CHECK_ID}
    assert observed == {"apps": ("PASS", 2), "batch": ("PASS", 1), "empty": ("FAIL", 0)}
    assert traversals == {"namespace": 1, "networkpolicy": 1, "system": 1}
