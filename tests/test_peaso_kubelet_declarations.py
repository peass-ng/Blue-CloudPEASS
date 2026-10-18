"""Published kubelet declaration checks through the real collector and engine."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks.catalog import requirement_tags_for
from peaso.collectors.k8s import collect
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

PID = "k8s.cis.a_limit_is_set_on_pod_pids"
SECCOMP = "k8s.cis.the_seccomp_default_parameter_is_set_to_true"
ROTATION_DECLARATION = "k8s.cis.kubelet_rotate_kubelet_server_certificate_true"
NOW = datetime.now(timezone.utc).isoformat()


class NodeAPI:
    server = "https://fixture.invalid"
    api_client = SimpleNamespace(configuration=SimpleNamespace(host=server))

    def __init__(self):
        self.calls = []

    def get_json(self, path, params=None):
        self.calls.append(path)
        assert path == "/api/v1/nodes"
        return {"metadata": {"resourceVersion": "7"},
                "items": [{"metadata": {"name": "node-a", "uid": "uid-a"}}]}


def observed(configuration, *, node="node-a", uid="uid-a"):
    return {"id": f"k8s://fixture/component_configuration/kubelet/node/{uid}",
            "component": "kubelet", "node_name": node, "node_uid": uid,
            "observed_at": NOW, "configuration": configuration,
            "provenance": {"cluster_id": "fixture", "source": "operator-supplied metadata",
                           "runtime_verified": False, "namespace": "_cluster"}}


def snapshot(rows=(), *, component_status="collected", node_status="collected", complete=False):
    nodes = [{"id": "k8s://fixture/node/node-a", "metadata": {"name": "node-a", "uid": "uid-a"}}]
    return make_snapshot("k8s", ["fixture"], [
        {"type": "node", "scope": "fixture", "status": node_status,
         "items": nodes if node_status == "collected" else []},
        {"type": "component_configuration", "scope": "fixture",
         "status": component_status, "items": list(rows)}], metadata={
             "cluster_id": "fixture",
             "component_configuration_coverage": {"status": "attested_complete" if complete else "unknown",
                                                  "cluster_id": "fixture"}})


def findings(snap, cid):
    report = evaluate_snapshot(snap, checks=[cid], include_not_applicable=True)
    rows = [row for row in report["findings"] if row["check_id"] == cid]
    coverage = [row for row in report["coverage"] if row.get("check_id") == cid]
    return rows, coverage


def test_only_two_signed_declarations_are_active_with_every_control_tag():
    # Historical node ID retained; the reviewed batch adds a third declaration.
    checks = {check.id: check for check in CHECKS}
    assert {PID, SECCOMP, ROTATION_DECLARATION} <= set(checks)
    assert len(checks) == len(CHECKS)
    for cid, expected_count, expected_control in ((PID, 5, "4.2.13"), (SECCOMP, 3, "4.2.14"),
                                                  (ROTATION_DECLARATION, 5, "4.2.11")):
        check = checks[cid]
        tags = requirement_tags_for(cid)
        assert check.severity == "medium" and check.category == "hardening"
        assert check.kind == "component_configuration" and check.control == "CM-6"
        assert HACKTRICKS in check.frameworks and HACKTRICKS in check.mapping
        assert len(tags) == expected_count
        assert len({tag["framework_id"] for tag in tags}) == expected_count
        assert all(tag["requirement_id"] == expected_control and tag["decision"] == "PARTIAL"
                   and tag["runtime_status"] == "partial" for tag in tags)


def test_fake_node_api_collection_and_real_engine_preserve_local_provenance():
    api = NodeAPI()
    request = {"provider": "k8s", "auth": {"cluster_id": "fixture"}, "options": {
        "inventories": ["component_configuration"],
        "metadata_evidence": {"component_configuration": [
            {"component": "kubelet", "node_name": "node-a", "node_uid": "uid-a",
             "observed_at": NOW, "configuration": {"podPidsLimit": 4096, "seccompDefault": True}}]},
        "component_metadata_policy": {"max_age_seconds": 600},
        "metadata_evidence_coverage": {"component_configuration": {
            "status": "complete", "cluster_id": "fixture", "observed_at": NOW,
            "nodes": [{"name": "node-a", "uid": "uid-a"}]}}}}
    collected = collect(request, api=api)
    assert api.calls == ["/api/v1/nodes"]
    for cid in (PID, SECCOMP):
        rows, _ = findings(collected, cid)
        assert [row["status"] for row in rows] == ["PASS"]
        assert rows[0]["evidence"]["observed_node_uid"] == "uid-a"
        assert rows[0]["evidence"]["cluster_declaration_coverage"] == "attested_complete"
        assert rows[0]["evidence"]["runtime_verified"] is False
    assert api.calls == ["/api/v1/nodes"]  # ordinary evaluation made no API call


@pytest.mark.parametrize("cid,configuration,status", [
    (PID, {"podPidsLimit": 0}, "FAIL"), (PID, {"podPidsLimit": -1}, "FAIL"),
    (SECCOMP, {"seccompDefault": False}, "FAIL"),
    (PID, {}, "UNKNOWN"), (SECCOMP, {}, "UNKNOWN"),
    (PID, {"podPidsLimit": True}, "UNKNOWN"),
    (SECCOMP, {"seccompDefault": 1}, "UNKNOWN"),
    (PID, {"configFile": "/var/lib/kubelet/config.yaml"}, "UNKNOWN"),
])
def test_observed_scalar_or_missing_and_untyped_facts(cid, configuration, status):
    rows, _ = findings(snapshot([observed(configuration)]), cid)
    assert [row["status"] for row in rows] == [status]


def test_foreign_node_and_cluster_do_not_supply_trusted_declaration():
    rows, _ = findings(snapshot([observed({"podPidsLimit": 4096}, node="foreign", uid="foreign")]), PID)
    assert [row["status"] for row in rows] == ["UNKNOWN"]
    foreign = observed({"seccompDefault": True})
    foreign["provenance"]["cluster_id"] = "other-cluster"
    rows, _ = findings(snapshot([foreign]), SECCOMP)
    assert [row["status"] for row in rows] == ["UNKNOWN"]


@pytest.mark.parametrize("collection_status,expected", [("denied", "DENIED"), ("empty", "EMPTY")])
def test_unavailable_component_inventory(collection_status, expected):
    rows, _ = findings(snapshot(component_status=collection_status), PID)
    assert [row["status"] for row in rows] == [expected]


@pytest.mark.parametrize("cid,configuration", [(PID, {"podPidsLimit": 0}),
                                                  (SECCOMP, {"seccompDefault": False})])
def test_measured_failure_survives_partial_inventory(cid, configuration):
    rows, coverage = findings(snapshot([observed(configuration)], component_status="partial", node_status="denied"), cid)
    assert sorted(row["status"] for row in rows) == ["FAIL", "UNKNOWN"]
    assert coverage[0]["status"] == "partial"
    failed = next(row for row in rows if row["status"] == "FAIL")
    assert failed["evidence"]["cluster_declaration_coverage"] == "unknown"
