"""Operator-attested kubelet metadata coverage requires current Node identities."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from peaso.collectors.k8s import K8sReadError, collect


NOW = datetime.now(timezone.utc).isoformat()
NODES = [("node-a", "uid-a"), ("node-b", "uid-b")]


@pytest.fixture(autouse=True)
def current_test_evidence_time(monkeypatch):
    # Collection-time fixtures must not expire while unrelated tests execute.
    # Freeze both clocks; the production 600-second freshness guard is unchanged.
    fixed = datetime.fromisoformat(NOW)
    class EvidenceDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed.astimezone(tz) if tz else fixed.replace(tzinfo=None)
    monkeypatch.setattr("peaso.collectors.k8s.datetime", EvidenceDateTime)
    monkeypatch.setitem(globals(), "datetime", EvidenceDateTime)


class NodeAPI:
    server = "https://fixture.invalid"
    api_client = SimpleNamespace(configuration=SimpleNamespace(host=server))

    def __init__(self, nodes=NODES, denied=False):
        self.nodes = nodes
        self.denied = denied
        self.calls = []

    def get_json(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        if self.denied:
            raise K8sReadError("permission_denied", 403)
        assert path == "/api/v1/nodes"
        page = int((params or {}).get("continue", "0"))
        name, uid = self.nodes[page]
        return {"metadata": {"resourceVersion": "7", **({"continue": str(page + 1)} if page + 1 < len(self.nodes) else {})},
                "items": [{"metadata": {"name": name, "uid": uid}}]}


def request(*, rows=None, manifest=None, max_age=600, max_pages=None, cluster="fixture"):
    rows = rows if rows is not None else [
        {"component": "kubelet", "node_name": name, "node_uid": uid,
         "observed_at": NOW, "configuration": {"podPidsLimit": 4096}} for name, uid in NODES]
    options = {"inventories": ["component_configuration"],
               "metadata_evidence": {"component_configuration": rows},
               "component_metadata_policy": {"max_age_seconds": max_age}}
    if manifest is not False:
        options["metadata_evidence_coverage"] = {"component_configuration": manifest if manifest is not None else
            {"status": "complete", "cluster_id": cluster, "observed_at": NOW,
             "nodes": [{"name": name, "uid": uid} for name, uid in NODES]}}
    if max_pages is not None:
        options["max_pages"] = max_pages
    return {"provider": "k8s", "options": options, "auth": {"cluster_id": cluster}}


def snapshot(api=None, **kwargs):
    api = api or NodeAPI()
    result = collect(request(**kwargs), api=api)
    return result, api


def test_complete_attestation_matches_paged_current_node_name_and_uid_without_runtime_claim():
    result, api = snapshot()
    coverage = result["metadata"]["component_configuration_coverage"]
    assert coverage["status"] == "attested_complete" and coverage["node_count"] == 2
    assert coverage["runtime_verified"] is False
    assert [path for path, _ in api.calls] == ["/api/v1/nodes", "/api/v1/nodes"]
    assert api.calls[1][1]["continue"] == "1"
    assert sum(c["type"] == "node" for c in result["collections"]) == 1
    assert "node" not in result["metadata"]["omitted_inventories"]
    rows = next(c["items"] for c in result["collections"] if c["type"] == "component_configuration")
    assert {(r["node_name"], r["node_uid"]) for r in rows} == set(NODES)
    assert all(r["provenance"]["runtime_verified"] is False for r in rows)
    assert all("component_configuration_coverage" not in r for r in rows)


def test_absent_manifest_does_not_add_node_read_or_claim_coverage():
    result, api = snapshot(manifest=False)
    assert api.calls == []
    assert result["metadata"]["component_configuration_coverage"]["status"] == "unknown"
    assert "node" in result["metadata"]["omitted_inventories"]


@pytest.mark.parametrize("rows", [
    [{"component": "kubelet", "node_name": "node-a", "node_uid": "old-uid", "observed_at": NOW,
      "configuration": {"podPidsLimit": 4096}},
     {"component": "kubelet", "node_name": "node-b", "node_uid": "uid-b", "observed_at": NOW,
      "configuration": {"podPidsLimit": 4096}}],
    [{"component": "kubelet", "node_name": "node-a", "node_uid": "uid-a", "observed_at": NOW,
      "configuration": {"podPidsLimit": 4096}}],
])
def test_recreated_or_missing_node_attestation_cannot_match_current_inventory(rows):
    result, _ = snapshot(rows=rows)
    assert result["metadata"]["component_configuration_coverage"]["status"] == "unknown"


def test_duplicate_or_foreign_manifest_identity_is_unknown():
    base = {"status": "complete", "cluster_id": "fixture", "observed_at": NOW,
            "nodes": [{"name": name, "uid": uid} for name, uid in NODES]}
    for manifest in ({**base, "cluster_id": "another"}, {**base, "nodes": [base["nodes"][0]] * 2}):
        result, _ = snapshot(manifest=manifest)
        assert result["metadata"]["component_configuration_coverage"]["status"] == "unknown"


@pytest.mark.parametrize("nodes", [
    [("node-a", "uid-a"), ("node-a", "uid-b")],
    [("node-a", "uid-a"), ("node-b", "uid-a")],
])
def test_current_node_list_rejects_duplicate_names_or_duplicate_uids(nodes):
    result, _ = snapshot(api=NodeAPI(nodes=nodes))
    assert result["metadata"]["component_configuration_coverage"]["reason"] == "duplicate_node_identity"


@pytest.mark.parametrize("identities", [
    [("node-a", "uid-a"), ("node-a", "uid-b")],
    [("node-a", "uid-a"), ("node-b", "uid-a")],
])
def test_manifest_rejects_duplicate_names_or_duplicate_uids(identities):
    manifest = {"status": "complete", "cluster_id": "fixture", "observed_at": NOW,
                "nodes": [{"name": name, "uid": uid} for name, uid in identities]}
    result, _ = snapshot(manifest=manifest)
    assert result["metadata"]["component_configuration_coverage"]["reason"] == "duplicate_node_identity"


def test_valid_declared_node_ids_are_stable_across_order_and_cluster_scoped():
    first, _ = snapshot()
    rows = [c["items"] for c in first["collections"] if c["type"] == "component_configuration"][0]
    reversed_rows = [{"component": "kubelet", "node_name": name, "node_uid": uid,
                      "observed_at": NOW, "configuration": {"podPidsLimit": 4096}}
                     for name, uid in reversed(NODES)]
    second, _ = snapshot(rows=reversed_rows)
    next_rows = [c["items"] for c in second["collections"] if c["type"] == "component_configuration"][0]
    assert {r["id"] for r in rows} == {r["id"] for r in next_rows}
    other, _ = snapshot(cluster="another")
    other_rows = [c["items"] for c in other["collections"] if c["type"] == "component_configuration"][0]
    assert {r["id"] for r in rows}.isdisjoint({r["id"] for r in other_rows})


def test_duplicate_declared_component_ids_do_not_collide_and_coverage_is_unknown():
    duplicate = [{"component": "kubelet", "node_name": "node-a", "node_uid": "uid-a",
                  "observed_at": NOW, "configuration": {"podPidsLimit": 4096}}] * 2
    result, _ = snapshot(rows=duplicate)
    rows = [c["items"] for c in result["collections"] if c["type"] == "component_configuration"][0]
    assert len({r["id"] for r in rows}) == 2
    assert result["metadata"]["component_configuration_coverage"]["reason"] == "duplicate_node_identity"


def test_stale_future_and_invalid_attestation_timestamps_are_unknown():
    stale = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
    for at in (stale, future, "not-a-time"):
        rows = [{"component": "kubelet", "node_name": name, "node_uid": uid,
                 "observed_at": at, "configuration": {"podPidsLimit": 4096}} for name, uid in NODES]
        result, _ = snapshot(rows=rows)
        assert result["metadata"]["component_configuration_coverage"]["status"] == "unknown"


def test_denied_or_truncated_node_list_and_unapproved_freshness_remain_unknown():
    result, _ = snapshot(api=NodeAPI(denied=True))
    assert result["metadata"]["component_configuration_coverage"]["status"] == "unknown"
    result, _ = snapshot(max_pages=1)
    assert result["metadata"]["component_configuration_coverage"]["status"] == "unknown"
    result, _ = snapshot(max_age=0)
    assert result["metadata"]["component_configuration_coverage"]["status"] == "unknown"


def test_missing_current_node_uid_is_unavailable_in_normal_and_attested_collections():
    bad_node = NodeAPI(nodes=[("node-a", "")])
    ordinary = collect({"provider": "k8s", "options": {"inventories": ["node"]},
                        "auth": {"cluster_id": "fixture"}}, api=bad_node)
    node = next(c for c in ordinary["collections"] if c["type"] == "node")
    assert node["status"] not in ("collected", "empty") and node["items"] == []
    assert node["error"]["code"] == "node_identity_missing"
    attested, _ = snapshot(api=NodeAPI(nodes=[("node-a", "")]))
    assert attested["metadata"]["component_configuration_coverage"]["status"] == "unknown"
