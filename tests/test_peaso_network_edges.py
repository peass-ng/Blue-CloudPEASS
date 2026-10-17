"""Tenant-scoped, bounded native network edge detail route."""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso.analysis.common import stable_id
from peaso.auth import Identity
from peaso.auth.api_keys import mint_key
from peaso.server.config import Settings
from peaso.storage import StoreError
from peaso.storage.artifacts import reference_for
from peaso.server.app import create_app


SCAN = "1" * 32


class Users:
    def authenticate(self, header):
        if header in {"Bearer alice", "Bearer bob"}:
            return Identity(header[7:])
        raise HTTPException(401, "Invalid authentication")


class Store:
    def __init__(self, manifest):
        self.manifest = manifest
        self.key_id, self.token, digest = mint_key()
        self.record = {"tenant": "alice", "secret_sha256": digest, "revoked_at": None,
                       "expires_at": None, "cognito_username": None}

    def job(self, tenant, ident):
        if tenant != "alice" or ident != SCAN:
            raise StoreError(404, "Scan not found")
        return {"id": SCAN, "status": "completed", "report": self.manifest}

    def api_key(self, key_id):
        return self.record if key_id == self.key_id else None

    def touch_api_key(self, tenant, key_id):
        return tenant == "alice" and key_id == self.key_id and self.record["revoked_at"] is None


class Artifacts:
    def __init__(self, items):
        self.items = items
        self.reads = []

    def get(self, tenant, reference):
        self.reads.append((tenant, reference))
        return self.items[reference]


@pytest.fixture
def api(tmp_path):
    edges = []
    a, b = stable_id("node-a"), stable_id("node-b")
    for i in range(123):
        edges.append({"id": stable_id("edge", i), "source": a, "target": b,
                      "type": "rule_candidate", "layer": "modeled_rule", "confidence": "medium",
                      "evidence": {"source": {"snapshot_id": "snap-1", "resource_id": "sg-1",
                                               "resource_type": "security_group", "scope": "account/region",
                                               "path": f"IpPermissions[{i}]", "collection_status": "collected",
                                               "request_evidence": {"secret": "never-return"}},
                                   "native_rule": {"secret": "never-return"}}})
    nodes = [{"id": a, "label": "Public rule", "native_id": "sg-1", "resource_id": "r-1",
              "type": "security_group", "provider": "aws", "scope": "account/region"},
             {"id": b, "label": "Attached instance", "native_id": "i-1", "resource_id": "r-2",
              "type": "instance", "provider": "aws", "scope": "account/region"}]
    group_id = stable_id("listed-group")
    manifest_ref = reference_for("alice", SCAN, "manifest")
    graph_ref = reference_for("alice", SCAN, "graph-network")
    projection_ref = reference_for("alice", SCAN, "graph-network")
    manifest = {"bundle_version": 1, "summary": {"snapshot_id": "snap-1"},
                "graphs": {"network": graph_ref}, "graph_projections": {"network": projection_ref}}
    artifact = Artifacts({manifest_ref: manifest, graph_ref: {"nodes": nodes, "edges": edges},
                          projection_ref: {"edges": [{"id": group_id, "underlying_count": len(edges),
                                                       "edge_refs": [e["id"] for e in edges]}]}})
    store = Store(manifest_ref)
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    with TestClient(create_app(settings, store=store, authenticator=Users(), artifacts=artifact),
                    base_url="http://127.0.0.1:8000") as client:
        yield client, store, artifact, manifest, edges, group_id


def route():
    return f"/api/scans/{SCAN}/graphs/network/edges"


def test_explicit_native_ids_and_secret_free_labels(api):
    client, store, artifact, _, edges, _ = api
    response = client.get(route(), params=[("ids", edges[2]["id"]), ("ids", edges[0]["id"])],
                          headers={"Authorization": "Bearer alice"})
    assert response.status_code == 200, response.text
    result = response.json()
    assert [e["id"] for e in result["items"]] == [edges[2]["id"], edges[0]["id"]]
    assert result["items"][0]["source"]["label"] == "Public rule"
    assert result["items"][0]["source"]["native_id"] == "sg-1"
    assert result["items"][0]["evidence_refs"][0]["path"] == "IpPermissions[2]"
    assert set(result["items"][0]["evidence_refs"][0]) == {
        "snapshot_id", "resource_id", "resource_type", "scope", "path", "collection_status"}
    assert result["items"][0]["evidence_status"] == "source_reference"
    assert "never-return" not in response.text and "native_rule" not in response.text
    assert len([ref for _, ref in artifact.reads if ref != store.manifest]) == 2
    client.get(route(), params={"ids": edges[1]["id"]}, headers={"Authorization": "Bearer alice"})
    assert len([ref for _, ref in artifact.reads if ref != store.manifest]) == 2


def test_group_page_and_explicit_limit(api):
    client, _, artifact, manifest, edges, group_id = api
    first = client.get(route(), params={"group_id": group_id, "limit": 100}, headers={"Authorization": "Bearer alice"})
    assert first.status_code == 200
    assert first.json()["total"] == 123 and first.json()["next_cursor"] == "100"
    second = client.get(route(), params={"group_id": group_id, "cursor": "100", "limit": 100},
                        headers={"Authorization": "Bearer alice"})
    assert [e["id"] for e in second.json()["items"]] == [e["id"] for e in edges[100:]]
    assert second.json()["next_cursor"] is None
    assert first.json()["items"][-1]["id"] == edges[99]["id"]
    assert first.json()["items"] == client.get(
        route(), params={"group_id": group_id, "limit": 100},
        headers={"Authorization": "Bearer alice"}).json()["items"]
    assert artifact.items[manifest["graph_projections"]["network"]]["edges"][0]["edge_refs"] == [
        edge["id"] for edge in edges]
    assert client.get(route(), params=[("ids", e["id"]) for e in edges[:101]],
                      headers={"Authorization": "Bearer alice"}).status_code == 422


def test_malformed_unknown_foreign_and_revoked(api):
    client, store, _, _, edges, group_id = api
    alice = {"Authorization": "Bearer alice"}
    assert client.get(route(), params={"ids": "../graph.json"}, headers=alice).status_code == 422
    assert client.get(route(), params={"ids": stable_id("unknown")}, headers=alice).status_code == 404
    assert client.get(route(), params={"group_id": stable_id("unknown")}, headers=alice).status_code == 404
    assert client.get(route(), params={"group_id": group_id, "cursor": "-1"}, headers=alice).status_code == 422
    assert client.get(route(), params={"group_id": group_id, "cursor": "124"}, headers=alice).status_code == 404
    assert client.get(route(), params={"group_id": group_id, "limit": "101"}, headers=alice).status_code == 422
    assert client.get(route(), params=[("ids", edges[0]["id"]), ("ids", edges[0]["id"])], headers=alice).status_code == 422
    assert client.get(route(), headers=alice).status_code == 422
    assert client.get(route(), params={"cursor": "0"}, headers=alice).status_code == 422
    assert client.get(route(), params={"ids": edges[0]["id"], "limit": "1"}, headers=alice).status_code == 422
    assert client.get(route(), params={"ids": edges[0]["id"], "group_id": group_id}, headers=alice).status_code == 422
    assert client.get(route(), params={"ids": edges[0]["id"]}, headers={"Authorization": "Bearer bob"}).status_code == 404
    assert client.get(route(), params={"ids": "../graph.json"}, headers={"Authorization": "Bearer bob"}).status_code == 404
    assert client.get("/api/scans/" + "2" * 32 + "/graphs/network/edges", params={"ids": edges[0]["id"]}, headers=alice).status_code == 404
    assert client.get(route(), params={"ids": edges[0]["id"]}, headers={"Authorization": "Bearer " + store.token}).status_code == 200
    assert client.post("/api/scans", json={}, headers={"Authorization": "Bearer " + store.token}).status_code == 403
    store.record["revoked_at"] = 1
    assert client.get(route(), params={"ids": edges[0]["id"]}, headers={"Authorization": "Bearer " + store.token}).status_code == 401


def test_unsupported_or_missing_artifact(api):
    client, store, artifact, manifest, edges, _ = api
    own = {"Authorization": "Bearer alice"}
    manifest["bundle_version"] = 0
    assert client.get(route(), params={"ids": edges[0]["id"]}, headers=own).status_code == 409
    manifest["bundle_version"] = 1
    artifact.items.pop(manifest["graphs"]["network"])
    assert client.get(route(), params={"ids": edges[0]["id"]}, headers=own).status_code == 409


def test_sampled_projection_group_is_not_listable(api):
    client, _, artifact, manifest, edges, group_id = api
    projection = artifact.items[manifest["graph_projections"]["network"]]
    projection["edges"][0]["edge_refs"] = [edges[0]["id"]]
    own = {"Authorization": "Bearer alice"}
    response = client.get(route(), params={"group_id": group_id}, headers=own)
    assert response.status_code == 404
    assert client.get(route(), params={"ids": edges[0]["id"]}, headers=own).status_code == 200
