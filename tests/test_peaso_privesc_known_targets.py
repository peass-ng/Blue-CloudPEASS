"""Known-target paths remain separate from missing-fact diagnostics, including old reports."""
from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from peaso import privesc
from peaso.privesc.queries import GraphIndex, known_target_graph, shortest_paths
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore

from test_peaso_privesc_unresolved import ALICE, ACCOUNT, aws_snap, entry, role, trust_service, user
from test_peaso_privesc_integration import Identities


def legacy_graph():
    bob = f"arn:aws:iam::{ACCOUNT}:role/bob"
    absent = "unresolved:aws:missing-attachment"
    group = "unknown:aws:possible-sources"
    return {
        "nodes": [
            {"id": ALICE, "kind": "principal", "type": "aws_user", "label": "alice"},
            {"id": bob, "kind": "principal", "type": "aws_role", "label": "bob"},
            {"id": absent, "kind": "aggregate", "type": "aws_role", "members": [],
             "confidence": "unknown", "unresolved": True},
            {"id": group, "kind": "aggregate", "type": "principal_group", "members": [ALICE],
             "confidence": "unknown"},
        ],
        "edges": [
            {"id": "known", "source": ALICE, "target": bob, "confidence": "derived",
             "techniques": ["real", "uncertain"], "findings": ["real-finding", "unknown-finding"],
             "technique_details": [
                 {"id": "real", "confidence": "derived", "finding": "real-finding", "evidence_refs": [{"proof": "yes"}]},
                 {"id": "uncertain", "confidence": "unknown", "finding": "unknown-finding", "evidence_refs": []},
             ]},
            {"id": "unknown-target", "source": ALICE, "target": absent,
             "confidence": "unknown", "techniques": ["maybe"]},
            {"id": "unknown-source", "source": group, "target": bob,
             "confidence": "unknown", "techniques": ["maybe"]},
        ],
    }


def test_analysis_defaults_to_known_targets_but_keeps_missing_fact_coverage():
    technique = entry("aws-test-attached-role", "aws",
                      {"all_of": [{"action": "lambda:UpdateFunctionCode", "resource": "*"}]},
                      {"kind": "aws_role", "selector": {"attached_to_service": "lambda"},
                       "scope": "same_account"})
    alice = user("alice", {"Effect": "Allow", "Action": "lambda:UpdateFunctionCode", "Resource": "*"})
    snap = aws_snap([alice], [role("lambda-role", trust_service("lambda.amazonaws.com"))])
    public = privesc.analyze(snap, entries=[technique])
    diagnostic = privesc.analyze(snap, entries=[technique], include_unknown=True)
    assert not public["graph"]["edges"]
    assert any(row.get("kind") == "selector" for row in public["coverage"])
    assert any(edge["target"].startswith("unresolved:") for edge in diagnostic["graph"]["edges"])


def test_legacy_graph_removes_memberless_paths_and_mixed_unknown_details():
    raw = legacy_graph()
    clean = known_target_graph(raw)
    assert clean is not raw and raw["edges"][-1]["id"] == "unknown-source"
    assert {node["id"] for node in clean["nodes"]} == {ALICE, f"arn:aws:iam::{ACCOUNT}:role/bob"}
    assert [edge["id"] for edge in clean["edges"]] == ["known"]
    assert clean["edges"][0]["techniques"] == ["real"]
    assert clean["edges"][0]["findings"] == ["real-finding"]
    assert known_target_graph(clean) is clean
    assert shortest_paths(raw, ALICE, "unresolved:aws:missing-attachment") == []
    assert shortest_paths(raw, ALICE, "unresolved:aws:missing-attachment", include_unknown=True)
    assert shortest_paths(GraphIndex(clean), ALICE, "unresolved:aws:missing-attachment", include_unknown=True) == []


def test_direct_query_never_crosses_unknown_membership_by_default():
    bob = f"arn:aws:iam::{ACCOUNT}:role/bob"
    graph = {"nodes": [
        {"id": ALICE, "kind": "principal", "type": "aws_user"},
        {"id": bob, "kind": "principal", "type": "aws_role"},
        {"id": "unknown:possible-targets", "kind": "aggregate", "type": "aws_role",
         "members": [bob], "confidence": "unknown"},
    ], "edges": [
        {"id": "claimed", "source": ALICE, "target": "unknown:possible-targets",
         "confidence": "derived", "techniques": ["claimed"]},
    ]}
    assert shortest_paths(graph, ALICE, bob) == []
    assert shortest_paths(graph, ALICE, bob, include_unknown=True)
    assert known_target_graph(graph)["edges"] == []


@pytest.mark.parametrize("hosted", [False, True])
def test_api_sanitizes_old_graph_before_serving_or_querying_it(tmp_path, hosted):
    class SignedArtifacts(FileArtifacts):
        def presign(self, tenant, reference, filename=None):
            return "https://signed.invalid/" + reference

    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity",
                        local_token="local-test-token-0123456789abcdef")
    store = SQLiteStore(settings.state_dir)
    artifacts = (SignedArtifacts if hosted else FileArtifacts)(settings.state_dir / "artifacts")
    ident = "a" * 32
    raw = legacy_graph()
    reference = artifacts.put("alice", ident, "graph-privesc", raw)
    bundle = {"bundle_version": 1, "graphs": {"privesc": reference},
              "graph_projections": {"privesc": reference}}
    manifest = artifacts.put("alice", ident, "manifest", bundle)
    with store.transaction() as db:
        db.execute("INSERT INTO jobs(id,tenant,connector_id,data,connector,status,created,deadline,report) "
                   "VALUES(?,?,?,?,?,?,?,?,?)",
                   (ident, "alice", "connector", json.dumps({}), json.dumps({"data": {}}),
                    "completed", time.time(), time.time() + 3600, manifest))
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()),
                    base_url="http://127.0.0.1:8000") as client:
        client.headers["Authorization"] = "Bearer alice"
        for suffix in ("", "?max_nodes=500"):
            response = client.get(f"/api/scans/{ident}/graphs/privesc{suffix}")
            assert response.status_code == 200, response.text
            graph = response.json()
            assert "download_url" not in graph
            assert {n["id"] for n in graph["nodes"]} == {ALICE, f"arn:aws:iam::{ACCOUNT}:role/bob"}
            assert [e["id"] for e in graph["edges"]] == ["known"]
        paths = client.get(f"/api/scans/{ident}/privesc/paths",
                           params={"source": ALICE, "target": "unresolved:aws:missing-attachment",
                                   "include_unknown": "true"})
        assert paths.status_code == 200 and paths.json()["items"] == []
        known = client.get(f"/api/scans/{ident}/privesc/paths",
                           params={"source": ALICE, "target": f"arn:aws:iam::{ACCOUNT}:role/bob"})
        assert known.status_code == 200 and known.json()["items"]
        assert client.get(f"/api/scans/{ident}/privesc/principals/unresolved:aws:missing-attachment").status_code == 404
        subgraph = client.get(f"/api/scans/{ident}/graphs/privesc/subgraph").json()
        assert all(not n["id"].startswith(("unknown:", "unresolved:")) for n in subgraph["nodes"])
        if hosted:
            # Keep the efficient signed-download path for already clean artifacts.
            clean_reference = artifacts.put("alice", ident, "graph-privesc", known_target_graph(raw))
            clean_manifest = artifacts.put("alice", ident, "manifest",
                                           {**bundle, "graphs": {"privesc": clean_reference},
                                            "graph_projections": {"privesc": clean_reference}})
            with store.transaction() as db:
                db.execute("UPDATE jobs SET report=? WHERE id=?", (clean_manifest, ident))
            signed = client.get(f"/api/scans/{ident}/graphs/privesc").json()
            assert signed["download_url"].endswith(clean_reference)
