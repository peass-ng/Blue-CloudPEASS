"""Complete IAM grant lists behind slim graph cards: the expanded report and the grants endpoint."""
from fastapi.testclient import TestClient

from peaso.analysis.iam import GRANT_SAMPLE, full_grants
from peaso.engine import NATIVE_DATA, compact_report, evaluate_snapshot, expand_report
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.snapshot import resources
from peaso.worker import Worker
from tests.test_peaso_iam_graph_slim import OWNER_PERMISSIONS, gcp_snapshot


def _referencing_node(graph):
    return next(n for n in graph["nodes"] if (n.get("card") or {}).get("referenced_grants"))


def test_expanded_report_inlines_the_complete_referenced_grant_list():
    snap = gcp_snapshot(["p1"])
    report = evaluate_snapshot(snap, categories=["iam_graph", "least_privilege"])
    graph = report["graphs"]["iam"]
    by_id = {n["id"]: n for n in graph["nodes"]}
    ref = _referencing_node(graph)["card"]["referenced_grants"][0]
    source = by_id[ref["source_node"]]
    assert source["card"]["source_grants_truncated"] and len(source["card"]["source_grants"]) == GRANT_SAMPLE
    assert ref["grant_count"] == source["card"]["grant_count"] == len(OWNER_PERMISSIONS)
    expanded = expand_report(report, snap)
    expanded_ref = _referencing_node(expanded["graphs"]["iam"])["card"]["referenced_grants"][0]
    native = {r["id"]: r for r in resources(snap)}[source["card"]["detail_ref"]["resource_ref"]]
    assert expanded_ref["grants"] == full_grants(native, "gcp")
    assert [g["native_grant"] for g in expanded_ref["grants"]] == OWNER_PERMISSIONS
    # Compacting the expanded report restores the count, not the sample size.
    compacted = _referencing_node(compact_report(expanded)["graphs"]["iam"])["card"]["referenced_grants"][0]
    assert compacted["grant_count"] == len(OWNER_PERMISSIONS)
    assert "card.grant_count" in NATIVE_DATA["referenced_grants"] and "detail_ref" in NATIVE_DATA["referenced_grants"]
    assert "/graphs/iam/grants/" in NATIVE_DATA["referenced_grants"]


def test_grants_endpoint_returns_complete_severity_annotated_list(tmp_path):
    snap = gcp_snapshot(["p1"])
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="local-test-token-0123456789abcdef")
    from tests.test_peaso_graph_scale import Identities
    with TestClient(create_app(settings, authenticator=Identities()), base_url="http://127.0.0.1:8000") as client:
        client.headers["Authorization"] = "Bearer alice"
        connector = client.post("/api/connectors", json={"name": "grants", "provider": "gcp", "auth": {}, "scopes": snap["scopes"],
                                                         "options": {"snapshot": snap}})
        assert connector.status_code == 201, connector.text
        job = client.post("/api/scans", json={"ai_enabled": False, "connector_id": connector.json()["id"], "categories": ["iam_graph", "least_privilege"]})
        assert job.status_code == 201, job.text
        assert Worker("collector", settings).run_once() and Worker("analyzer", settings).run_once()
        ident = job.json()["id"]
        role = next(n for n in client.get(f"/api/scans/{ident}/graphs/iam").json()["nodes"] if n["label"] == "roles/owner")
        ref = role["card"]["detail_ref"]["resource_ref"]
        assert role["card"]["detail_ref"]["endpoint"] == "/api/scans/{scan_id}/graphs/iam/grants/{resource_ref}"
        body = client.get(f"/api/scans/{ident}/graphs/iam/grants/{ref}")
        assert body.status_code == 200, body.text
        data = body.json()
        assert data["resource_ref"] == ref and data["provider"] == "gcp" and data["type"] == "iam_role"
        assert data["grant_count"] == len(data["grants"]) == role["card"]["grant_count"] == len(OWNER_PERMISSIONS)
        assert [g["native_grant"] for g in data["grants"]] == OWNER_PERMISSIONS
        assert all("severity" in g for g in data["grants"])
        assert data["grant_summary"] == role["card"]["grant_summary"]
        assert client.get(f"/api/scans/{ident}/graphs/iam/grants/sha256:missing").status_code == 404
        # Ownership is enforced like every other scan read.
        client.headers["Authorization"] = "Bearer bob"
        assert client.get(f"/api/scans/{ident}/graphs/iam/grants/{ref}").status_code == 404
