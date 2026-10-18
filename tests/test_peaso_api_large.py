"""Large evidence remains complete in downloads while API responses stay bounded."""
import json
from fastapi.testclient import TestClient
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts
from peaso.storage.reports import publish_report
from peaso.auth import Identity


class Identities:
    def authenticate(self, value):
        return Identity("bob" if value == "Bearer bob" else "alice")


class SignedFiles(FileArtifacts):
    def presign(self, tenant, reference, filename=None):
        from peaso.storage.artifacts import check_reference
        check_reference(tenant, reference)
        return "https://private.example.invalid/" + reference + "?expires=300"


def completed_job(store, artifacts, report):
    connector = store.add_connector("alice", {"provider": "aws"}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    collector = store.claim("collector")
    store.finish(job["id"], collector["owner"], "collected", artifacts.put("alice", job["id"], "snapshot", {}))
    analyzer = store.claim("analyzer")
    reference = publish_report(artifacts, "alice", job["id"], report)
    store.finish(job["id"], analyzer["owner"], "completed", reference)
    return job["id"], artifacts.get("alice", reference)


def test_large_downloads_pages_details_facets_and_graph_envelopes(tmp_path):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="large-test-token-0123456789")
    store = SQLiteStore(settings.state_dir)
    artifacts = SignedFiles(settings.state_dir / "artifacts")
    findings = [{"id": f"finding-{index:05d}", "category": "hardening", "check_id": "fixture", "service": "s3" if index % 2 else "ec2", "provider": "aws", "title": "Full evidence", "severity": "high", "status": "FAIL" if index % 2 else "PASS", "resource_id": str(index), "scope": "fixture", "frameworks": ["NIST 800-53"], "evidence": {"payload": "native " * 10000}, "remediation": "Review access"} for index in range(620)]
    report = {"schema_version": "1.0", "provider": "aws", "snapshot_id": "fixture", "created_at": "2026-01-01T00:00:00Z", "scopes": ["fixture"], "resources": [], "findings": findings, "coverage": [{"status": "evaluated"}], "stats": {"finding_count": 620, "resource_count": 0}, "graphs": {"network": {"nodes": [], "edges": []}, "iam": {"nodes": [{"id": "large-node", "evidence": {"policy": "native " * 1000000}}], "edges": []}}}
    ident, bundle = completed_job(store, artifacts, report)
    assert artifacts.size("alice", bundle["report_json"]) > 30 * 1024 * 1024
    original_get = artifacts.get
    calls = []
    def bounded_get(tenant, reference):
        calls.append(reference)
        assert reference not in {bundle["report_json"], *bundle["graphs"].values()}, "API must not read complete downloads or giant graphs"
        return original_get(tenant, reference)
    artifacts.get = bounded_get
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()), base_url="http://127.0.0.1") as client:
        for format in ("json", "markdown"):
            response = client.get(f"/api/scans/{ident}/report?format={format}")
            assert response.status_code == 200 and response.json()["expires_in"] == 300 and len(response.content) < 1000
        summary = client.get(f"/api/scans/{ident}/summary").json()
        assert summary["finding_count"] == 620 and "findings" not in summary and summary["stats"]["by_category"] == {"hardening": 620}
        first = client.get(f"/api/scans/{ident}/findings?limit=200&group_by=resource_id").json()
        assert first["total"] == 620 and len(first["items"]) == 200 and first["next_offset"] == 200
        assert first["facets"]["services"] == ["ec2", "s3"] and "evidence" not in first["items"][0]
        assert len(json.dumps(first).encode()) < 200000
        filtered = client.get(f"/api/scans/{ident}/findings?service=s3&status=FAIL&framework=NIST%20800-53&limit=500").json()
        assert filtered["total"] == 310 and len(filtered["items"]) == 310 and not filtered["has_more"]
        assert not set(calls) & {chunk["reference"] for chunk in bundle["finding_chunks"]}, "Finding lists must read only summary indexes"
        detail = client.get(f"/api/scans/{ident}/findings/finding-00000")
        assert detail.json()["evidence"] == findings[0]["evidence"]
        graph = client.get(f"/api/scans/{ident}/graphs/iam").json()
        assert "download_url" in graph
        coverage = client.get(f"/api/scans/{ident}/coverage").json()
        assert coverage["total"] == 1
        reference = store.job("alice", ident)["report"]
        manifest = original_get("alice", reference)
        manifest["framework_filters"]["fixture-exact-version"] = ["fixture"]
        (artifacts.root / reference).write_text(json.dumps(manifest))
        version = client.get(f"/api/scans/{ident}/findings?framework=fixture-exact-version&limit=200").json()
        assert version["total"] == 620
        client.headers["Authorization"] = "Bearer bob"
        for path in ("report", "summary", "findings", "findings/finding-00000", "graphs/iam", "coverage"):
            assert client.get(f"/api/scans/{ident}/{path}").status_code == 404
    assert len(original_get("alice", bundle["report_json"])["findings"]) == 620


def test_signed_large_finding_envelope_carries_only_bounded_defensive_template(tmp_path):
    from peaso.remediation import report_templates
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="large-test-token-0123456789")
    store = SQLiteStore(settings.state_dir)
    artifacts = SignedFiles(settings.state_dir / "artifacts")
    check_id = "aws.gap.vpc.sg_world_any_common_ports"
    finding = {"id": "finding-large", "category": "exposure", "check_id": check_id,
               "service": "ec2", "provider": "aws", "title": "Broad ingress", "severity": "high",
               "status": "FAIL", "resource_id": "resource-1", "native_resource_id": "sg-12345678",
               "scope": "123456789012/us-east-1", "frameworks": [],
               "evidence": {"payload": "sensitive-evidence-marker" + "x" * (2 * 1024 * 1024)},
               "remediation": "Legacy review"}
    report = {"schema_version": "1.0", "provider": "aws", "snapshot_id": "fixture-large",
              "created_at": "2026-01-01T00:00:00Z", "scopes": ["123456789012/us-east-1"],
              "resources": [], "findings": [finding], "coverage": [], "stats": {}, "graphs": {},
              "remediation_templates": report_templates([check_id], "aws")}
    ident, bundle = completed_job(store, artifacts, report)
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()), base_url="http://127.0.0.1") as client:
        envelope = client.get(f"/api/scans/{ident}/findings/finding-large").json()
        assert envelope["download_url"].startswith("https://private.example.invalid/")
        assert len(json.dumps(envelope).encode()) < 64 * 1024
        assert "payload" not in envelope and "sensitive-evidence-marker" not in json.dumps(envelope)
        detail = envelope["remediation_details"]
        assert detail["steps"] and detail["references"]
        assert "sg-12345678" in detail["cli"][0]["code"]
        assert "<APPROVED_CIDR>" in detail["cli"][1]["code"]
        assert "<RULE_ID>" in detail["cli"][2]["code"]
        assert "Authorization" not in json.dumps(envelope)
