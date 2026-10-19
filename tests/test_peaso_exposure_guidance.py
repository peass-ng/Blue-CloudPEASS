"""Asset-specific presentation for both newly collected and archived exposure findings."""
import copy

import pytest

from peaso.engine import hydrate_finding
from peaso.remediation import details_for, exposure_details, template
from peaso.reports import _guidance_fields, _remediation_lines
from peaso.storage.reports import publish_report
from tests.test_peaso_findings_sorting import api

CHECK = "analysis.internet_exposure"
NETWORK_ACTION = "Consider whether this endpoint needs internet access; restrict unnecessary source networks or ports."


def row(evidence=None, status="FAIL"):
    return {"id": "f1", "check_id": CHECK, "provider": "aws", "scope": "123456789012/us-east-1",
            "category": "exposure", "service": "apigatewayv2", "resource_id": "api1", "title": "Public API",
            "severity": "medium", "frameworks": [], "status": status, "evidence": evidence or {},
            "remediation": "Old generic guidance"}


@pytest.mark.parametrize("evidence,status,fragment", [
    ({"exposure_kind": "api", "exposed_ports": ["tcp/443"]}, "FAIL", NETWORK_ACTION),
    ({"exposure_kind": "external_share", "external_scope_ids": ["999988887777"]}, "FAIL", "snapshot restore"),
    ({"data_exposure": True, "source": {"resource_type": "rds_snapshot"}}, "FAIL", "public snapshot restore"),
    ({"data_exposure": True, "source": {"resource_type": "bucket"}}, "FAIL", "policy or ACL"),
    ({"exposure_kind": "control_plane"}, "FAIL", "control-plane"),
    ({"exposure_kind": "api", "exposed_ports": ["tcp/443"]}, "UNKNOWN", "Collect the missing configuration"),
    ({"exposure_kind": "api"}, "PASS", "Keep the access restrictions"),
])
def test_actions_follow_asset_and_verdict_without_mutating_the_template(evidence, status, fragment):
    shared = {"summary": "Old generic summary", "steps": ["Inspect", "Change", "Retest"],
              "references": [{"title": "Docs", "url": "https://example.com"}], "cli": []}
    before = copy.deepcopy(shared)
    finding = row(evidence, status)
    result = exposure_details(finding, shared)
    assert fragment in result["summary"]
    assert result["steps"] == [result["summary"]]
    assert result["references"] == shared["references"] and result["cli"] == shared["cli"]
    assert shared == before
    assert hydrate_finding(finding)["remediation"] == result["summary"]
    assert details_for(CHECK, finding)["steps"] == result["steps"]


def test_archived_markdown_uses_dynamic_actions_and_distinct_guidance_groups():
    shared = {"summary": "Old generic summary", "steps": ["Inspect every path", "Find owner"], "references": [], "cli": []}
    network = row({"exposure_kind": "api"})
    snapshot = row({"exposure_kind": "external_share"})
    text = "\n".join(_remediation_lines(network, {CHECK: shared}))
    assert "Inspect every path" not in text and NETWORK_ACTION in text.replace("\\", "")
    assert _guidance_fields(network, {CHECK: shared}) != _guidance_fields(snapshot, {CHECK: shared})
    other = {**network, "check_id": "other.check"}
    assert exposure_details(other, shared) is shared


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure", "k8s"])
def test_exposure_provider_templates_have_one_short_default_action(provider):
    details = template(CHECK, provider)
    assert details["steps"] == [NETWORK_ACTION]
    assert len(details["caveats"]) == 1
    assert details["references"]


def test_archived_finding_api_overrides_actions_but_retains_evidence_and_references(api):
    client, store, artifacts = api
    finding = row({"exposure_kind": "api", "exposed_ports": ["tcp/443"], "unresolved": [],
                   "semantics": "Declared-configuration model; no traffic was sent."})
    connector = store.add_connector("alice", {"provider": "aws"}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    collector = store.claim("collector")
    store.finish(job["id"], collector["owner"], "collected", artifacts.put("alice", job["id"], "snapshot", {}))
    analyzer = store.claim("analyzer")
    archived = {"summary": "Old verbose summary", "steps": ["Trace every layer", "Find every owner"], "cli": [],
                "references": [{"title": "AWS security groups", "url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"}]}
    report = {"schema_version": "1.0", "provider": "aws", "snapshot_id": "fixture", "scopes": [],
              "resources": [], "findings": [finding], "coverage": [], "stats": {}, "graphs": {},
              "remediation_templates": {CHECK: archived}}
    reference = publish_report(artifacts, "alice", job["id"], report)
    store.finish(job["id"], analyzer["owner"], "completed", reference)
    response = client.get(f"/api/scans/{job['id']}/findings/f1")
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["remediation_details"]["steps"] == [NETWORK_ACTION]
    assert value["remediation_details"]["references"] == archived["references"]
    assert value["evidence"] == finding["evidence"] and value["status"] == "FAIL"
