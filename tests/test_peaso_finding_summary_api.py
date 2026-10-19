"""Archived resource detail gets a concise observation without rewriting evidence."""
from copy import deepcopy
import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.finding_observation import evidence_summary
from peaso.checks.k8s_finding_clarity_reviewed import ROWS
from peaso.storage.reports import publish_report
from tests.test_peaso_findings_sorting import api


@pytest.mark.parametrize("cid", [next(iter(ROWS)), "aws.kms.rotation", "gcp.ports.compute_instance_ip_forwarding_disabled",
                               "aws.claude_a.iam.root_console_has_mfa", "aws.a.iam.root_summary_no_keys"])
def test_archived_component_detail_preserves_raw_evidence(api, cid):
    client, store, artifacts = api
    check = next(c for c in CHECKS if c.id == cid)
    if cid == "aws.claude_a.iam.root_console_has_mfa":
        status, evidence = "PASS", {"password_present": 0, "mfa_enabled": 0}
    elif cid == "aws.a.iam.root_summary_no_keys":
        status, evidence = "PASS", {"account_access_keys_present": 0}
    else:
        fixture = CASES[cid]
        status, evidence = check.evaluate(fixture["fail"], fixture.get("fail_index", {}))
    finding = {"id": "f1", "check_id": cid, "provider": check.provider, "scope": "cluster/test",
               "category": "hardening", "service": check.kind, "resource_id": "pod/test",
               "title": check.title, "severity": check.severity, "frameworks": [],
               "status": status, "evidence": evidence, "remediation": check.remediation}
    from peaso.checks.catalog import _base_description_for
    archived_description = _base_description_for(cid)
    finding.update({key: archived_description[key] for key in ("description", "evaluated", "pass_when", "fail_when", "not_applicable_when") if key in archived_description})
    expected = evidence_summary(finding)
    assert expected
    original = deepcopy(finding)
    connector = store.add_connector("alice", {"provider": check.provider}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    collector = store.claim("collector")
    store.finish(job["id"], collector["owner"], "collected", artifacts.put("alice", job["id"], "snapshot", {}))
    analyzer = store.claim("analyzer")
    report = {"schema_version": "1.0", "provider": check.provider, "snapshot_id": "fixture", "scopes": [],
              "resources": [], "findings": [finding], "coverage": [], "stats": {}, "graphs": {}}
    reference = publish_report(artifacts, "alice", job["id"], report)
    store.finish(job["id"], analyzer["owner"], "completed", reference)
    response = client.get(f"/api/scans/{job['id']}/findings/f1")
    assert response.status_code == 200, response.text
    detail = response.json()
    assert detail["evidence_summary"] == expected
    assert detail["evidence_summary_format"] == "natural-language-v2"
    assert detail["evidence"] == original["evidence"]
    assert detail["status"] == status
    assert finding == original
