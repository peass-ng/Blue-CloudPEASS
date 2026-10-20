"""The Markdown export shares check guidance without losing per-resource facts."""
from copy import deepcopy
import json

from peaso.reports import render_markdown


def _report():
    detail = {
        "summary": "Review each security group's declared ingress.",
        "steps": [f"Review step {step}." for step in range(1, 8)],
        "cli": [{"label": "Inspect this group", "code": "aws ec2 describe-security-groups --group-ids <RESOURCE_ID>"}],
        "iac": {"label": "Reviewed declaration", "language": "hcl", "code": "ingress = []"},
        "caveats": ["Confirm legitimate callers first."],
        "references": [{"title": "AWS security group rules", "url": "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"}],
    }
    findings = []
    resources = []
    for index in range(40):
        resource_id = f"sg-{index:08x}"
        findings.append({
            "id": f"finding-{index}", "provider": "aws", "check_id": "aws.example.ingress",
            "status": "FAIL", "title": "Review ingress", "category": "exposure", "severity": "high",
            "resource_id": resource_id, "native_resource_id": resource_id,
            "resource_name": f"group-{index}", "scope": "222233334444/us-east-1",
            "frameworks": ["CIS", f"Framework-{index}"], "description": "Reads declared ingress rules; reachability requires separate evidence.",
            "evaluated": ["IpPermissions[].IpRanges[].CidrIp"],
            "pass_when": "No matching ingress rule is declared.",
            "fail_when": "A matching ingress rule is declared.",
            "not_applicable_when": "No group was collected.",
            "remediation": "Review this ingress rule.", "message": f"Rule {index} needs review.",
            "evidence": {"group_id": resource_id, "rule_index": index},
        })
        resources.append({"id": resource_id, "type": "aws.ec2.security_group", "scope": "222233334444/us-east-1", "name": f"group-{index}"})
    return {
        "provider": "aws", "snapshot_id": "sha256:synthetic", "created_at": "2026-10-12T22:00:00Z",
        "scopes": ["222233334444/us-east-1"], "stats": {"resources": 40, "findings": 40},
        "coverage": [{"level": "check", "check_id": "aws.example.ingress", "scope": "222233334444/us-east-1", "status": "evaluated", "reason": "native evidence"}],
        "findings": findings, "resources": resources,
        "graphs": {"network": {"nodes": [{"id": "node-1"}], "edges": [{"id": "edge-1"}]}},
        "remediation_templates": {"aws.example.ingress": detail},
    }


def test_shared_guidance_preserves_each_finding_resource_evidence_and_bound_command():
    report = _report()
    before = json.dumps(report, sort_keys=True)
    markdown = render_markdown(report)
    assert json.dumps(report, sort_keys=True) == before
    assert markdown.count("#### What this check evaluates") == 1
    assert markdown.count("Review each security group's declared ingress\\.") == 1
    assert markdown.count("7. Review step 7\\.") == 1
    assert markdown.count("Confirm legitimate callers first\\.") == 1
    assert markdown.count('id="check-guidance-1"') == 1
    assert markdown.count("[reviewed meaning and remediation](#check-guidance-1)") == 40
    assert markdown.count("### FAIL: Review ingress") == 40
    assert markdown.count("- Frameworks: CIS, Framework-") == 40
    assert markdown.count("- Scope: 222233334444/us-east-1") == 40
    assert markdown.count("- Severity: high") == 40
    assert markdown.count("- Message: Rule ") == 40
    assert markdown.count("--group-ids sg-") == 40
    for index in range(40):
        resource_id = f"sg-{index:08x}"
        assert f"- Finding ID: finding-{index}\n" in markdown
        assert f"- Frameworks: CIS, Framework-{index}\n" in markdown
        assert f"- Message: Rule {index} needs review.\n" in markdown
        assert markdown.count(f"--group-ids {resource_id}") == 1
        assert f'"group_id": "{resource_id}"' in markdown
        assert f"### aws.ec2.security_group: {resource_id}" in markdown
    assert '"id": "edge-1"' in markdown
    assert '"status": "evaluated"' in markdown
    assert "## Aggregated not-applicable and empty results" not in markdown
    assert len(markdown.encode()) < 120_000


def test_distinct_guidance_variant_and_legacy_remediation_are_not_merged():
    report = _report()
    report["findings"] = report["findings"][:3]
    report["resources"] = []
    report["findings"][1]["description"] = "A narrower archived definition."
    report["findings"][2]["check_id"] = "legacy"
    report["findings"][2].pop("description")
    report["findings"][2].pop("evaluated")
    report["remediation_templates"] = {"aws.example.ingress": report["remediation_templates"]["aws.example.ingress"]}
    markdown = render_markdown(report)
    assert markdown.count('id="check-guidance-') == 2
    assert markdown.count("A narrower archived definition\\.") == 1
    assert markdown.count("Remediation: Review this ingress rule.") == 1
    assert markdown.count("--group-ids sg-") == 2


def test_description_criteria_and_remediation_variants_keep_separate_links():
    report = _report()
    report["findings"] = report["findings"][:3]
    report["resources"] = []
    report["findings"][1]["pass_when"] = "The archived narrower pass condition."
    variant = deepcopy(report["remediation_templates"]["aws.example.ingress"])
    variant["summary"] = "Review this variant separately."
    report["findings"][2]["remediation_details"] = variant
    markdown = render_markdown(report)
    assert markdown.count('id="check-guidance-') == 3
    for index in range(1, 4):
        assert markdown.count(f"[reviewed meaning and remediation](#check-guidance-{index})") == 1
    assert markdown.count("The archived narrower pass condition\\.") == 1
    assert markdown.count("Review this variant separately\\.") == 1
    assert markdown.count("--group-ids sg-") == 3
