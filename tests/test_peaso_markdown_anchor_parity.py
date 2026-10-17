"""Frozen synthetic Markdown bytes across guidance variants and report states."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from peaso.reports import render_markdown


EXPECTED = Path(__file__).parent / "fixtures" / "markdown_anchor_expected.json"


def _base_report():
    findings = []
    for index in range(3):
        resource_id = f"sg-{index + 1:08x}"
        findings.append({
            "id": f"synthetic-{index}", "provider": "aws", "check_id": "synthetic.check",
            "status": "FAIL", "title": "Configuration review", "category": "hardening",
            "severity": "medium", "resource_id": resource_id, "native_resource_id": resource_id,
            "resource_name": resource_id, "scope": "000000000000/us-east-1",
            "frameworks": ["Synthetic Framework", "Control-1"],
            "message": "Review this setting.", "description": "Declared configuration is evaluated.",
            "evaluated": ["data.mode"], "pass_when": "Mode is safe.",
            "fail_when": "Mode is unsafe.", "not_applicable_when": "No item is present.",
            "remediation": "Review the setting.",
            "evidence": {"resource": resource_id, "mode": "synthetic", "backticks": "```", "unicode": "é漢字"},
        })
    return {
        "provider": "aws", "snapshot_id": "synthetic-only", "created_at": "2026-10-13T00:00:00Z",
        "scopes": ["000000000000/us-east-1"], "stats": {"findings": 3},
        "coverage": [{"level": "check", "check_id": "synthetic.check", "scope": "000000000000/us-east-1", "status": "evaluated", "reason": "synthetic evidence"}],
        "findings": findings,
        "resources": [{"id": "synthetic-resource", "type": "synthetic.config", "scope": "000000000000/us-east-1", "data": {"mode": "test"}}],
        "graphs": {"network": {"nodes": [{"id": "synthetic-node"}], "edges": [{"id": "synthetic-edge"}]}},
        "framework_versions": [{"id": "synthetic-v1", "native_check_ids": ["synthetic.check"]}],
        "snapshot_metadata": {"source": "synthetic-only"},
        "finding_aggregates": [{"status": "NOT_APPLICABLE", "check_id": "synthetic.check", "title": "Configuration review", "count": 2, "scopes": {"synthetic": 2}, "sample_resource_ids": ["synthetic-a"]}],
        "remediation_templates": {"synthetic.check": {
            "summary": "Review the configuration.", "steps": ["Check owner approval.", "Apply reviewed settings."],
            "cli": [{"label": "Inspect", "code": "aws ec2 describe-security-groups --group-ids <RESOURCE_ID>"},
                    {"label": "Unbound placeholder", "code": "echo <UNKNOWN_ID>"}],
            "iac": {"label": "Reviewed", "language": "hcl", "code": "ingress = []"},
            "caveats": ["Keep authorized access."],
            "references": [{"title": "Synthetic reference", "url": "https://example.invalid/docs"}],
        }},
    }


def _cases():
    cases = [("complete", _base_report())]
    value = _base_report()
    value["coverage"][0].update(status="denied", reason="synthetic permission denied")
    value["findings"][0].update(status="DENIED", evidence={"reason": "synthetic denied"})
    cases.append(("denied", value))
    value = _base_report()
    value["coverage"][0].update(status="partial", reason="synthetic partial inventory")
    value["findings"][1].update(status="UNKNOWN", evidence={"reason": "synthetic missing field"})
    cases.append(("partial", value))
    cases.append(("malformed_nonobject", "synthetic-invalid-report"))
    value = _base_report()
    value["findings"] = None
    cases.append(("malformed_findings", value))
    value = _base_report()
    value["findings"][1]["description"] = "An archived narrower description."
    cases.append(("same_check_description_variant", value))
    value = _base_report()
    value["findings"][1]["pass_when"] = "An archived narrower pass condition."
    cases.append(("same_check_criteria_variant", value))
    value = _base_report()
    variant = deepcopy(value["remediation_templates"]["synthetic.check"])
    variant["summary"] = "A distinct explicit remediation."
    value["findings"][1]["remediation_details"] = variant
    cases.append(("same_check_remediation_variant", value))
    value = _base_report()
    value["remediation_templates"] = {}
    cases.append(("absent_template", value))
    value = _base_report()
    value["findings"][0]["remediation_details"] = "invalid-details-type"
    cases.append(("invalid_explicit_details_template_fallback", value))
    value = _base_report()
    value["findings"][0]["remediation_details"] = {}
    cases.append(("empty_explicit_details_override", value))
    value = _base_report()
    value["remediation_templates"] = {}
    for finding in value["findings"]:
        finding.pop("description")
    cases.append(("legacy_remediation_only", value))
    value = _base_report()
    value["findings"][1].update(resource_id="synthetic unsafe id", native_resource_id="synthetic unsafe id", resource_name="synthetic unsafe id")
    cases.append(("valid_invalid_command_identities", value))
    value = _base_report()
    value["findings"][0]["description"] = "é漢字 | `code`  \nnext line "
    value["graphs"]["network"]["trailing"] = "backticks ```` and spaces  "
    cases.append(("backticks_unicode_whitespace", value))
    value = _base_report()
    value["findings"][0].pop("frameworks")
    value["findings"][1].pop("description")
    value["check_frameworks"] = {"synthetic.check": ["Hydrated Framework"]}
    value["check_meta"] = {"synthetic.check": {"description": "Hydrated description."}}
    cases.append(("factored_framework_and_metadata", value))
    cases.append(("catalog", {"checks": [{"id": "synthetic.check"}]}))
    cases.append(("diff", {"added": [{"id": "synthetic-a"}], "removed": [], "changed": [], "coverage_before": [], "coverage_after": []}))
    return cases


@pytest.mark.parametrize(("name", "report"), _cases(), ids=lambda value: value if isinstance(value, str) else None)
def test_frozen_markdown_output(name, report):
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))[name]
    if "error" in expected:
        exception_type = {"ValueError": ValueError, "TypeError": TypeError}[expected["error"]]
        with pytest.raises(exception_type) as raised:
            render_markdown(report)
        assert str(raised.value) == expected["message"]
    else:
        actual = render_markdown(report).encode("utf-8")
        assert actual == expected["markdown"].encode("utf-8")
