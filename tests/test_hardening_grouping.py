import copy
import json

from bluepeass.hardening_report import group_hardening_targets, render_hardening_markdown, publish_hardening_report
from bluepeass.report import build_report


def row(resource, *, control="s3_bucket_public_access", status="FAIL", service="AWS/S3", reason="Public access enabled", region="eu-west-1"):
    return {"provider": "aws", "control_id": "aws_compliance.control." + control,
            "title": "Buckets should restrict public access", "description": "Restrict bucket access.",
            "severity": "high", "tags": {"service": service}, "resource": resource,
            "status": status, "reason": reason, "dimensions": {"region": region},
            "suites": ["aws-compliance"], "reference_url": "https://example.test/control"}


def target(account, rows, *, label=None, errors=None):
    return {"target_id": account, "target_type": "account", "label": label,
            "data": {"findings": {"permission_catalog": []}, "errors": [], "hardening": {
                "status": "partial" if errors else "completed", "findings": rows,
                "controls": [{**r, "suite": "aws-compliance", "rows": 1} for r in rows],
                "errors": errors or [], "coverage": {"complete": not errors, "zero_result_controls": []},
                "summary": {}, "versions": {"aws-compliance": "fixture"}}}}


def test_one_check_contains_assets_across_accounts_with_the_same_resource_id():
    targets = [target("111", [row("bucket"), row("other")]), target("222", [row("bucket", reason="Different evidence")])]
    untouched = copy.deepcopy(targets)
    report = build_report(provider="aws", targets=targets)
    assert targets == untouched
    assert report["schema_version"] == 2
    findings = report["hardening"]["services"][0]["findings"]
    assert len(findings) == 1
    assert len(findings[0]["assets"]) == 3
    assert {(a["target_id"], a["resource"]) for a in findings[0]["assets"]} == {("111", "bucket"), ("111", "other"), ("222", "bucket")}
    assert "findings" not in report["targets"][0]["data"]["hardening"]
    assert report["targets"][0]["data"]["hardening"]["finding_ids"] == [findings[0]["finding_id"]]
    assert report["hardening"]["summary"]["by_status"] == {"FAIL": 3}


def test_grouping_retains_different_status_region_and_audit_identity_observations():
    duplicate = row("bucket")
    report = group_hardening_targets([
        target("111", [duplicate, duplicate, row("bucket", status="PASS", region="us-east-1")], label="audit-role"),
        target("111", [duplicate], label="another-role")], "aws")
    assets = report["services"][0]["findings"][0]["assets"]
    assert len(assets) == 1
    assert len(assets[0]["observations"]) == 3
    assert assets[0]["affected"]
    assert report["summary"]["by_status"] == {"FAIL": 2, "PASS": 1}
    assert len({o["scan_id"] for o in assets[0]["observations"]}) == 2


def test_different_services_and_control_ids_never_merge_by_title():
    report = group_hardening_targets([target("111", [row("s3"), row("s3", control="different_check"), row("ec2", control="ec2_check", service="AWS/EC2")])], "aws")
    assert [s["service"] for s in report["services"]] == ["AWS/EC2", "AWS/S3"]
    assert [len(s["findings"]) for s in report["services"]] == [1, 2]


def test_markdown_emits_one_heading_and_all_affected_assets_across_accounts():
    report = group_hardening_targets([target("111", [row("a"), row("passed", status="PASS")]), target("222", [row("b")])], "aws")
    markdown = render_hardening_markdown(report)
    assert markdown.count("### AWS/S3") == 1
    assert markdown.count("#### Buckets should restrict public access") == 1
    assert "| 111 | a |" in markdown
    assert "| 222 | b |" in markdown
    assert "| PASS |" not in markdown
    assert "| PASS |" in render_hardening_markdown(report, show_passed=True)
    assert "**Affected assets:** 2" in markdown


def test_query_errors_without_assets_are_shown_under_the_correct_service():
    audit = target("111", [row("bucket", status="PASS")], errors=[{"control_id": "aws_compliance.control.s3_bucket_public_access", "error": "Access denied"}])
    audit["data"]["hardening"]["findings"] = []
    report = group_hardening_targets([audit], "aws")
    finding = report["services"][0]["findings"][0]
    assert finding["assets"] == []
    assert len(finding["error_ids"]) == 1
    markdown = render_hardening_markdown(report)
    assert "### AWS/S3" in markdown
    assert "| 111 | Access denied |" in markdown
    assert not report["summary"]["coverage_complete"]


def test_markdown_escapes_html_and_table_content_from_cloud_resources():
    resource = '<script>alert(1)</script>|bad\n# fake-heading'
    finding = row(resource, reason='[attack](javascript:alert(1))')
    finding["reference_url"] = "javascript:alert(1)"
    report = group_hardening_targets([target("111", [finding])], "aws")
    markdown = render_hardening_markdown(report)
    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown
    assert "\\|bad<br>\\# fake-heading" in markdown
    assert "[Control reference" not in markdown


def test_publish_markdown_and_json_share_the_same_grouped_model(tmp_path, capsys):
    from types import SimpleNamespace
    targets = [target("111", [row("a")]), target("222", [row("b")])]
    path = tmp_path / "report.txt"
    args = SimpleNamespace(hardening_show_passed=False, hardening_out_markdown=str(path))
    publish_hardening_report(args, targets, "aws")
    document = build_report(provider="aws", targets=targets)
    assert path.read_text() == render_hardening_markdown(document["hardening"])
    assert capsys.readouterr().out.strip() == path.read_text().strip()
    assert json.loads(json.dumps(document))["hardening"]["summary"]["affected_assets"] == 2
