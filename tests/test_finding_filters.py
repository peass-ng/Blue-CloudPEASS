import copy

from bluepeass.finding_filters import filter_aws_raw_report, filter_hardening_audit, filter_raw_scope
from bluepeass.hardening_report import group_hardening_targets, render_hardening_markdown
from bluepeass.normalize import normalize_aws_account, normalize_gcp_scope, normalize_k8s_cluster
from bluepeass.report import build_report


SERVICE_ROLE = "arn:aws:iam::111111111111:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport"
SSO_ROLE = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_Admin_abcdef"
CUSTOM_ROLE = "arn:aws:iam::111111111111:role/customer/AWSServiceRoleForFake"
AWS_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
CUSTOM_POLICY = "arn:aws:iam::111111111111:policy/AdministratorAccess"
GRANTS = {"flagged_perms": {"critical": ["iam:CreateAccessKey"]}}


def test_aws_unused_filters_keep_customer_roles_actual_grants_and_external_trusts():
    raw = {"unused_roles": {role: {"n_days": 100, "permissions": GRANTS} for role in [SERVICE_ROLE, SSO_ROLE, CUSTOM_ROLE]},
           "unused_permissions": {SERVICE_ROLE: {"last_perms": {}, "permissions": GRANTS}, CUSTOM_ROLE: {"last_perms": {}, "permissions": GRANTS}},
           "unused_custom_policies": {AWS_POLICY: {}, CUSTOM_POLICY: {}},
           "external_trust_roles": {SERVICE_ROLE: {"reason": "external trust"}}}
    original = copy.deepcopy(raw)
    filtered = filter_aws_raw_report(raw)
    assert raw == original
    assert list(filtered["unused_roles"]) == [CUSTOM_ROLE]
    assert list(filtered["unused_permissions"]) == [CUSTOM_ROLE]
    assert list(filtered["unused_custom_policies"]) == [CUSTOM_POLICY]
    assert filtered["role_permissions"][SERVICE_ROLE] == GRANTS
    assert filtered["external_trust_roles"] == raw["external_trust_roles"]
    assert filtered["finding_filters"]["suppressed"] == 4
    assert filter_aws_raw_report(filtered)["finding_filters"] == filtered["finding_filters"]


def test_flagged_grants_without_access_analyzer_are_not_unused_finding_records():
    raw = {"unused_permissions": {SERVICE_ROLE: {"type": "role", "permissions": GRANTS}}}
    assert filter_aws_raw_report(raw)["unused_permissions"] == raw["unused_permissions"]


def test_normalized_aws_report_drops_only_managed_role_inactivity():
    data = normalize_aws_account({"account_id": "111", "unused_roles": {SERVICE_ROLE: {"n_days": 100, "permissions": GRANTS}, CUSTOM_ROLE: {"n_days": 100, "permissions": GRANTS}}})
    findings = data["findings"]
    principals = {item["id"]: item["identifier"] for item in findings["principal_catalog"]}
    assert [principals[item["subject_ref"]] for item in findings["principals_inactive"]] == [CUSTOM_ROLE]
    assert SERVICE_ROLE in {principals[item["subject_ref"]] for item in findings["principals_flagged"]}
    report = build_report(provider="aws", targets=[{"target_id": "111", "data": data}])
    assert report["finding_filters"]["suppressed"] == 1


def test_gcp_and_kubernetes_builtin_definitions_are_not_custom_cleanup_findings():
    gcp = {"scope": "projects/fixture", "scope_type": "project", "unused_custom_roles": [{"name": "roles/editor"}, {"name": "projects/fixture/roles/Editor"}]}
    assert [item["name"] for item in filter_raw_scope(gcp, "gcp")["unused_custom_roles"]] == ["projects/fixture/roles/Editor"]
    assert len(normalize_gcp_scope(gcp)["findings"]["unused_custom_definitions"]) == 1
    k8s = {"context": "fixture", "findings": {"unused_custom_definitions": [{"kind": "clusterroles", "scope": "cluster", "name": "system:controller:example"}, {"kind": "clusterroles", "scope": "cluster", "name": "customer-role"}]}}
    assert [item["name"] for item in filter_raw_scope(k8s, "k8s")["findings"]["unused_custom_definitions"]] == ["customer-role"]
    assert len(normalize_k8s_cluster(k8s)["findings"]["unused_custom_definitions"]) == 1


def test_hardening_edge_case_filters_keep_custom_roles_and_execution_errors():
    def finding(resource, control="iam_role_unused_60", status="FAIL"):
        return {"provider": "aws", "control_id": "aws_compliance.control." + control, "title": "Role should be in use", "resource": resource, "status": status, "tags": {"service": "AWS/IAM"}}
    rows = [finding(SERVICE_ROLE), finding(SSO_ROLE), finding(CUSTOM_ROLE), finding(SERVICE_ROLE, "iam_role_trust_policy"), finding(SERVICE_ROLE, status="ERROR")]
    audit = {"status": "partial", "findings": rows, "controls": [{"control_id": "aws_compliance.control.iam_role_unused_60", "rows": 3}], "coverage": {"complete": False}, "errors": [{"control_id": "aws_compliance.control.iam_role_unused_60", "error": "Denied read"}]}
    filtered = filter_hardening_audit(audit, "aws")
    assert len(filtered["findings"]) == 3
    assert filtered["summary"]["by_status"] == {"FAIL": 2, "ERROR": 1}
    assert filtered["errors"] == audit["errors"]
    assert filtered["controls"] == audit["controls"]
    assert filtered["finding_filters"]["suppressed"] == 2
    grouped = group_hardening_targets([{"target_id": "111", "data": {"hardening": audit}}], "aws")
    assert grouped["summary"]["resource_evaluations"] == 3
    assert grouped["summary"]["execution_errors"] == 1
    assert grouped["finding_filters"]["suppressed"] == 2
    markdown = render_hardening_markdown(grouped)
    assert "Known non-actionable finding records suppressed" in markdown
    assert "Denied read" in markdown


def test_control_only_blacklist_rule_still_cannot_hide_query_errors():
    rule = {"id": "custom-review", "provider": "azure", "sections": ["hardening"], "control_patterns": ["control.example"], "reason": "Known catalog issue"}
    audit = {"findings": [{"control_id": "control.example", "status": "FAIL"}, {"control_id": "control.example", "status": "ERROR"}], "errors": [{"error": "HTTP 403"}]}
    result = filter_hardening_audit(audit, "azure", rules=[rule])
    assert [finding["status"] for finding in result["findings"]] == ["ERROR"]
    assert result["errors"] == audit["errors"]
    assert result["finding_filters"]["by_rule"]["custom-review"]["reason"] == rule["reason"]


def test_azure_builtin_role_edge_case_needs_positive_type_evidence():
    raw = {"unused_custom_roles": [{"role_definition_id": "builtin", "role_type": "BuiltInRole"}, {"role_definition_id": "custom", "role_type": "CustomRole"}, {"role_definition_id": "unknown"}]}
    result = filter_raw_scope(raw, "azure")
    assert [role["role_definition_id"] for role in result["unused_custom_roles"]] == ["custom", "unknown"]
    assert result["finding_filters"]["suppressed"] == 1
