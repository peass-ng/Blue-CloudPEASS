"""Actual hosted intake accepts safe scoped operator reviews, never endpoints."""
import copy
from types import SimpleNamespace

from fastapi import HTTPException
import pytest

from peaso.server.validation import validate_connector

SETTINGS = SimpleNamespace(auth_mode="cognito")
AUTH = {"aws": {"method": "access_keys", "aws_access_key_id": "fixture-id", "aws_secret_access_key": "fixture-secret"},
        "azure": {"method": "token", "arm_token": "fixture-arm", "logs_token": "fixture-logs"},
        "gcp": {"method": "token", "token": "fixture-gcp"}}
ORG = {"status": "collected", "scope": "123456789012/global", "audited_account_ids": ["123456789012"],
       "allowed_instance_types": ["t3.small"], "approved_break_glass_principals": ["arn:aws:iam::123456789012:role/emergency"]}
AZURE = {"azure_attack_detection": {"status": "collected", "subscription_scope": "/subscriptions/customer",
    "checks": {"azure.other.attack_t1049": {"requirements": []}}}}
GCP = {"status": "collected", "scope": "projects/customer-project", "sql_scope": ["database"], "approved_offsite_policy": True}


@pytest.mark.parametrize("provider,options", [
    ("aws", {"compliance_policy": {"aws_organizations": ORG}}),
    ("aws", {"compliance_policy": {"aws_organizations": {"by_scope": {ORG["scope"]: ORG}}}}),
    ("aws", {"compliance_policy": {"aws_organizations": ORG,
        "aws_backup_plan": {"applies_to": ["123456789012/us-east-1"], "required_frequency_hours": 24}}}),
    ("azure", {"compliance_policy": AZURE}),
    ("azure", {"compliance_policy": {"sw21": {"status": "collected", "scope": "/tenants/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "entraDiagnostics": {"approvedSinkIds": []}}}}),
    ("azure", {"compliance_policy": {"sw33": {"status": "collected", "scope": "/subscriptions/customer", "vpnTunnels": {"gatewayId": "/subscriptions/customer/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkGateways/approved", "expectedTunnels": []}}}}),
    ("azure", {"compliance_policy": {"status": "collected", "scope": "/subscriptions/customer", "checks": {"azure.gap.compute_vm_vulnerability_findings_resolved_for_sql_server": {"assessmentKeys": ["approved-assessment"], "maxReportAgeSeconds": 3600, "requiredFindingIds": [], "findingSetComplete": True}}}}),
    ("azure", {"compliance_policy": {"sw16": {"azure.cis.intune_logs_captured_sent_log_analytics": {"status": "collected", "scope": "/tenants/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "resources": []}}}}),
    ("azure", {"compliance_policy": {"sw19": {"status": "collected", "scope": "/subscriptions/customer", "azure.cis.multifactor_auth_status_privileged_users": {"reviewed": True}}}}),
    ("azure", {"compliance_policy": {"sw26": {"status": "collected", "scope": "/subscriptions/customer", "azure.gap.appservice_api_app_latest_tls_version": {"reviewed": True}}}}),
    ("aws", {"compliance_policy": {"sw38_policy": {"status": "collected", "scope": "123456789012/us-east-1", "approved_tls_policies": ["TLSv1.2_2021"]}}}),
    ("azure", {"compliance_policy": {"sw12": {"status": "collected", "scope": "/subscriptions/customer",
        "checks": {"azure.other.attack_t1546": {"requirements": []}}}}}),
    ("gcp", {"compliance_policy": GCP}),
    ("gcp", {"sw51_policy": {"status": "collected", "scope": "projects/customer-project",
        "approved_asset_types": ["compute.googleapis.com/Instance"]}}),
    ("gcp", {"sw55_policy": {"status": "collected", "scope": "organizations/1234",
        "approved_on_call_topics": ["projects/customer-project/topics/responders"]}}),
])
def test_scoped_native_operator_inputs_reach_hosted_connector(provider, options):
    auth, original = copy.deepcopy(AUTH[provider]), copy.deepcopy(options)
    validate_connector(provider, auth, options, SETTINGS)
    assert options == original and auth == AUTH[provider]


@pytest.mark.parametrize("provider,options", [
    ("aws", {"compliance_policy": {"aws_organizations": {**ORG, "endpoint": "https://evil.test"}}}),
    ("aws", {"compliance_policy": {"aws_organizations": {**ORG, "scope": "*/global"}}}),
    ("aws", {"compliance_policy": {"sw38_policy": {"status": "collected", "scope": "123456789012/us-east-1", "approved_tls_policies": "TLSv1.2_2021"}}}),
    ("gcp", {"sw51_policy": {"status": "collected", "scope": "organizations/1234", "approved_asset_types": []}}),
    ("aws", {"compliance_policy": {"aws_organizations": {**ORG, "audited_account_ids": ["123"]}}}),
    ("aws", {"compliance_policy": {"aws_organizations": {"by_scope": {"999999999999/global": ORG}}}}),
    ("azure", {"compliance_policy": {**AZURE, "native_facts": {"pass": True}}}),
    ("azure", {"compliance_policy": {"status": "collected", "scope": "/subscriptions/customer", "checks": {"aws.unrelated": {"approved": True}}}}),
    ("azure", {"compliance_policy": {"sw16": {"endpoint": {"status": "collected", "scope": "/subscriptions/customer"}}}}),
    ("azure", {"compliance_policy": {"sw19": {"status": "collected", "scope": "/subscriptions/customer", "native_facts": {"pass": True}}}}),
    ("azure", {"compliance_policy": {"sw33": {"status": "collected", "scope": "/subscriptions/customer", "request_url": "https://evil.test"}}}),
    ("azure", {"compliance_policy": {"azure_attack_detection": {**AZURE["azure_attack_detection"], "endpoint": "https://evil.test"}}}),
    ("gcp", {"compliance_policy": {**GCP, "endpoint": "https://evil.test"}}),
    ("gcp", {"compliance_policy": {**GCP, "approved_offsite_policy": "true"}}),
    ("aws", {"sw51_policy": {"status": "collected", "scope": "projects/customer-project"}}),
    ("azure", {"sw55_policy": {"status": "collected", "scope": "projects/customer-project"}}),
    ("gcp", {"sw51_policy": {"status": "collected", "scope": "projects/customer-project", "endpoint": "https://evil.test"}}),
    ("gcp", {"sw55_policy": {"status": "collected", "scope": "https://evil.test"}}),
    ("gcp", {"sw55_policy": {"status": "collected", "scope": "projects/customer-project", "consent_scopes": [0] * 257}}),
    ("azure", {"compliance_policy": {"sw12": {"status": "collected", "scope": "/subscriptions/customer", "checks": {
        "azure.other.attack_t1546": {"query": "x" * 8193}}}}}),
])
def test_native_policy_intake_rejects_unscoped_cross_provider_and_unbounded_inputs(provider, options):
    with pytest.raises(HTTPException) as error:
        validate_connector(provider, copy.deepcopy(AUTH[provider]), options, SETTINGS)
    assert error.value.status_code == 422
