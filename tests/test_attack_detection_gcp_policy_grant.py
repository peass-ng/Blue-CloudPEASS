"""Conservative GCP service-account policy observation from official AuditLog shape."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_gcp_events
from peaso.attack_detection.gcp import normalize_gcp_audit
from peaso.attack_detection.gcp import normalize_gcp_token_creator_binding_observation


PROJECT = "customer-project"
ACTOR = "operator@example.com"
SERVICE_ACCOUNT = f"workload@{PROJECT}.iam.gserviceaccount.com"
TARGET = f"projects/-/serviceAccounts/{SERVICE_ACCOUNT}"


def event(*, actor=ACTOR, member=None):
    return {
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "grant-event-id", "timestamp": "2026-10-18T12:00:00Z",
        "resource": {"type": "service_account", "labels": {"project_id": PROJECT}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "iam.googleapis.com",
            "methodName": "google.iam.admin.v1.SetIAMPolicy",
            "authenticationInfo": {"principalEmail": actor},
            "request": {"@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                        "resource": TARGET},
            "resourceName": "projects/-/serviceAccounts/123456789012345678901",
            "serviceData": {"policyDelta": {"bindingDeltas": [
                {"action": "ADD", "role": "roles/iam.serviceAccountTokenCreator",
                 "member": member or (("serviceAccount:" if actor.endswith(".gserviceaccount.com") else "user:") + actor)}
            ]}},
            "response": {"@type": "type.googleapis.com/google.iam.v1.Policy",
                         "bindings": [{"role": "roles/iam.serviceAccountTokenCreator",
                                       "members": [member or f"user:{actor}"]}]},
        },
    }


def test_complete_admin_activity_response_is_only_binding_observation():
    result = normalize_gcp_token_creator_binding_observation(event())
    assert result == {
        "cloud.provider": "gcp", "event.name": "service_account_token_creator_self_binding_observed",
        "event.source": "iam.googleapis.com", "event.outcome": "success",
        "event.id": "grant-event-id", "event.time": "2026-10-18T12:00:00Z",
        "account.id": PROJECT, "actor.id": ACTOR, "target.id": TARGET,
        "request.actor_is_member": True, "request.role": "roles/iam.serviceAccountTokenCreator",
        "request.binding_observed": True, "target.service_account": SERVICE_ACCOUNT,
        "request.binding_added": True,
    }
    assert "new_privilege" not in result and "compromise" not in result


def test_service_account_actor_uses_service_account_member_type():
    actor = "runner@other-project.iam.gserviceaccount.com"
    row = event(actor=actor, member=f"serviceAccount:{actor}")
    assert normalize_gcp_token_creator_binding_observation(row)["actor.id"] == actor


@pytest.mark.parametrize("request_project,resource_project", [
    (PROJECT, PROJECT), (PROJECT, "-"), ("-", PROJECT),
])
def test_explicit_project_resource_preserves_requested_target_and_returned_binding(
    request_project, resource_project,
):
    row = event()
    requested = f"projects/{request_project}/serviceAccounts/{SERVICE_ACCOUNT}"
    row["protoPayload"]["request"]["resource"] = requested
    row["protoPayload"]["resourceName"] = (
        f"projects/{resource_project}/serviceAccounts/{SERVICE_ACCOUNT}"
    )
    result = normalize_gcp_token_creator_binding_observation(row)
    assert result["target.id"] == requested
    assert result["target.service_account"] == SERVICE_ACCOUNT
    assert result["request.binding_observed"] is True
    assert result["request.binding_added"] is True
    assert "new_privilege" not in result and "compromise" not in result


@pytest.mark.parametrize("change", [
    "request_project", "resource_project", "email_project", "returned_member", "conditional_binding",
])
def test_explicit_project_resource_rejects_mismatched_evidence(change):
    row = event()
    payload = row["protoPayload"]
    payload["request"]["resource"] = f"projects/{PROJECT}/serviceAccounts/{SERVICE_ACCOUNT}"
    payload["resourceName"] = f"projects/{PROJECT}/serviceAccounts/{SERVICE_ACCOUNT}"
    if change == "request_project":
        payload["request"]["resource"] = payload["request"]["resource"].replace(
            f"projects/{PROJECT}/", "projects/another-project/"
        )
    elif change == "resource_project":
        payload["resourceName"] = payload["resourceName"].replace(
            f"projects/{PROJECT}/", "projects/another-project/"
        )
    elif change == "email_project":
        payload["request"]["resource"] = (
            f"projects/{PROJECT}/serviceAccounts/workload@another-project.iam.gserviceaccount.com"
        )
    elif change == "returned_member":
        payload["response"]["bindings"][0]["members"] = ["user:other@example.com"]
    elif change == "conditional_binding":
        payload["response"]["bindings"][0]["condition"] = {"expression": "true"}
    assert normalize_gcp_token_creator_binding_observation(row) is None


def test_public_rule_shape_matches_only_completed_binding_observation():
    rule = Rule(
        id="synthetic-token-creator", title="Observed Token Creator binding",
        level="medium", description="Resulting service account policy binding",
        technique_id="gcp-iam-serviceaccounts-setiampolicy", product="gcp",
        selection={"event.source": "iam.googleapis.com",
                   "event.name": "service_account_token_creator_self_binding_observed",
                   "event.outcome": "success", "request.actor_is_member": True,
                   "request.binding_observed": True,
                   "request.binding_added": True,
                   "request.role": "roles/iam.serviceAccountTokenCreator"},
    )
    assert normalize_gcp_audit(event()) == normalize_gcp_token_creator_binding_observation(event())
    matches = detect_gcp_events([event()], [rule])
    assert len(matches) == 1
    assert matches[0].actor_id == ACTOR
    assert matches[0].target_id == TARGET
    denied = event()
    denied["protoPayload"]["status"] = {"code": 7}
    assert detect_gcp_events([denied], [rule]) == []


@pytest.mark.parametrize("change", [
    "data_access", "wrong_method", "wrong_service", "project_policy", "other_project",
    "foreign_resource_label", "missing_request", "redacted_request", "missing_response",
    "redacted_response", "failed", "boolean_status", "different_member", "wrong_role",
    "conditional_binding", "wrong_resource_name", "redacted_actor", "missing_event_id",
    "missing_delta", "removed_delta", "unrelated_delta", "conditional_delta",
])
def test_incomplete_or_ambiguous_events_fail_closed(change):
    row = deepcopy(event())
    payload = row["protoPayload"]
    if change == "data_access":
        row["logName"] = row["logName"].replace("%2Factivity", "%2Fdata_access")
    elif change == "wrong_method":
        payload["methodName"] = "SetIamPolicy"
    elif change == "wrong_service":
        payload["serviceName"] = "cloudresourcemanager.googleapis.com"
    elif change == "project_policy":
        row["resource"]["type"] = "project"
    elif change == "other_project":
        payload["request"]["resource"] = TARGET.replace(PROJECT, "another-project")
    elif change == "foreign_resource_label":
        row["resource"]["labels"]["project_id"] = "another-project"
    elif change == "missing_request":
        payload.pop("request")
    elif change == "redacted_request":
        payload["request"]["resource"] = "REDACTED"
    elif change == "missing_response":
        payload.pop("response")
    elif change == "redacted_response":
        payload["response"]["bindings"] = "REDACTED"
    elif change == "failed":
        payload["status"] = {"code": 7, "message": "PERMISSION_DENIED"}
    elif change == "boolean_status":
        payload["status"] = {"code": False}
    elif change == "different_member":
        payload["response"]["bindings"][0]["members"] = ["user:other@example.com"]
    elif change == "wrong_role":
        payload["response"]["bindings"][0]["role"] = "roles/iam.serviceAccountUser"
    elif change == "conditional_binding":
        payload["response"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2027-01-01T00:00:00Z')"}
    elif change == "wrong_resource_name":
        payload["resourceName"] = "projects/-/serviceAccounts/other@example.com"
    elif change == "redacted_actor":
        payload["authenticationInfo"]["principalEmail"] = "REDACTED"
    elif change == "missing_event_id":
        row.pop("insertId")
    elif change == "missing_delta":
        payload.pop("serviceData")
    elif change == "removed_delta":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["action"] = "REMOVE"
    elif change == "unrelated_delta":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["member"] = "user:other@example.com"
    elif change == "conditional_delta":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["condition"] = {"expression": "true"}
    assert normalize_gcp_token_creator_binding_observation(row) is None


def test_preexisting_binding_with_unrelated_policy_edit_does_not_alert():
    row = event()
    row["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"] = [
        {"action": "ADD", "role": "roles/iam.serviceAccountUser", "member": "user:other@example.com"}
    ]
    assert normalize_gcp_token_creator_binding_observation(row) is None
