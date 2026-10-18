"""Project IAM ADD delta corroboration based on Google's AuditLog schema."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_gcp_events
from peaso.attack_detection.gcp_next import normalize_gcp_project_self_iam_bindings


PROJECT = "customer-project"
ACTOR = "operator@example.com"


def _event() -> dict:
    return {
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "policy-event-1",
        "timestamp": "2026-10-18T12:00:00Z",
        "resource": {"type": "project", "labels": {"project_id": PROJECT}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "cloudresourcemanager.googleapis.com",
            "methodName": "SetIamPolicy",
            "resourceName": f"projects/{PROJECT}",
            "authenticationInfo": {"principalEmail": ACTOR},
            "request": {
                "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                "resource": PROJECT,
            },
            "response": {
                "@type": "type.googleapis.com/google.iam.v1.Policy",
                "bindings": [
                    {"role": "roles/owner", "members": [f"user:{ACTOR}"]},
                    {"role": "roles/viewer", "members": ["user:other@example.com"]},
                ],
            },
            "serviceData": {"policyDelta": {"bindingDeltas": [
                {"action": "ADD", "role": "roles/owner", "member": f"user:{ACTOR}"},
            ]}},
        },
    }


def test_successful_project_owner_self_binding_addition():
    assert normalize_gcp_project_self_iam_bindings(_event()) == [{
        "cloud.provider": "gcp",
        "event.name": "project_iam_self_binding_added",
        "event.source": "cloudresourcemanager.googleapis.com",
        "event.outcome": "success",
        "event.id": "policy-event-1",
        "event.time": "2026-10-18T12:00:00Z",
        "account.id": PROJECT,
        "actor.id": ACTOR,
        "target.id": f"projects/{PROJECT}",
        "request.actor_is_member": True,
        "request.binding_added": True,
        "request.role": "roles/owner",
    }]


def test_sigma_selection_requires_a_new_self_owner_binding():
    rule = Rule(
        id="test-project-owner-add", title="Owner self grant", level="high",
        description="Observed direct binding", technique_id="gcp-owner-self", product="gcp",
        selection={"event.source": "cloudresourcemanager.googleapis.com",
                   "event.name": "project_iam_self_binding_added", "event.outcome": "success",
                   "request.actor_is_member": True, "request.binding_added": True,
                   "request.role": "roles/owner"},
    )
    assert len(detect_gcp_events([_event()], [rule])) == 1
    existing_owner_edit = _event()
    existing_owner_edit["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"][0]["member"] = "user:other@example.com"
    assert detect_gcp_events([existing_owner_edit], [rule]) == []


def test_service_account_actor_and_sorted_distinct_roles():
    event = _event()
    actor = "builder@other-project.iam.gserviceaccount.com"
    event["protoPayload"]["authenticationInfo"]["principalEmail"] = actor
    event["protoPayload"]["response"]["bindings"] = [
        {"role": "roles/viewer", "members": [f"serviceAccount:{actor}"]},
        {"role": "roles/owner", "members": [f"serviceAccount:{actor}"]},
        {"role": "roles/owner", "members": [f"serviceAccount:{actor}"]},
    ]
    event["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"] = [
        {"action": "ADD", "role": "roles/viewer", "member": f"serviceAccount:{actor}"},
        {"action": "ADD", "role": "roles/owner", "member": f"serviceAccount:{actor}"},
    ]
    rows = normalize_gcp_project_self_iam_bindings(event)
    assert [row["request.role"] for row in rows] == ["roles/owner", "roles/viewer"]
    assert all(row["actor.id"] == actor for row in rows)


@pytest.mark.parametrize("change", [
    "data_access", "different_project_log", "wrong_resource_type", "wrong_resource_label",
    "wrong_service", "wrong_method", "wrong_resource_name", "failed", "ambiguous_status",
    "incomplete_operation", "redacted_actor", "different_member", "conditional_binding",
    "missing_request", "redacted_request", "wrong_requested_project", "missing_response",
    "redacted_response", "missing_bindings", "missing_event_id", "wrong_policy_type",
    "missing_delta", "removed_delta", "unspecified_delta", "different_delta_member",
    "different_delta_role", "conditional_delta",
])
def test_fails_closed_on_ambiguous_or_benign_logs(change):
    event = deepcopy(_event())
    payload = event["protoPayload"]
    if change == "data_access":
        event["logName"] = event["logName"].replace("%2Factivity", "%2Fdata_access")
    elif change == "different_project_log":
        event["logName"] = event["logName"].replace(PROJECT, "other-project")
    elif change == "wrong_resource_type":
        event["resource"]["type"] = "service_account"
    elif change == "wrong_resource_label":
        event["resource"]["labels"]["project_id"] = "other-project"
    elif change == "wrong_service":
        payload["serviceName"] = "iam.googleapis.com"
    elif change == "wrong_method":
        payload["methodName"] = "GetIamPolicy"
    elif change == "wrong_resource_name":
        payload["resourceName"] = "projects/other-project"
    elif change == "failed":
        payload["status"] = {"code": 7}
    elif change == "ambiguous_status":
        payload["status"] = {}
    elif change == "incomplete_operation":
        event["operation"] = {"first": True, "last": False}
    elif change == "redacted_actor":
        payload["authenticationInfo"] = {}
    elif change == "different_member":
        payload["response"]["bindings"][0]["members"] = ["user:someone-else@example.com"]
    elif change == "conditional_binding":
        payload["response"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2027-01-01T00:00:00Z')"}
    elif change == "missing_request":
        del payload["request"]
    elif change == "redacted_request":
        payload["request"] = "REDACTED"
    elif change == "wrong_requested_project":
        payload["request"]["resource"] = "other-project"
    elif change == "missing_response":
        del payload["response"]
    elif change == "redacted_response":
        payload["response"] = "REDACTED"
    elif change == "missing_bindings":
        del payload["response"]["bindings"]
    elif change == "missing_event_id":
        del event["insertId"]
    elif change == "wrong_policy_type":
        payload["response"]["@type"] = "type.googleapis.com/google.iam.v1.TestIamPermissionsResponse"
    elif change == "missing_delta":
        del payload["serviceData"]
    elif change == "removed_delta":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["action"] = "REMOVE"
    elif change == "unspecified_delta":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["action"] = "ACTION_UNSPECIFIED"
    elif change == "different_delta_member":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["member"] = "user:other@example.com"
    elif change == "different_delta_role":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["role"] = "roles/viewer"
    elif change == "conditional_delta":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["condition"] = {"expression": "true"}
    assert normalize_gcp_project_self_iam_bindings(event) == []


def test_common_legitimate_policy_edit_without_self_binding_is_ignored():
    event = _event()
    event["protoPayload"]["response"]["bindings"] = [
        {"role": "roles/viewer", "members": ["user:colleague@example.com"]}
    ]
    assert normalize_gcp_project_self_iam_bindings(event) == []


def test_existing_owner_editing_unrelated_binding_does_not_match():
    event = _event()
    event["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"] = [
        {"action": "ADD", "role": "roles/viewer", "member": "user:colleague@example.com"}
    ]
    assert normalize_gcp_project_self_iam_bindings(event) == []
