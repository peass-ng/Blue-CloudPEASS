"""Project IAM ADD delta must prove a direct foreign-project SA grant."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.gcp_iam_cross_project_next import normalize_gcp_cross_project_sa_grants


PROJECT = "customer-project"
GRANTEE = "builder@operations-project.iam.gserviceaccount.com"
MEMBER = f"serviceAccount:{GRANTEE}"


def event() -> dict:
    return {
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "cross-project-grant-1", "timestamp": "2026-10-18T12:00:00Z",
        "resource": {"type": "project", "labels": {"project_id": PROJECT}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "cloudresourcemanager.googleapis.com",
            "methodName": "SetIamPolicy",
            "resourceName": f"projects/{PROJECT}",
            "authenticationInfo": {"principalEmail": "admin@example.com"},
            "request": {"@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest", "resource": PROJECT},
            "response": {"@type": "type.googleapis.com/google.iam.v1.Policy", "bindings": [
                {"role": "roles/owner", "members": [MEMBER]},
            ]},
            "serviceData": {"policyDelta": {"bindingDeltas": [
                {"action": "ADD", "role": "roles/owner", "member": MEMBER},
            ]}},
        },
    }


def test_completed_cross_project_owner_grant():
    assert normalize_gcp_cross_project_sa_grants(event()) == [{
        "cloud.provider": "gcp",
        "event.name": "cross_project_service_account_binding_added",
        "event.source": "cloudresourcemanager.googleapis.com",
        "event.outcome": "success",
        "event.id": "cross-project-grant-1", "event.time": "2026-10-18T12:00:00Z",
        "account.id": PROJECT, "actor.id": "admin@example.com",
        "target.id": f"projects/{PROJECT}",
        "target.principal": MEMBER, "target.principal_project": "operations-project",
        "request.role": "roles/owner", "request.binding_added": True,
        "request.cross_project_service_account": True,
    }]


def test_multiple_grants_are_sorted_deduplicated_and_not_assumed_malicious():
    row = event()
    bindings = row["protoPayload"]["response"]["bindings"]
    deltas = row["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"]
    bindings.append({"role": "roles/viewer", "members": [MEMBER]})
    deltas.append({"action": "ADD", "role": "roles/viewer", "member": MEMBER})
    deltas.append({"action": "ADD", "role": "roles/owner", "member": MEMBER})
    result = normalize_gcp_cross_project_sa_grants(row)
    assert [item["request.role"] for item in result] == ["roles/owner", "roles/viewer"]
    assert all("malicious" not in item and "compromise" not in item for item in result)


@pytest.mark.parametrize("change", [
    "wrong_log_project", "data_access_log", "wrong_resource_type", "wrong_resource_project",
    "wrong_service", "wrong_method", "wrong_resource_name", "failed", "ambiguous_status",
    "incomplete", "redacted_actor", "missing_request", "wrong_request_project",
    "missing_response", "redacted_response", "same_project_sa", "user_member",
    "no_delta", "removed_delta", "unrelated_delta_member", "unrelated_delta_role",
    "conditional_delta", "conditional_returned_binding", "missing_event_id",
])
def test_rejects_non_additions_and_ambiguous_scope(change):
    row = deepcopy(event())
    payload = row["protoPayload"]
    if change == "wrong_log_project":
        row["logName"] = row["logName"].replace(PROJECT, "other-project")
    elif change == "data_access_log":
        row["logName"] = row["logName"].replace("%2Factivity", "%2Fdata_access")
    elif change == "wrong_resource_type":
        row["resource"]["type"] = "service_account"
    elif change == "wrong_resource_project":
        row["resource"]["labels"]["project_id"] = "other-project"
    elif change == "wrong_service":
        payload["serviceName"] = "iam.googleapis.com"
    elif change == "wrong_method":
        payload["methodName"] = "GetIamPolicy"
    elif change == "wrong_resource_name":
        payload["resourceName"] = "projects/other-project"
    elif change == "failed":
        payload["status"] = {"code": 7}
    elif change == "ambiguous_status":
        payload["status"] = {"message": "unknown"}
    elif change == "incomplete":
        row["operation"] = {"first": True, "last": False}
    elif change == "redacted_actor":
        payload["authenticationInfo"] = {}
    elif change == "missing_request":
        del payload["request"]
    elif change == "wrong_request_project":
        payload["request"]["resource"] = "other-project"
    elif change == "missing_response":
        del payload["response"]
    elif change == "redacted_response":
        payload["response"] = "REDACTED"
    elif change == "same_project_sa":
        same = MEMBER.replace("operations-project", PROJECT)
        payload["response"]["bindings"][0]["members"] = [same]
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["member"] = same
    elif change == "user_member":
        user = "user:operator@example.com"
        payload["response"]["bindings"][0]["members"] = [user]
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["member"] = user
    elif change == "no_delta":
        del payload["serviceData"]
    elif change == "removed_delta":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["action"] = "REMOVE"
    elif change == "unrelated_delta_member":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["member"] = "serviceAccount:other@operations-project.iam.gserviceaccount.com"
    elif change == "unrelated_delta_role":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["role"] = "roles/viewer"
    elif change == "conditional_delta":
        payload["serviceData"]["policyDelta"]["bindingDeltas"][0]["condition"] = {"expression": "true"}
    elif change == "conditional_returned_binding":
        payload["response"]["bindings"][0]["condition"] = {"expression": "true"}
    elif change == "missing_event_id":
        del row["insertId"]
    assert normalize_gcp_cross_project_sa_grants(row) == []
