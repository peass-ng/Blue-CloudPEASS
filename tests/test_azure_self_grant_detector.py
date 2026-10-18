"""A privileged Azure self-grant requires both request and successful outcome."""
from __future__ import annotations

import json
from copy import deepcopy

import pytest

from peaso.attack_detection.azure import (
    OWNER, USER_ACCESS_ADMINISTRATOR, correlate_azure_self_grants,
)


SUB = "12345678-1234-1234-1234-123456789abc"
ACTOR = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
OTHER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
ASSIGNMENT = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
OPERATION = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
RESOURCE = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments/{ASSIGNMENT}"


def pair(*, role=OWNER, resource=RESOURCE, principal=ACTOR):
    started = {
        "subscriptionId": SUB, "category": {"value": "Administrative"},
        "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
        "status": {"value": "Started"}, "operationId": OPERATION,
        "caller": "actor@example.invalid",
        "resourceId": resource, "eventDataId": "start-event", "eventTimestamp": "2026-10-18T08:00:00Z",
        "claims": {"http://schemas.microsoft.com/identity/claims/objectidentifier": ACTOR},
        "properties": {"requestbody": json.dumps({"id": ASSIGNMENT, "properties": {
            "principalId": principal,
            "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{role}",
            "principalType": "User"}})},
    }
    success = deepcopy(started)
    success["status"] = {"value": "Succeeded"}
    success["subStatus"] = {"value": "Created (HTTP Status Code: 201)"}
    success["eventDataId"] = "success-event"
    success["eventTimestamp"] = "2026-10-18T08:01:00Z"
    success["properties"] = {"statusCode": "Created"}
    return started, success


def test_owner_self_grant_requires_review_with_only_bound_evidence():
    started, success = pair()
    matches = correlate_azure_self_grants([success, started], subscription=SUB)
    assert len(matches) == 1
    match = matches[0]
    assert match["event.name"] == "role_self_assignment"
    assert match["event.outcome"] == "success"
    assert match["event.id"] == "success-event"
    assert match["actor.id"] == match["target.id"] == ACTOR
    assert match["scope.id"] == f"/subscriptions/{SUB}"
    assert match["request.role_definition_id"] == OWNER
    assert match["correlation_evidence"] == {
        "started_event_id": "start-event", "succeeded_event_id": "success-event",
        "operation_id": OPERATION, "assignment_id": ASSIGNMENT,
        "scope": f"/subscriptions/{SUB}",
    }
    assert "requestbody" not in json.dumps(match)
    assert "rule_id" not in match and "severity" not in match


def test_user_access_admin_self_grant_and_duplicate_success_deduped():
    started, success = pair(role=USER_ACCESS_ADMINISTRATOR)
    matches = correlate_azure_self_grants(
        [started, deepcopy(started), success, deepcopy(success)], subscription=SUB)
    assert len(matches) == 1
    assert matches[0]["request.role_name"] == "User Access Administrator"


@pytest.mark.parametrize("field", ["operationId", "resourceId"])
def test_conflicting_event_id_across_keys_suppresses_candidate(field):
    started, success = pair()
    conflicting = deepcopy(started)
    if field == "operationId":
        conflicting[field] = OTHER
    else:
        conflicting[field] = RESOURCE.replace(ASSIGNMENT, OTHER)
    assert len(correlate_azure_self_grants([started, success], subscription=SUB)) == 1
    assert correlate_azure_self_grants([started, conflicting, success], subscription=SUB) == []


@pytest.mark.parametrize("status_code", ["Created", "Created (HTTP Status Code: 201)", "201"])
def test_matching_native_status_code_keeps_candidate(status_code):
    started, success = pair()
    success["properties"]["statusCode"] = status_code
    assert len(correlate_azure_self_grants([started, success], subscription=SUB)) == 1


def test_absent_optional_status_code_keeps_candidate():
    started, success = pair()
    success.pop("properties")
    assert len(correlate_azure_self_grants([started, success], subscription=SUB)) == 1


@pytest.mark.parametrize("status", ["Failed", "Succeeded"])
def test_duplicate_ineligible_outcome_conflicts_with_valid_event_id(status):
    started, success = pair()
    contradictory = deepcopy(success)
    contradictory["status"] = {"value": status}
    contradictory["subStatus"] = {"value": "OK (HTTP Status Code: 200)"}
    contradictory["properties"]["statusCode"] = "OK"
    assert correlate_azure_self_grants([started, success, contradictory], subscription=SUB) == []


def test_unrelated_ineligible_event_does_not_hide_valid_pair():
    started, success = pair()
    unrelated = deepcopy(success)
    unrelated["eventDataId"] = "unrelated-update-event"
    unrelated["subStatus"] = {"value": "OK (HTTP Status Code: 200)"}
    unrelated["properties"]["statusCode"] = "OK"
    assert len(correlate_azure_self_grants([started, success, unrelated], subscription=SUB)) == 1


@pytest.mark.parametrize("status_code", ["OK", "OK (HTTP Status Code: 200)", "200", None, 201, {}])
def test_conflicting_or_malformed_status_code_suppresses_candidate(status_code):
    started, success = pair()
    success["properties"]["statusCode"] = status_code
    assert correlate_azure_self_grants([started, success], subscription=SUB) == []


def test_updated_assignment_is_not_reported_as_created():
    started, success = pair()
    success["subStatus"] = {"value": "OK (HTTP Status Code: 200)"}
    assert correlate_azure_self_grants([started, success], subscription=SUB) == []


def test_ambiguous_operation_pairs_do_not_claim_self_grant():
    started, success = pair()
    other_start = deepcopy(started)
    other_start["eventDataId"] = "other-start-event"
    other_start["properties"]["requestbody"] = json.dumps({"id": ASSIGNMENT, "properties": {
        "principalId": OTHER,
        "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{OWNER}"}})
    assert correlate_azure_self_grants([started, other_start, success], subscription=SUB) == []
    other_success = deepcopy(success)
    other_success["eventDataId"] = "other-success-event"
    assert correlate_azure_self_grants([started, success, other_success], subscription=SUB) == []


@pytest.mark.parametrize("change", [
    "failed", "no_request", "other_principal", "other_actor", "other_operation",
    "other_resource", "too_late", "wrong_category", "wrong_subscription",
    "wrong_request_id", "no_actor_oid", "success_before_started",
    "missing_created", "different_caller", "conflicting_repeat", "same_event_id",
])
def test_incomplete_or_mismatched_operations_do_not_match(change):
    started, success = pair()
    if change == "failed":
        success["status"]["value"] = "Failed"
    elif change == "no_request":
        started["properties"] = {}
    elif change == "other_principal":
        started["properties"]["requestbody"] = json.dumps({"properties": {
            "principalId": OTHER,
            "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{OWNER}"}})
    elif change == "other_actor":
        success["claims"]["http://schemas.microsoft.com/identity/claims/objectidentifier"] = OTHER
    elif change == "other_operation":
        success["operationId"] = OTHER
    elif change == "other_resource":
        success["resourceId"] = success["resourceId"].replace(ASSIGNMENT, OTHER)
    elif change == "too_late":
        success["eventTimestamp"] = "2026-10-18T08:11:00Z"
    elif change == "wrong_category":
        started["category"]["value"] = "Policy"
    elif change == "wrong_subscription":
        started["subscriptionId"] = OTHER
    elif change == "wrong_request_id":
        body = json.loads(started["properties"]["requestbody"])
        body["id"] = OTHER
        started["properties"]["requestbody"] = json.dumps(body)
    elif change == "no_actor_oid":
        started["claims"] = {}
    elif change == "success_before_started":
        success["eventTimestamp"] = "2026-10-18T07:59:00Z"
    elif change == "missing_created":
        success.pop("subStatus")
    elif change == "different_caller":
        success["caller"] = "different@example.invalid"
    elif change == "same_event_id":
        success["eventDataId"] = started["eventDataId"]
    elif change == "conflicting_repeat":
        repeated = deepcopy(started)
        repeated["caller"] = "different@example.invalid"
        assert correlate_azure_self_grants([started, repeated, success], subscription=SUB) == []
        return
    assert correlate_azure_self_grants([started, success], subscription=SUB) == []


def test_other_role_stays_a_candidate_for_the_rule_pack_to_reject():
    started, success = pair(role="b24988ac-6180-42a0-ab88-20f7382dd24c")
    matches = correlate_azure_self_grants([started, success], subscription=SUB)
    assert len(matches) == 1
    assert matches[0]["request.role_definition_id"] == "b24988ac-6180-42a0-ab88-20f7382dd24c"
    assert matches[0]["request.role_name"] is None


def test_management_group_scope_is_deferred_until_a_separate_source_exists():
    resource = f"/providers/Microsoft.Management/managementGroups/root-group/providers/Microsoft.Authorization/roleAssignments/{ASSIGNMENT}"
    started, success = pair(resource=resource)
    assert correlate_azure_self_grants([started, success], subscription=SUB) == []
