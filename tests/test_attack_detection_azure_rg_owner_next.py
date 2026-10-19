"""Synthetic positive and negative cases for RG self-grant correlation."""

from __future__ import annotations

import copy
import json

from peaso.attack_detection.azure_rg_owner_next import correlate_azure_rg_owner_self_grants
from peaso.attack_detection.rules import Rule, detect_azure_events
from peaso.server.azure_attack_logs import analyze_azure_source

SUB = "66666666-7777-4888-8999-000000000000"
ACTOR = "86b10631-ff01-4e73-a031-29e505565caa"
ASSIGNMENT = "dc4de024-bbd3-469c-806c-1a8f619b8788"
OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
SCOPE = f"/subscriptions/{SUB}/resourceGroups/proof-rg"
RESOURCE = f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{ASSIGNMENT}"
CLAIM = "http://schemas.microsoft.com/identity/claims/objectidentifier"


def records():
    common = {
        "subscriptionId": SUB, "resourceId": RESOURCE,
        "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
        "category": {"value": "Administrative"},
        "operationId": "6f4fe080-ccfb-4981-827c-071009a326b5",
        "caller": "alice@example.test", "claims": {CLAIM: ACTOR},
    }
    started = {**common, "status": {"value": "Started"},
               "eventDataId": "start-1", "eventTimestamp": "2026-10-18T16:43:52Z",
               "properties": {"requestbody": json.dumps({"properties": {
                   "principalId": ACTOR, "principalType": "User",
                   "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{OWNER}",
               }})}}
    succeeded = {**common, "status": {"value": "Succeeded"},
                 "eventDataId": "success-1", "eventTimestamp": "2026-10-18T16:43:55Z",
                 "subStatus": {"value": "Created"},
                 "properties": {"statusCode": "Created"}}
    return [started, succeeded]


def hits(rows):
    return correlate_azure_rg_owner_self_grants(rows, subscription=SUB)


def test_exact_rg_owner_self_grant_and_sigma():
    rule = Rule(id="rg-owner", title="RG Owner self assignment", level="high",
                description="Observed assignment", technique_id="azure-rg-owner-self-grant",
                product="azure", selection={
                    "event.source": "azure.activity",
                    "event.name": "rg_owner_self_assignment",
                    "event.outcome": "success", "request.self_grant": True,
                    "request.role_definition_id": OWNER,
                    "scope.type": "resource_group",
                })
    result = hits(records())
    assert len(result) == 1
    assert result[0]["scope.id"].lower() == SCOPE.lower()
    assert result[0]["target.id"] == ACTOR
    assert result[0]["request.role_definition_id"] == OWNER
    assert result[0]["event.name"] == "rg_owner_self_assignment"
    assert all(result[0].get(key) == value for key, value in rule.selection.items())
    assert [match.rule_id for match in detect_azure_events(result, [rule])] == ["rg-owner"]


def test_other_principal_role_or_scope_fails_closed():
    base = records()
    other = copy.deepcopy(base); body = json.loads(other[0]["properties"]["requestbody"])
    body["properties"]["principalId"] = "11111111-1111-1111-1111-111111111111"
    other[0]["properties"]["requestbody"] = json.dumps(body)
    assert hits(other) == []
    other = copy.deepcopy(base); body = json.loads(other[0]["properties"]["requestbody"])
    body["properties"]["roleDefinitionId"] = body["properties"]["roleDefinitionId"].replace(OWNER, "b24988ac-6180-42a0-ab88-20f7382dd24c")
    other[0]["properties"]["requestbody"] = json.dumps(body)
    assert hits(other) == []
    other = copy.deepcopy(base); body = json.loads(other[0]["properties"]["requestbody"])
    body["properties"]["roleDefinitionId"] = "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/roleDefinitions/" + OWNER
    other[0]["properties"]["requestbody"] = json.dumps(body)
    assert hits(other) == []
    other = copy.deepcopy(base)
    for row in other: row["resourceId"] = RESOURCE.replace("/providers/Microsoft.Authorization", "/providers/Microsoft.Compute/virtualMachines/vm1/providers/Microsoft.Authorization")
    assert hits(other) == []


def test_missing_failed_unpaired_or_stale_success_fails_closed():
    base = records()
    assert hits(base[:1]) == []
    for change in ("failed", "not_created", "missing_substatus", "operation", "caller", "stale", "missing_oid", "malformed_body", "missing_start_id", "missing_success_id"):
        rows = copy.deepcopy(base)
        if change == "failed": rows[1]["status"] = {"value": "Failed"}
        if change == "not_created": rows[1]["subStatus"] = {"value": "OK"}
        if change == "missing_substatus": rows[1].pop("subStatus")
        if change == "operation": rows[1]["operationId"] = "11111111-1111-1111-1111-111111111111"
        if change == "caller": rows[1]["caller"] = "other@example.test"
        if change == "stale": rows[1]["eventTimestamp"] = "2026-10-18T17:10:00Z"
        if change == "missing_oid": rows[0]["claims"] = {}
        if change == "malformed_body": rows[0]["properties"]["requestbody"] = "{"
        if change == "missing_start_id": rows[0].pop("eventDataId")
        if change == "missing_success_id": rows[1].pop("eventDataId")
        assert hits(rows) == [], change


def test_ambiguous_duplicate_operation_fails_closed():
    base = records()
    duplicate_start = copy.deepcopy(base[0])
    duplicate_start["eventDataId"] = "start-2"
    assert hits([*base, duplicate_start]) == []
    duplicate_success = copy.deepcopy(base[1])
    duplicate_success["eventDataId"] = "success-2"
    assert hits([*base, duplicate_success]) == []


def test_azure_source_reader_delivers_rg_owner_self_grant(monkeypatch):
    from types import SimpleNamespace

    class Transport:
        def request(self, url, **kwargs):
            return {"value": records()}

        def close(self):
            pass

    rule = Rule(id="rg-owner", title="RG Owner self assignment", level="high",
                description="Observed assignment", technique_id="azure-rg-owner-self-grant",
                product="azure", selection={
                    "event.name": "rg_owner_self_assignment", "event.outcome": "success",
                    "request.self_grant": True, "scope.type": "resource_group",
                })
    monkeypatch.setattr("peaso.server.azure_attack_logs.AzureTransport", lambda auth: Transport())
    monkeypatch.setattr("peaso.attack_detection.detect_azure_events",
                        lambda candidates: detect_azure_events(candidates, [rule]))
    result = analyze_azure_source({}, [SUB], {}, SimpleNamespace(kind="azure_activity_log", subscription_id=SUB))
    assert result["coverage"]["self_grant_candidates"] == 1
    assert [item["rule_id"] for item in result["detections"]] == ["rg-owner"]
