"""APIM policy writers can be scoped to a child API, operation, or product."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


SERVICE = f"{RG}/providers/Microsoft.ApiManagement/service/api1"
API = SERVICE + "/apis/orders"
TARGET = "mi-apim"
ENTRY = next(entry for entry in yaml.safe_load(
    (Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/azure/api_management.yaml").read_text())
    if entry["id"] == "azure-apim-policy-write-managed-identity-token")


def _case(action, assignment_scope, *, known_api=True, typed_service=False):
    service = {"id": SERVICE, "type": "Microsoft.ApiManagement/service", "name": "api1",
               "identity": {"type": "SystemAssigned", "principalId": TARGET}}
    native = {"id": SERVICE, "_coverage": {"apis": {"status": "collected"}},
              "apis": [{"id": API}] if known_api else []}
    extra = [("apim_native", SUB, [native], "collected")]
    if typed_service:
        extra.append(("api_management", SUB, [service], "collected"))
    return az(assignments=[("u-alice", "User", assignment_scope, ROLE_ID)],
              roles={ROLE_ID: ([action], [])}, graph=[] if typed_service else [service], extra=extra)


@pytest.mark.parametrize("action,scope", [
    ("Microsoft.ApiManagement/service/policies/write", SERVICE),
    ("Microsoft.ApiManagement/service/apis/write", API),
    ("Microsoft.ApiManagement/service/apis/policies/write", API),
    ("Microsoft.ApiManagement/service/apis/operations/policies/write", API + "/operations/getOrder"),
    ("Microsoft.ApiManagement/service/products/policies/write", SERVICE + "/products/standard"),
])
def test_exact_apim_policy_write_scopes_reach_attached_identity(action, scope):
    assert validate_entry(ENTRY)[0] == []
    result = privesc.analyze(_case(action, scope), entries=[ENTRY])
    assert reached(result, "u-alice", ENTRY["id"]).get(TARGET) == "conditional"


def test_unknown_api_or_other_service_scope_does_not_reach_identity():
    action = "Microsoft.ApiManagement/service/apis/policies/write"
    assert TARGET not in reached(privesc.analyze(_case(action, API, known_api=False), entries=[ENTRY]),
                                 "u-alice", ENTRY["id"])
    wrong = SERVICE.replace("/api1", "/other") + "/apis/orders"
    assert TARGET not in reached(privesc.analyze(_case(action, wrong), entries=[ENTRY]),
                                 "u-alice", ENTRY["id"])


@pytest.mark.parametrize("action", [
    "Microsoft.ApiManagement/service/apis/write",
    "Microsoft.ApiManagement/service/apis/policies/write",
    "Microsoft.ApiManagement/service/apis/operations/policies/write",
    "Microsoft.ApiManagement/service/products/policies/write",
])
def test_service_level_policy_grants_remain_detected(action):
    result = privesc.analyze(_case(action, SERVICE), entries=[ENTRY])
    assert reached(result, "u-alice", ENTRY["id"]).get(TARGET) == "conditional"


def test_typed_apim_service_identity_works_without_resource_graph():
    action = "Microsoft.ApiManagement/service/apis/policies/write"
    result = privesc.analyze(_case(action, API, typed_service=True), entries=[ENTRY])
    assert reached(result, "u-alice", ENTRY["id"]).get(TARGET) == "conditional"


def test_unrelated_action_does_not_reach_identity():
    snap = _case("Microsoft.ApiManagement/service/apis/read", API)
    assert TARGET not in reached(privesc.analyze(copy.deepcopy(snap), entries=[ENTRY]),
                                 "u-alice", ENTRY["id"])


def test_child_scope_deny_blocks_policy_write():
    action = "Microsoft.ApiManagement/service/apis/policies/write"
    snap = _case(action, API)
    deny = next(c for c in snap["collections"] if c["type"] == "deny_assignment")
    deny["status"] = "collected"
    deny["items"] = [{"id": "deny-api-policy", "properties": {"scope": API,
        "principals": [{"id": "u-alice"}], "permissions": [{"actions": [action]}]}}]
    assert TARGET not in reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", ENTRY["id"])
