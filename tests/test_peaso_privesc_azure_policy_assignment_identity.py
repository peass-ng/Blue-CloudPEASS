"""Policy assignment escalation must bind its definition, assignment, and UAMI."""
from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, T, _uami, az


TECHNIQUE = "azure-policy-assignment-write-user-assigned-identity"
SOURCE = "u-alice"
TARGET = "mi-policy"
UAMI = _uami("policy-mi", TARGET)
ASSIGNMENT_WRITE = "Microsoft.Authorization/policyAssignments/write"
DEFINITION_WRITE = "Microsoft.Authorization/policyDefinitions/write"
UAMI_ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
ROLES = {
    "11111111-1111-1111-1111-111111111111": ([ASSIGNMENT_WRITE], []),
    "22222222-2222-2222-2222-222222222222": ([DEFINITION_WRITE], []),
    "33333333-3333-3333-3333-333333333333": ([UAMI_ASSIGN], []),
}
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)


def _run(assignment_scope, definition_scope=SUB, uami_scope=None, *, graph=None, extra=()):
    assignments = [(SOURCE, "User", assignment_scope, next(iter(ROLES))),
                   (SOURCE, "User", definition_scope, list(ROLES)[1]),
                   (SOURCE, "User", uami_scope or UAMI["id"], list(ROLES)[2])]
    snap = az(assignments, roles=ROLES, graph=graph or [UAMI],
              extra=[("resource_group", SUB, [{"id": RG}], "collected"), *extra])
    return reached(privesc.analyze(snap, entries=[ENTRY]), SOURCE, TECHNIQUE)


def test_policy_assignment_definition_and_uami_same_usable_subscription():
    assert _run(RG) == {TARGET: "conditional"}


def test_unrelated_resource_or_definition_scope_cannot_be_joined():
    vm = RG + "/providers/Microsoft.Compute/virtualMachines/one"
    assert TARGET not in _run(vm)
    other_sub = "/subscriptions/00000000-0000-0000-0000-00000000bbbb"
    assert TARGET not in _run(RG, definition_scope=other_sub)
    assert TARGET not in _run(RG, uami_scope=RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other")


def test_exact_existing_assignment_and_custom_definition_child_grants():
    assignment = RG + "/providers/Microsoft.Authorization/policyAssignments/existing"
    definition = SUB + "/providers/Microsoft.Authorization/policyDefinitions/custom"
    graph = [UAMI, {"id": definition, "type": "Microsoft.Authorization/policyDefinitions",
                    "properties": {"policyType": "Custom"}}]
    extra = [("policy_assignment", SUB,
              [{"id": assignment, "type": "Microsoft.Authorization/policyAssignments"}], "collected")]
    assert _run(assignment, definition, graph=graph, extra=extra) == {TARGET: "conditional"}
    built_in = [UAMI, {**graph[1], "properties": {"policyType": "BuiltIn"}}]
    assert TARGET not in _run(assignment, definition, graph=built_in, extra=extra)
