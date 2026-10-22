"""An ACR task can reach only a verified UAMI on a registry the source can write."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


REGISTRY = f"{RG}/providers/Microsoft.ContainerRegistry/registries/one"
IDENTITY = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/target"
WRITE = "Microsoft.ContainerRegistry/registries/tasks/write"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-acr-task-assign-user-assigned-identity")


def _run(*, graph_type="Microsoft.ContainerRegistry/registries", registry=True,
         uami=True, actions=(WRITE, ASSIGN), assignment_scope=SUB,
         graph_status=None, identity_status=None):
    graph = [{"id": REGISTRY, "type": graph_type, "name": "one"}] if registry else []
    identity = {"id": IDENTITY, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {"principalId": "mi-target", "clientId": "client-target"}} if uami else None
    extra = [] if identity_status is None else [("managed_identity", SUB, [identity] if identity else [], identity_status)]
    if graph_status is not None:
        graph = []
    snap = az([("u-alice", "User", assignment_scope, ROLE_ID)],
              roles={ROLE_ID: (list(actions), [])}, graph=graph, extra=extra)
    if graph_status is not None:
        next(c for c in snap["collections"] if c["type"] == "resource_graph")["status"] = graph_status
    return privesc.analyze(snap, entries=[ENTRY], include_unknown=True)


def test_known_registry_and_verified_uami_reach_conditionally():
    assert reached(_run(identity_status="collected"), "u-alice", ENTRY["id"]) == {"mi-target": "conditional"}


def test_existing_task_with_exact_write_scope_can_receive_uami():
    task = f"{REGISTRY}/tasks/existing"
    identity = {"id": IDENTITY, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {"principalId": "mi-target", "clientId": "client-target"}}
    snap = az([("u-alice", "User", task, ROLE_ID),
               ("u-alice", "User", IDENTITY, ROLE_ID)],
              roles={ROLE_ID: ([WRITE, ASSIGN], [])},
              graph=[{"id": task, "type": "Microsoft.ContainerRegistry/registries/tasks",
                      "name": "existing"}],
              extra=[("managed_identity", SUB, [identity], "collected")])
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    assert reached(result, "u-alice", ENTRY["id"]) == {"mi-target": "conditional"}


def test_no_registry_or_wrong_registry_type_does_not_name_uami():
    for result in (_run(registry=False, identity_status="collected"),
                   _run(graph_type="Microsoft.Compute/virtualMachines", identity_status="collected")):
        assert "mi-target" not in reached(result, "u-alice", ENTRY["id"])


def test_missing_identity_or_permission_does_not_name_uami():
    for result in (_run(uami=False, identity_status="empty"),
                   _run(actions=(WRITE,), identity_status="collected"),
                   _run(actions=(ASSIGN,), identity_status="collected"),
                   _run(assignment_scope=f"{RG}/providers/Microsoft.Compute/virtualMachines/other",
                        identity_status="collected")):
        assert "mi-target" not in reached(result, "u-alice", ENTRY["id"])


def test_missing_registry_inventory_does_not_name_uami():
    result = _run(registry=False, graph_status="not_collected", identity_status="collected")
    assert "mi-target" not in reached(result, "u-alice", ENTRY["id"])


def test_identity_seen_only_on_another_host_is_not_a_verified_uami_resource():
    snap = az([("u-alice", "User", SUB, ROLE_ID)], roles={ROLE_ID: ([WRITE, ASSIGN], [])},
              graph=[{"id": REGISTRY, "type": "Microsoft.ContainerRegistry/registries", "name": "one"},
                     {"id": f"{RG}/providers/Microsoft.Compute/virtualMachines/host",
                      "type": "Microsoft.Compute/virtualMachines", "name": "host",
                      "identity": {"userAssignedIdentities": {IDENTITY: {"principalId": "mi-target"}}}}],
              extra=[("managed_identity", SUB, [], "partial")])
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    assert "mi-target" not in reached(result, "u-alice", ENTRY["id"])
