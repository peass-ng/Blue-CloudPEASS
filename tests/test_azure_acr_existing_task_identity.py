"""ACR task write reaches only identities actually attached to that task."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


REGISTRY = f"{RG}/providers/Microsoft.ContainerRegistry/registries/one"
TASK = f"{REGISTRY}/tasks/one"
OTHER_TASK = f"{REGISTRY}/tasks/other"
IDENTITY = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/target"
WRITE = "Microsoft.ContainerRegistry/registries/tasks/write"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-acr-task-write-existing-identity")


def _task(rid=TASK, identity=None):
    item = {"id": rid, "type": "Microsoft.ContainerRegistry/registries/tasks", "name": rid.rsplit("/", 1)[-1]}
    if identity is not None:
        item["identity"] = identity
    return item


def _run(graph, *, scope=TASK, extra=()):
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: ([WRITE], [])},
              graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY], include_unknown=True), "u-alice", ENTRY["id"])


def test_exact_existing_task_system_identity():
    assert _run([_task(identity={"principalId": "mi-task"})]) == {"mi-task": "conditional"}


def test_exact_existing_task_user_assigned_identity_needs_no_new_assign_permission():
    uami = {"id": IDENTITY, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
            "properties": {"principalId": "mi-target"}}
    task = _task(identity={"userAssignedIdentities": {IDENTITY: {"principalId": "mi-target"}}})
    assert _run([task], extra=[("managed_identity", SUB, [uami], "collected")]) == {"mi-target": "conditional"}


def test_registry_parent_identity_is_not_task_identity():
    registry = {"id": REGISTRY, "type": "Microsoft.ContainerRegistry/registries",
                "identity": {"principalId": "mi-registry"}}
    assert "mi-registry" not in _run([registry, _task()])


def test_write_on_other_task_does_not_reach_identity():
    assert "mi-target" not in _run([_task(OTHER_TASK, {"principalId": "mi-target"})], scope=TASK)


def test_host_only_uami_without_its_resource_does_not_name_identity():
    task = _task(identity={"userAssignedIdentities": {IDENTITY: {"principalId": "mi-target"}}})
    assert "mi-target" not in _run([task], extra=[("managed_identity", SUB, [], "partial")])


def test_duplicate_conflicting_task_records_do_not_name_identity():
    assert "mi-target" not in _run([_task(identity={"principalId": "mi-target"}),
                                    _task(identity={"principalId": "mi-other"})])


def test_one_writable_task_reaches_uami_shared_with_another_task():
    uami = {"id": IDENTITY, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
            "properties": {"principalId": "mi-target"}}
    attached = {"userAssignedIdentities": {IDENTITY: {"principalId": "mi-target"}}}
    assert _run([_task(TASK, attached), _task(OTHER_TASK, attached)],
                extra=[("managed_identity", SUB, [uami], "collected")]) == {"mi-target": "conditional"}
