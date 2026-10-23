"""Managed Run Command grants join the identity VM and executable child."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TECHNIQUE = "azure-vm-managed-runcommands-write"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VM = RG + "/providers/Microsoft.Compute/virtualMachines/one"
OTHER = RG + "/providers/Microsoft.Compute/virtualMachines/other"
CHILD = VM + "/runCommands/validation"
OTHER_CHILD = OTHER + "/runCommands/validation"
WRITE = "Microsoft.Compute/virtualMachines/runCommands/write"
START = "Microsoft.Compute/virtualMachines/start/action"


def _run(grants, *, power="PowerState/running", include_vm=True, native=True):
    ids = [f"{i:08d}-0000-0000-0000-000000000010" for i in range(len(grants))]
    roles = {rid: ([action], []) for rid, (action, _) in zip(ids, grants)}
    assignments = [("u-alice", "User", scope, rid)
                   for rid, (_, scope) in zip(ids, grants)]
    vm = {"id": VM, "type": "Microsoft.Compute/virtualMachines",
          "identity": {"principalId": "mi-vm"},
          "properties": {"instanceView": {"statuses": [{"code": power}]}}}
    extra = [("vm", SUB, [vm], "collected")] if include_vm and native else []
    graph = [vm] if include_vm and not native else []
    snap = az(assignments, roles=roles, graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_parent_and_child_permissions_reach_same_vm():
    assert _run([(WRITE, VM)]) == {"mi-vm": "conditional"}
    assert _run([(WRITE, CHILD)]) == {"mi-vm": "conditional"}
    assert _run([(WRITE, CHILD)], native=False) == {"mi-vm": "conditional"}


def test_unrelated_child_and_missing_vm_do_not_complete_route():
    assert not _run([(WRITE, OTHER_CHILD)])
    assert not _run([(WRITE, CHILD)], include_vm=False)


def test_stopped_vm_needs_start_on_same_vm():
    assert not _run([(WRITE, CHILD)], power="PowerState/deallocated")
    assert _run([(WRITE, CHILD), (START, VM)], power="PowerState/deallocated") == {
        "mi-vm": "conditional"}
    assert not _run([(WRITE, CHILD), (START, OTHER)], power="PowerState/deallocated")
