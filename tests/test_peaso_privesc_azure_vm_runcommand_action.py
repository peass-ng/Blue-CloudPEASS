"""Action Run Command requires one runnable VM carrying the identity."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TECHNIQUE = "azure-vm-runcommand-action"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VM = RG + "/providers/Microsoft.Compute/virtualMachines/one"
OTHER = RG + "/providers/Microsoft.Compute/virtualMachines/other"
RUN = "Microsoft.Compute/virtualMachines/runCommand/action"
START = "Microsoft.Compute/virtualMachines/start/action"


def _run(grants, *, power="PowerState/running", include_vm=True, native=True):
    ids = [f"{i:08d}-0000-0000-0000-000000000012" for i in range(len(grants))]
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


def test_runcommand_action_targets_inventoried_identity_vm():
    assert _run([(RUN, VM)]) == {"mi-vm": "conditional"}
    assert _run([(RUN, VM)], native=False) == {"mi-vm": "conditional"}
    assert not _run([(RUN, OTHER)])
    assert not _run([(RUN, VM)], include_vm=False)


def test_stopped_vm_needs_start_on_same_vm():
    assert not _run([(RUN, VM)], power="PowerState/deallocated")
    assert _run([(RUN, VM), (START, VM)], power="PowerState/deallocated") == {
        "mi-vm": "conditional"}
    assert not _run([(RUN, VM), (START, OTHER)], power="PowerState/deallocated")
