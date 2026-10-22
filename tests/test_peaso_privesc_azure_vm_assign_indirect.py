"""Indirect VM routes cannot combine grants from unrelated VMs or assets."""
import pytest

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, _uami, az


TECHNIQUE = "azure-vm-assign-user-assigned-identity-indirect-exec"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VM = RG + "/providers/Microsoft.Compute/virtualMachines/one"
OTHER = RG + "/providers/Microsoft.Compute/virtualMachines/other"
UAMI = _uami("indirect", "mi-indirect")
APP = RG + "/providers/Microsoft.Compute/galleries/gal/applications/app"
DISK = RG + "/providers/Microsoft.Compute/disks/payload"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
WRITE = "Microsoft.Compute/virtualMachines/write"


def _run(route, *, vm_scope=VM, target_scope=None, include_vm=True, disk_region="westus"):
    actions = [(ASSIGN, UAMI["id"]), (WRITE, vm_scope)] + route
    ids = [f"{i:08d}-0000-0000-0000-000000000006" for i in range(len(actions))]
    roles = {rid: ([action], []) for rid, (action, _) in zip(ids, actions)}
    assignments = [("u-alice", "User", scope, rid)
                   for rid, (_, scope) in zip(ids, actions)]
    graph = [UAMI, {"id": APP, "type": "Microsoft.Compute/galleries/applications", "location": "eastus"},
             {"id": DISK, "type": "Microsoft.Compute/disks", "location": disk_region}]
    vm = {"id": VM, "type": "Microsoft.Compute/virtualMachines", "location": "westus",
          "properties": {"storageProfile": {"osDisk": {"osType": "Linux"}}}}
    extra = [("vm", SUB, [vm], "collected")] if include_vm else []
    snap = az(assignments, roles=roles, graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


@pytest.mark.parametrize("route", [
    [("Microsoft.Compute/virtualMachines/reimage/action", VM)],
    [("Microsoft.SerialConsole/serialPorts/connect/action", VM),
     ("Microsoft.Compute/virtualMachines/restart/action", VM)],
    [("Microsoft.GuestConfiguration/guestConfigurationAssignments/write",
      VM + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/one")],
    [("Microsoft.Compute/galleries/applications/versions/write", APP + "/versions/1.0.0")],
    [("Microsoft.Compute/virtualMachines/deallocate/action", VM),
     ("Microsoft.Compute/virtualMachines/start/action", VM),
     ("Microsoft.Compute/disks/read", DISK), ("Microsoft.Compute/disks/write", DISK)],
])
def test_each_indirect_route_requires_one_vm_and_exact_uami(route):
    assert _run(route) == {"mi-indirect": "conditional"}
    assert not _run(route, vm_scope=OTHER)
    assert not _run(route, include_vm=False)


def test_serial_and_disk_routes_do_not_join_unrelated_resources():
    assert not _run([("Microsoft.Compute/virtualMachines/redeploy/action", VM)])
    serial = [("Microsoft.SerialConsole/serialPorts/connect/action", VM),
              ("Microsoft.Compute/virtualMachines/restart/action", OTHER)]
    assert not _run(serial)
    disk = [("Microsoft.Compute/virtualMachines/deallocate/action", VM),
            ("Microsoft.Compute/virtualMachines/start/action", VM),
            ("Microsoft.Compute/disks/read", DISK), ("Microsoft.Compute/disks/write", DISK)]
    assert not _run(disk, disk_region="eastus")


def test_disk_swap_does_not_require_deallocation_of_running_vm():
    disk = [("Microsoft.Compute/disks/read", DISK),
            ("Microsoft.Compute/disks/write", DISK)]
    assert _run(disk) == {"mi-indirect": "conditional"}
    assert not _run(disk, disk_region="eastus")
