"""OS disk swaps join VM rights with a usable replacement disk route."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TECHNIQUE = "azure-vm-os-disk-swap"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VM = RG + "/providers/Microsoft.Compute/virtualMachines/one"
OTHER_VM = RG + "/providers/Microsoft.Compute/virtualMachines/other"
CURRENT = RG + "/providers/Microsoft.Compute/disks/current"
REPLACEMENT = RG + "/providers/Microsoft.Compute/disks/replacement"
VM_WRITE = "Microsoft.Compute/virtualMachines/write"
DISK_READ = "Microsoft.Compute/disks/read"
DISK_WRITE = "Microsoft.Compute/disks/write"
START = "Microsoft.Compute/virtualMachines/start/action"


def _run(grants, *, region="westus", size=64, disk_os="Linux", managed_by=None,
         power="PowerState/running", ephemeral=False, existing=True):
    ids = [f"{i:08d}-0000-0000-0000-000000000011" for i in range(len(grants))]
    roles = {rid: ([action], []) for rid, (action, _) in zip(ids, grants)}
    assignments = [("u-alice", "User", scope, rid)
                   for rid, (_, scope) in zip(ids, grants)]
    os_disk = {"osType": "Linux", "managedDisk": {"id": CURRENT}}
    if ephemeral:
        os_disk["diffDiskSettings"] = {"option": "Local"}
    vm = {"id": VM, "type": "Microsoft.Compute/virtualMachines", "location": "westus",
          "identity": {"principalId": "mi-vm"},
          "properties": {"storageProfile": {"osDisk": os_disk},
                         "instanceView": {"statuses": [{"code": power}]}}}
    graph = [{"id": CURRENT, "type": "Microsoft.Compute/disks", "location": "westus",
              "properties": {"diskSizeGB": 64, "osType": "Linux"}}]
    if existing:
        graph.append({"id": REPLACEMENT, "type": "Microsoft.Compute/disks",
                      "location": region, "managedBy": managed_by,
                      "properties": {"diskSizeGB": size, "osType": disk_os}})
    extra = [("vm", SUB, [vm], "collected"),
             ("resource_group", SUB, [{"id": RG}], "collected")]
    snap = az(assignments, roles=roles, graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_existing_compatible_disk_does_not_require_deallocation():
    grants = [(VM_WRITE, VM), (DISK_READ, REPLACEMENT), (DISK_WRITE, REPLACEMENT)]
    assert _run(grants) == {"mi-vm": "conditional"}
    assert not _run([(VM_WRITE, OTHER_VM), *grants[1:]])
    assert not _run(grants, region="eastus")
    assert not _run(grants, size=128)
    assert not _run(grants, disk_os="Windows")
    assert not _run(grants, managed_by=OTHER_VM)
    assert not _run(grants, ephemeral=True)


def test_stopped_vm_needs_start_on_same_vm():
    grants = [(VM_WRITE, VM), (DISK_READ, REPLACEMENT), (DISK_WRITE, REPLACEMENT)]
    assert not _run(grants, power="PowerState/deallocated")
    assert _run([*grants, (START, VM)], power="PowerState/deallocated") == {
        "mi-vm": "conditional"}
    assert not _run([*grants, (START, OTHER_VM)], power="PowerState/deallocated")


def test_creatable_disk_uses_a_known_resource_group():
    grants = [(VM_WRITE, VM), (DISK_READ, RG), (DISK_WRITE, RG)]
    assert _run(grants, existing=False) == {"mi-vm": "conditional"}
    assert not _run(grants[:-1], existing=False)
