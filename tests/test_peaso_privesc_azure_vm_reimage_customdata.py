"""Reimage customData is an exact Linux VM request-body route."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TECHNIQUE = "azure-vm-customdata-reimage"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VM = RG + "/providers/Microsoft.Compute/virtualMachines/one"
OTHER = RG + "/providers/Microsoft.Compute/virtualMachines/other"
ROLE = "12345678-0000-0000-0000-000000000008"


def _run(scope, *, action="Microsoft.Compute/virtualMachines/reimage/action", os_type="Linux",
         native=True, identity=True):
    vm = {"id": VM, "type": "Microsoft.Compute/virtualMachines",
          "properties": {"storageProfile": {"osDisk": {"osType": os_type}}}}
    if identity:
        vm["identity"] = {"principalId": "mi-vm"}
    extra = [("vm", SUB, [vm], "collected")] if native else []
    graph = [] if native else [vm]
    snap = az([("u-alice", "User", scope, ROLE)], roles={ROLE: ([action], [])},
              graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_reimage_action_binds_to_linux_vm_identity():
    assert _run(VM) == {"mi-vm": "conditional"}
    assert _run(VM, native=False) == {"mi-vm": "conditional"}
    assert not _run(OTHER)
    assert not _run(VM, os_type="Windows")
    assert not _run(VM, identity=False)


def test_redeploy_does_not_supply_new_customdata():
    assert not _run(VM, action="Microsoft.Compute/virtualMachines/redeploy/action")
