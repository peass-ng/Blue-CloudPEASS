"""VMSS managed Run Command must reach an inventoried instance child."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TECHNIQUE = "azure-vmss-vm-managed-runcommands-write"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VMSS = RG + "/providers/Microsoft.Compute/virtualMachineScaleSets/one"
OTHER = RG + "/providers/Microsoft.Compute/virtualMachineScaleSets/other"
INSTANCE = VMSS + "/virtualMachines/0"
OTHER_INSTANCE = OTHER + "/virtualMachines/0"
COMMAND = INSTANCE + "/runCommands/validation"
WRITE = "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommands/write"
START_INSTANCE = "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/start/action"
START_SET = "Microsoft.Compute/virtualMachineScaleSets/start/action"


def _run(grants, *, power="PowerState/running", mode="Uniform", instance=True,
         include_unknown=False):
    ids = [f"{i:08d}-0000-0000-0000-000000000014" for i in range(len(grants))]
    roles = {rid: ([action], []) for rid, (action, _) in zip(ids, grants)}
    assignments = [("u-alice", "User", scope, rid)
                   for rid, (_, scope) in zip(ids, grants)]
    child = {"id": INSTANCE, "type": "Microsoft.Compute/virtualMachineScaleSets/virtualMachines",
             "properties": {"instanceView": {"statuses": [{"code": power}]}}}
    vmss = {"id": VMSS, "type": "Microsoft.Compute/virtualMachineScaleSets",
            "identity": {"principalId": "mi-vmss"},
            "properties": {"orchestrationMode": mode},
            "virtualMachines": [child] if instance else [],
            "_coverage": {"virtualMachines": {"status": "collected" if instance else "empty"}}}
    snap = az(assignments, roles=roles, extra=[("vm_scale_set", SUB, [vmss], "collected")])
    return reached(privesc.analyze(snap, entries=[ENTRY], include_unknown=include_unknown),
                   "u-alice", TECHNIQUE)


def test_runcommand_grant_joins_exact_uniform_instance():
    assert _run([(WRITE, VMSS)]) == {"mi-vmss": "conditional"}
    assert _run([(WRITE, COMMAND)]) == {"mi-vmss": "conditional"}
    assert not _run([(WRITE, OTHER_INSTANCE + "/runCommands/validation")])
    assert not _run([(WRITE, VMSS)], instance=False)


def test_stopped_instance_needs_exact_start_route():
    assert not _run([(WRITE, COMMAND)], power="PowerState/deallocated")
    assert _run([(WRITE, COMMAND), (START_INSTANCE, INSTANCE)],
                power="PowerState/deallocated") == {"mi-vmss": "conditional"}
    assert _run([(WRITE, COMMAND), (START_SET, VMSS)],
                power="PowerState/deallocated") == {"mi-vmss": "conditional"}
    assert not _run([(WRITE, COMMAND), (START_INSTANCE, OTHER_INSTANCE)],
                    power="PowerState/deallocated")


def test_flexible_instance_identity_is_unresolved():
    assert not _run([(WRITE, COMMAND)], mode="Flexible")
    assert "unknown" in _run([(WRITE, COMMAND)], mode="Flexible",
                             include_unknown=True).values()
