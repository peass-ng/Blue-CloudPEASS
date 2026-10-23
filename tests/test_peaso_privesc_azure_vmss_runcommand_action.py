"""Action Run Command must target a real Uniform scale-set instance."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TECHNIQUE = "azure-vmss-vm-runcommand-action"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VMSS = RG + "/providers/Microsoft.Compute/virtualMachineScaleSets/one"
OTHER = RG + "/providers/Microsoft.Compute/virtualMachineScaleSets/other"
INSTANCE = VMSS + "/virtualMachines/0"
OTHER_INSTANCE = OTHER + "/virtualMachines/0"
ACTION = "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action"
START = "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/start/action"


def _run(grants, *, power="PowerState/running", mode="Uniform", instance=True,
         include_unknown=False):
    ids = [f"{i:08d}-0000-0000-0000-000000000015" for i in range(len(grants))]
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


def test_action_binds_to_exact_inventoried_instance():
    assert _run([(ACTION, INSTANCE)]) == {"mi-vmss": "conditional"}
    assert _run([(ACTION, VMSS)]) == {"mi-vmss": "conditional"}
    assert not _run([(ACTION, OTHER_INSTANCE)])
    assert not _run([(ACTION, INSTANCE)], instance=False)


def test_stopped_instance_needs_start_and_flexible_is_unresolved():
    assert not _run([(ACTION, INSTANCE)], power="PowerState/deallocated")
    assert _run([(ACTION, INSTANCE), (START, INSTANCE)],
                power="PowerState/deallocated") == {"mi-vmss": "conditional"}
    assert not _run([(ACTION, INSTANCE), (START, OTHER_INSTANCE)],
                    power="PowerState/deallocated")
    assert not _run([(ACTION, INSTANCE)], mode="Flexible")
    assert "unknown" in _run([(ACTION, INSTANCE)], mode="Flexible",
                             include_unknown=True).values()
