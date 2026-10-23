"""VMSS model changes require a same-scale-set rollout route."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TECHNIQUE = "azure-vmss-model-write"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VMSS = RG + "/providers/Microsoft.Compute/virtualMachineScaleSets/one"
OTHER = RG + "/providers/Microsoft.Compute/virtualMachineScaleSets/other"
CHILD = VMSS + "/extensions/CustomScript"
MONITOR = VMSS + "/extensions/Monitor"
VMSS_WRITE = "Microsoft.Compute/virtualMachineScaleSets/write"
EXT_WRITE = "Microsoft.Compute/virtualMachineScaleSets/extensions/write"
UPGRADE = "Microsoft.Compute/virtualMachineScaleSets/manualUpgrade/action"


def _run(grants, *, mode="Uniform", policy="Automatic", existing_handler=None,
         child=CHILD, include_vmss=True, include_unknown=False):
    ids = [f"{i:08d}-0000-0000-0000-000000000013" for i in range(len(grants))]
    roles = {rid: ([action], []) for rid, (action, _) in zip(ids, grants)}
    assignments = [("u-alice", "User", scope, rid)
                   for rid, (_, scope) in zip(ids, grants)]
    vmss = {"id": VMSS, "type": "Microsoft.Compute/virtualMachineScaleSets",
            "identity": {"principalId": "mi-vmss"},
            "properties": {"orchestrationMode": mode, "upgradePolicy": {"mode": policy}}}
    extra = [("vm_scale_set", SUB, [vmss], "collected")] if include_vmss else []
    graph = ([{"id": child, "type": "Microsoft.Compute/virtualMachineScaleSets/extensions",
              "properties": {"type": existing_handler}}] if existing_handler else [])
    snap = az(assignments, roles=roles, graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY], include_unknown=include_unknown),
                   "u-alice", TECHNIQUE)


def test_scale_set_model_write_has_a_uniform_rollout_route():
    assert _run([(VMSS_WRITE, VMSS)]) == {"mi-vmss": "conditional"}
    assert _run([(VMSS_WRITE, VMSS)], policy="Manual") == {"mi-vmss": "conditional"}
    assert not _run([(VMSS_WRITE, OTHER)])
    assert not _run([(VMSS_WRITE, VMSS)], include_vmss=False)


def test_extension_child_requires_rollout_under_manual_policy():
    assert _run([(EXT_WRITE, CHILD)]) == {"mi-vmss": "conditional"}
    assert not _run([(EXT_WRITE, OTHER + "/extensions/CustomScript")])
    assert not _run([(EXT_WRITE, CHILD)], policy="Manual")
    assert _run([(EXT_WRITE, CHILD), (UPGRADE, VMSS)], policy="Manual") == {
        "mi-vmss": "conditional"}
    assert not _run([(EXT_WRITE, CHILD), (UPGRADE, OTHER)], policy="Manual")


def test_known_monitoring_child_is_not_code_execution():
    assert not _run([(EXT_WRITE, MONITOR)], existing_handler="AzureMonitorLinuxAgent",
                    child=MONITOR)
    assert _run([(EXT_WRITE, CHILD)], existing_handler="CustomScript") == {
        "mi-vmss": "conditional"}


def test_flexible_instance_identity_does_not_claim_uniform_model_path():
    assert not _run([(VMSS_WRITE, VMSS)], mode="Flexible")
    assert "unknown" in _run([(VMSS_WRITE, VMSS)], mode="Flexible",
                             include_unknown=True).values()
