"""VMSS instance Run Command reaches only an identity attached to its parent scale set."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


VMSS = f"{RG}/providers/Microsoft.Compute/virtualMachineScaleSets/nodes"
OTHER = f"{RG}/providers/Microsoft.Compute/virtualMachineScaleSets/other"
INSTANCE = f"{VMSS}/virtualMachines/0"
OTHER_INSTANCE = f"{OTHER}/virtualMachines/0"
ACTION = "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-aks-vmss-node-run-command")


def _scale_set(rid, principal, *, children=True, status="collected", mode="Uniform"):
    item = {"id": rid, "type": "Microsoft.Compute/virtualMachineScaleSets",
            "name": rid.rsplit("/", 1)[-1], "identity": {"principalId": principal},
            "properties": {"orchestrationMode": mode},
            "_coverage": {"virtualMachines": {"status": status}}}
    if children:
        item["virtualMachines"] = [{"id": rid + "/virtualMachines/0",
                                     "type": "Microsoft.Compute/virtualMachineScaleSets/virtualMachines",
                                     "name": "0"}]
    return item


def _run(*, scope=VMSS, actions=(ACTION,), children=True, status="collected",
         extra_scales=(), denied=False, mode="Uniform"):
    scales = [_scale_set(VMSS, "mi-node", children=children, status=status, mode=mode), *extra_scales]
    extra = [("vm_scale_set", SUB, scales, "collected")]
    if denied:
        extra.append(("deny_assignment", SUB, [{
            "id": INSTANCE + "/providers/Microsoft.Authorization/denyAssignments/one",
            "properties": {"scope": INSTANCE, "principals": [{"id": "u-alice"}],
                           "permissions": [{"actions": [ACTION]}]}}], "collected"))
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              extra=extra)
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    return reached(result, "u-alice", ENTRY["id"])


def test_parent_scale_set_grant_reaches_only_its_attached_identity():
    found = _run(extra_scales=(_scale_set(OTHER, "mi-other"),))
    assert any("mi-node" in key for key in found)
    assert not any("mi-other" in key for key in found)


def test_exact_instance_grant_is_not_missed():
    assert any("mi-node" in key for key in _run(scope=INSTANCE))


def test_other_instance_grant_does_not_reach_node_identity():
    found = _run(scope=OTHER_INSTANCE, extra_scales=(_scale_set(OTHER, "mi-other"),))
    assert not any("mi-node" in key for key in found)
    assert any("mi-other" in key for key in found)


def test_missing_action_or_no_instances_does_not_name_identity():
    assert not _run(actions=())
    assert not _run(children=False, status="empty")
    assert not _run(mode="Flexible")


def test_instance_scoped_deny_blocks_parent_grant():
    assert not _run(denied=True)


def test_unavailable_instance_inventory_does_not_name_a_definite_identity():
    found = _run(children=False, status="not_collected")
    assert found and all(confidence == "unknown" for confidence in found.values())
