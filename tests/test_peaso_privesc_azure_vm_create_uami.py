"""VM creation with a UAMI joins real network resources and exact rights."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, _uami, az


TECHNIQUE = "azure-vm-create-with-user-assigned-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
OTHER = SUB + "/resourceGroups/other"
NIC = RG + "/providers/Microsoft.Network/networkInterfaces/free"
SUBNET = RG + "/providers/Microsoft.Network/virtualNetworks/network/subnets/app"
UAMI = _uami("target", "mi-target")
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
VM_WRITE = "Microsoft.Compute/virtualMachines/write"
NIC_WRITE = "Microsoft.Network/networkInterfaces/write"
NIC_JOIN = "Microsoft.Network/networkInterfaces/join/action"
SUBNET_JOIN = "Microsoft.Network/virtualNetworks/subnets/join/action"


def _run(actions, *, nic=True, attached=False, subnet=True, nic_configured=True):
    ids = [f"{i:08d}-0000-0000-0000-000000000007" for i in range(len(actions))]
    roles = {rid: ([action], []) for rid, (action, _) in zip(ids, actions)}
    assignments = [("u-alice", "User", scope, rid) for rid, (_, scope) in zip(ids, actions)]
    graph = [UAMI]
    if nic:
        props = {"virtualMachine": {"id": OTHER + "/providers/Microsoft.Compute/virtualMachines/in-use"}} if attached else {}
        if nic_configured:
            props["ipConfigurations"] = [{"properties": {"subnet": {"id": SUBNET}}}]
        graph.append({"id": NIC, "type": "Microsoft.Network/networkInterfaces", "properties": props})
    if subnet:
        graph.append({"id": SUBNET, "type": "Microsoft.Network/virtualNetworks/subnets"})
    extra = [("resource_group", SUB, [{"id": RG}, {"id": OTHER}], "collected")]
    snap = az(assignments, roles=roles, graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_existing_unattached_nic_does_not_require_nic_write_or_subnet_join():
    actions = [(ASSIGN, UAMI["id"]), (VM_WRITE, RG), (NIC_JOIN, NIC)]
    assert _run(actions, subnet=False) == {"mi-target": "conditional"}
    assert not _run(actions, attached=True, subnet=False)
    assert not _run(actions, nic_configured=False, subnet=False)
    assert not _run(actions[:-1], subnet=False)
    assert not _run([(ASSIGN, OTHER + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other"),
                     *actions[1:]], subnet=False)


def test_new_nic_joins_exact_existing_subnet():
    actions = [(ASSIGN, UAMI["id"]), (VM_WRITE, RG), (NIC_WRITE, RG),
               (NIC_JOIN, RG), (SUBNET_JOIN, SUBNET)]
    assert _run(actions, nic=False) == {"mi-target": "conditional"}
    assert not _run(actions, nic=False, subnet=False)
    assert not _run(actions[:-1], nic=False)
    assert _run([(ASSIGN, UAMI["id"]), (VM_WRITE, OTHER),
                 (NIC_WRITE, RG), (NIC_JOIN, RG), (SUBNET_JOIN, SUBNET)], nic=False) == {
                     "mi-target": "conditional"}
    assert not _run([(ASSIGN, UAMI["id"]), (VM_WRITE, SUBNET),
                     (NIC_WRITE, RG), (NIC_JOIN, RG), (SUBNET_JOIN, SUBNET)], nic=False)
