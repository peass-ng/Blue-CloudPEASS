"""VM UAMI assignment requires one real VM and a usable guest route there."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, _uami, az


TECHNIQUE = "azure-vm-assign-user-assigned-identity-existing"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VM = RG + "/providers/Microsoft.Compute/virtualMachines/one"
OTHER = RG + "/providers/Microsoft.Compute/virtualMachines/other"
UAMI = _uami("high", "mi-high")
WRITE = "Microsoft.Compute/virtualMachines/write"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
RUN = "Microsoft.Compute/virtualMachines/runCommand/action"
MANAGED = "Microsoft.Compute/virtualMachines/runCommands/write"
EXTENSION = "Microsoft.Compute/virtualMachines/extensions/write"
START = "Microsoft.Compute/virtualMachines/start/action"
LOGIN = "Microsoft.Compute/virtualMachines/login/action"
ROLE_IDS = [f"{i:08d}-0000-0000-0000-000000000005" for i in range(5)]


def _run(vm_scope, route_scope, route=RUN, *, power="running", start=False, login_extension=False,
         native=True, attached=False):
    actions = [ASSIGN, WRITE, route] + ([START] if start else [])
    scopes = [UAMI["id"], vm_scope, route_scope] + ([VM] if start else [])
    roles = {rid: (([], [action]) if action == LOGIN else ([action], []))
             for rid, action in zip(ROLE_IDS, actions)}
    assignments = [("u-alice", "User", scope, rid) for rid, scope in zip(ROLE_IDS, scopes)]
    identity = {"principalId": "mi-system"}
    if attached:
        identity["userAssignedIdentities"] = {UAMI["id"]: {"principalId": "mi-high"}}
    vm = {"id": VM, "type": "Microsoft.Compute/virtualMachines", "identity": identity,
          "properties": {"instanceView": {"statuses": [{"code": "PowerState/" + power}]}}}
    if login_extension:
        vm["resources"] = [{"id": VM + "/extensions/aad",
                            "type": "Microsoft.Compute/virtualMachines/extensions",
                            "properties": {"type": "AADSSHLoginForLinux", "provisioningState": "Succeeded"}}]
    graph = [UAMI]
    extra = [("vm", SUB, [vm], "collected")] if native else []
    if not native:
        graph.append(vm)
    snap = az(assignments, roles=roles, graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_same_vm_direct_run_routes_and_exact_uami():
    assert _run(VM, VM) == {"mi-high": "conditional"}
    assert _run(VM, VM + "/runCommands/job", MANAGED) == {"mi-high": "conditional"}
    assert _run(VM, VM + "/extensions/script", EXTENSION) == {"mi-high": "conditional"}
    assert _run(VM, VM, native=False) == {"mi-high": "conditional"}
    assert not _run(OTHER, VM)
    assert not _run(VM, OTHER)
    assert not _run(VM, VM, attached=True)


def test_stopped_vm_needs_start_and_login_needs_extension():
    assert not _run(VM, VM, power="deallocated")
    assert _run(VM, VM, power="deallocated", start=True) == {"mi-high": "conditional"}
    assert not _run(VM, VM, route=LOGIN)
    assert _run(VM, VM, route=LOGIN, login_extension=True) == {"mi-high": "conditional"}
