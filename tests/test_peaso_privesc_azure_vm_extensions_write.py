"""VM extension grants must join the same VM and an executable guest route."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TECHNIQUE = "azure-vm-extensions-write"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VM = RG + "/providers/Microsoft.Compute/virtualMachines/one"
OTHER = RG + "/providers/Microsoft.Compute/virtualMachines/other"
CHILD = VM + "/extensions/CustomScript"
OTHER_CHILD = OTHER + "/extensions/CustomScript"
WRITE = "Microsoft.Compute/virtualMachines/extensions/write"
START = "Microsoft.Compute/virtualMachines/start/action"


def _run(grants, *, power="PowerState/running", include_vm=True, existing_handler=None,
         include_unknown=False):
    vm = {"id": VM, "type": "Microsoft.Compute/virtualMachines",
          "identity": {"principalId": "mi-vm"},
          "properties": {"instanceView": {"statuses": [{"code": power}]}}}
    roles = {f"{i:08d}-0000-0000-0000-000000000008": ([action], [])
             for i, (action, _) in enumerate(grants)}
    assignments = [("u-alice", "User", scope, rid)
                   for rid, (_, scope) in zip(roles, grants)]
    extra = [("vm", SUB, [vm], "collected")] if include_vm else []
    graph = ([{"id": CHILD, "type": "Microsoft.Compute/virtualMachines/extensions",
              "properties": {"type": existing_handler}}] if existing_handler else [])
    snap = az(assignments, roles=roles, graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY], include_unknown=include_unknown),
                   "u-alice", TECHNIQUE)


def test_parent_and_exact_child_grants_reach_the_same_vm_identity():
    assert _run([(WRITE, VM)]) == {"mi-vm": "conditional"}
    assert _run([(WRITE, CHILD)]) == {"mi-vm": "conditional"}


def test_unrelated_or_missing_vm_cannot_complete_route():
    assert not _run([(WRITE, OTHER_CHILD)])
    assert not _run([(WRITE, CHILD)], include_vm=False)


def test_existing_monitoring_extension_cannot_run_supplied_code():
    assert not _run([(WRITE, CHILD)], existing_handler="AzureMonitorLinuxAgent")
    assert _run([(WRITE, CHILD)], existing_handler="CustomScript") == {"mi-vm": "conditional"}
    assert _run([(WRITE, VM)], existing_handler="AzureMonitorLinuxAgent") == {"mi-vm": "conditional"}


def test_unclassified_existing_handler_remains_unresolved():
    assert not _run([(WRITE, CHILD)], existing_handler="CustomHandler")
    assert "unknown" in _run([(WRITE, CHILD)], existing_handler="CustomHandler",
                             include_unknown=True).values()


def test_stopped_vm_needs_start_permission_on_that_vm():
    assert not _run([(WRITE, CHILD)], power="PowerState/deallocated")
    assert _run([(WRITE, CHILD), (START, VM)], power="PowerState/deallocated") == {"mi-vm": "conditional"}
    assert not _run([(WRITE, CHILD), (START, OTHER)], power="PowerState/deallocated")
