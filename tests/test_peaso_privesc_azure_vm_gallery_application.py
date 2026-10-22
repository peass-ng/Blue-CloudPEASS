"""Gallery application writes must form one deployable VM route."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TECHNIQUE = "azure-vm-gallery-application-install"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
VM = RG + "/providers/Microsoft.Compute/virtualMachines/one"
OTHER_VM = RG + "/providers/Microsoft.Compute/virtualMachines/other"
GALLERY = RG + "/providers/Microsoft.Compute/galleries/gal"
APP = GALLERY + "/applications/app"
NEW_APP = GALLERY + "/applications/peaso-probe"
NEW_GALLERY = RG + "/providers/Microsoft.Compute/galleries/peaso-probe"
VERSION_WRITE = "Microsoft.Compute/galleries/applications/versions/write"
APP_WRITE = "Microsoft.Compute/galleries/applications/write"
GALLERY_WRITE = "Microsoft.Compute/galleries/write"
VM_WRITE = "Microsoft.Compute/virtualMachines/write"
START = "Microsoft.Compute/virtualMachines/start/action"


def _run(grants, *, app=True, gallery=True, vm=True, os_type="Linux", app_os="Linux",
         power="PowerState/running"):
    ids = [f"{i:08d}-0000-0000-0000-000000000009" for i in range(len(grants))]
    roles = {rid: ([action], []) for rid, (action, _) in zip(ids, grants)}
    assignments = [("u-alice", "User", scope, rid)
                   for rid, (_, scope) in zip(ids, grants)]
    graph = []
    if app:
        graph.append({"id": APP, "type": "Microsoft.Compute/galleries/applications",
                      "properties": {"supportedOSType": app_os}})
    if gallery:
        graph.append({"id": GALLERY, "type": "Microsoft.Compute/galleries"})
    extra = [("resource_group", SUB, [{"id": RG}], "collected")]
    if vm:
        extra.append(("vm", SUB, [{"id": VM, "type": "Microsoft.Compute/virtualMachines",
                                  "identity": {"principalId": "mi-vm"},
                                  "properties": {"storageProfile": {"osDisk": {"osType": os_type}},
                                                 "instanceView": {"statuses": [{"code": power}]}}}], "collected"))
    snap = az(assignments, roles=roles, graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_existing_application_version_joins_exact_vm_and_os():
    grants = [(VERSION_WRITE, APP + "/versions/99.0.0"), (VM_WRITE, VM)]
    assert _run(grants) == {"mi-vm": "conditional"}
    assert not _run(grants, app=False, gallery=False)
    assert not _run(grants, vm=False)
    assert not _run(grants, app_os="Windows")
    assert not _run([(VERSION_WRITE, APP + "/versions/99.0.0"), (VM_WRITE, OTHER_VM)])


def test_new_application_requires_definition_and_version_rights():
    grants = [(APP_WRITE, NEW_APP), (VERSION_WRITE, NEW_APP + "/versions/99.0.0"),
              (VM_WRITE, VM)]
    assert _run(grants, app=False) == {"mi-vm": "conditional"}
    assert not _run(grants, app=False, gallery=False)
    assert not _run(grants[1:], app=False)


def test_new_gallery_requires_every_creation_right_and_running_vm():
    grants = [(GALLERY_WRITE, NEW_GALLERY),
              (APP_WRITE, NEW_GALLERY + "/applications/peaso-probe"),
              (VERSION_WRITE, NEW_GALLERY + "/applications/peaso-probe/versions/99.0.0"),
              (VM_WRITE, VM)]
    assert _run(grants, app=False, gallery=False) == {"mi-vm": "conditional"}
    assert not _run(grants[1:], app=False, gallery=False)
    assert not _run(grants, app=False, gallery=False, power="PowerState/deallocated")
    assert _run([*grants, (START, VM)], app=False, gallery=False,
                power="PowerState/deallocated") == {"mi-vm": "conditional"}
