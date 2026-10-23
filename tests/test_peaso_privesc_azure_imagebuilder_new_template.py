"""Image Builder needs one runnable template and a two-hop UAMI assignment."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-imagebuilder-template-create-via-template-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
OTHER_RG = f"{SUB}/resourceGroups/other"
TEMPLATE = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/template"
BUILD = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/build"
WRITE = "Microsoft.VirtualMachineImages/imageTemplates/write"
RUN = "Microsoft.VirtualMachineImages/imageTemplates/run/action"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
CREATE_RG = "Microsoft.Resources/subscriptions/resourceGroups/write"


def _run(*, write_scope=RG, run_scope=RG, source_assign=TEMPLATE, hop_assign=BUILD,
         collect_groups=True, can_create_rg=False):
    assignments = [("u-alice", "User", write_scope, "role-write"),
                   ("u-alice", "User", run_scope, "role-run"),
                   ("u-alice", "User", source_assign, "role-assign"),
                   ("mi-template", "ServicePrincipal", hop_assign, "role-assign")]
    if can_create_rg:
        assignments.append(("u-alice", "User", SUB, "role-create-rg"))
    identities = [{"id": TEMPLATE, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                   "properties": {"principalId": "mi-template"}},
                  {"id": BUILD, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                   "properties": {"principalId": "mi-build"}}]
    groups = [{"id": RG}, {"id": OTHER_RG}] if collect_groups else []
    snap = az(assignments=assignments,
              roles={"role-write": ([WRITE], []), "role-run": ([RUN], []),
                     "role-assign": ([ASSIGN], []), "role-create-rg": ([CREATE_RG], [])},
              extra=[("managed_identity", SUB, identities), ("resource_group", SUB, groups)])
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_same_new_template_and_two_identity_grants_reach_build_uami():
    assert validate_entry(ENTRY)[0] == []
    assert _run().get("mi-build") == "conditional"
    assert _run(write_scope=SUB, run_scope=RG).get("mi-build") == "conditional"
    assert _run(write_scope=SUB, run_scope=SUB, collect_groups=False,
                can_create_rg=True).get("mi-build") == "conditional"
    assert _run(hop_assign=TEMPLATE).get("mi-template") == "conditional"


def test_split_template_permissions_or_missing_identity_hop_do_not_reach_build_uami():
    assert _run(write_scope=RG, run_scope=OTHER_RG).get("mi-build") != "conditional"
    assert _run(source_assign=BUILD).get("mi-build") != "conditional"
    assert _run(hop_assign=TEMPLATE).get("mi-build") != "conditional"
    assert _run(collect_groups=False).get("mi-build") != "conditional"
