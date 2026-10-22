"""Federated credential write must bind to an exact UAMI child."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-managedidentity-federated-credential-write"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/target"
OTHER = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other"
ACTION = "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write"


def _run(scope, *, existing=0):
    identity = [{"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                 "properties": {"principalId": "mi-target"}},
                {"id": OTHER, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                 "properties": {"principalId": "mi-other"}}]
    credentials = [{"id": f"{UAMI}/federatedIdentityCredentials/cred{i:02d}"}
                   for i in range(existing)]
    snap = az(assignments=[("u-alice", "User", scope, "role-fic")],
              roles={"role-fic": ([ACTION], [])},
              extra=[("managed_identity", SUB, identity),
                     ("managed_identity_federated_credential", UAMI, credentials)])
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_parent_grant_can_create_or_replace_fic_on_exact_uami():
    assert validate_entry(ENTRY)[0] == []
    assert _run(UAMI).get("mi-target") == "conditional"
    assert _run(UAMI, existing=20).get("mi-target") == "conditional"
    assert _run(UAMI).get("mi-other") != "conditional"


def test_existing_child_grant_is_detected_but_unrelated_uami_is_not():
    assert _run(f"{UAMI}/federatedIdentityCredentials/cred00", existing=1).get("mi-target") == "conditional"
    assert _run(OTHER).get("mi-target") != "conditional"
    assert _run(f"{OTHER}/federatedIdentityCredentials/cred00", existing=1).get("mi-target") != "conditional"
