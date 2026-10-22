"""Spring Apps UAMI path requires one writable app and exact identity assignment."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, _uami, az


TECHNIQUE = "azure-springapps-app-write-user-assigned-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
SERVICE = RG + "/providers/Microsoft.AppPlatform/Spring/one"
OTHER = RG + "/providers/Microsoft.AppPlatform/Spring/other"
APP = SERVICE + "/apps/product"
DEPLOYMENT = APP + "/deployments/production"
UAMI = _uami("spring-mi", "mi-spring")
ROLE_IDS = [f"{i:08d}-0000-0000-0000-000000000002" for i in range(3)]
ACTIONS = ["Microsoft.AppPlatform/Spring/apps/write",
           "Microsoft.AppPlatform/Spring/apps/deployments/write",
           "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"]


def _run(scopes, *, graph=True, native=False, children=True):
    roles = {rid: ([action], []) for rid, action in zip(ROLE_IDS, ACTIONS)}
    assignments = [("u-alice", "User", scope, rid) for rid, scope in zip(ROLE_IDS, scopes)]
    resources = [UAMI, {"id": OTHER, "type": "Microsoft.AppPlatform/Spring"}]
    if children:
        resources.extend([{"id": APP, "type": "Microsoft.AppPlatform/Spring/apps"},
                          {"id": DEPLOYMENT, "type": "Microsoft.AppPlatform/Spring/apps/deployments"}])
    if graph:
        resources.append({"id": SERVICE, "type": "Microsoft.AppPlatform/Spring"})
    extra = [("spring_cloud_service", SUB, [{"id": SERVICE,
              "type": "Microsoft.AppPlatform/Spring"}], "collected")] if native else []
    snap = az(assignments, roles=roles, graph=resources, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_same_app_and_exact_uami():
    assert _run([APP, DEPLOYMENT, UAMI["id"]]) == {"mi-spring": "conditional"}
    assert _run([SERVICE, SERVICE, UAMI["id"]]) == {"mi-spring": "conditional"}
    assert _run([APP, DEPLOYMENT, UAMI["id"]], graph=False, native=True) == {"mi-spring": "conditional"}
    assert _run([APP, DEPLOYMENT, UAMI["id"]], children=False) == {"mi-spring": "conditional"}


def test_unjoined_or_missing_permissions_cannot_name_identity():
    assert not _run([OTHER, DEPLOYMENT, UAMI["id"]])
    assert not _run([APP, OTHER, UAMI["id"]])
    assert not _run([APP, DEPLOYMENT, RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other"])
    assert not _run([APP, DEPLOYMENT, UAMI["id"]], graph=False)
