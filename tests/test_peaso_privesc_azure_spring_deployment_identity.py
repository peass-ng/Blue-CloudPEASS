"""Deployment grants must be children of the app carrying the identity."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, _uami, az


TECHNIQUE = "azure-springapps-deployment-write-app-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
SERVICE = RG + "/providers/Microsoft.AppPlatform/Spring/one"
APP = SERVICE + "/apps/product"
OTHER = SERVICE + "/apps/other"
DEPLOYMENT = APP + "/deployments/production"
OTHER_DEPLOYMENT = OTHER + "/deployments/production"
UAMI = _uami("shared", "mi-shared")
ROLE = "12345678-0000-0000-0000-000000000003"
ACTION = "Microsoft.AppPlatform/Spring/apps/deployments/write"


def _run(scope, *, app=True, deployment=True, user_assigned=True):
    identity = ({"userAssignedIdentities": {UAMI["id"]: {"principalId": "mi-shared"}}}
                if user_assigned else {"principalId": "mi-app"})
    graph = [UAMI, {"id": SERVICE, "type": "Microsoft.AppPlatform/Spring"},
             {"id": OTHER, "type": "Microsoft.AppPlatform/Spring/apps"}]
    if app:
        graph.append({"id": APP, "type": "Microsoft.AppPlatform/Spring/apps", "identity": identity})
    if deployment:
        graph.append({"id": DEPLOYMENT, "type": "Microsoft.AppPlatform/Spring/apps/deployments"})
    snap = az([("u-alice", "User", scope, ROLE)], roles={ROLE: ([ACTION], [])}, graph=graph)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_exact_deployment_and_parent_scope_reach_attached_identity():
    assert _run(DEPLOYMENT) == {"mi-shared": "conditional"}
    assert _run(APP) == {"mi-shared": "conditional"}
    assert _run(SERVICE, user_assigned=False) == {"mi-app": "conditional"}
    assert _run(DEPLOYMENT, deployment=False) == {"mi-shared": "conditional"}


def test_other_app_and_missing_attachment_do_not_reach_identity():
    assert not _run(OTHER_DEPLOYMENT)
    assert not _run(OTHER)
    assert not _run(DEPLOYMENT, app=False)
