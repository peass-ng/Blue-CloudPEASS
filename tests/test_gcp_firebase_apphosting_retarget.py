"""A Firebase App Hosting identity pivot needs one exact existing backend."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
EMAIL = "target@p1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + EMAIL
BACKEND = PROJECT + "/locations/us-central1/backends/web"
ENTRY = next(e for e in privesc.catalog()["entries"]
             if e["id"] == "gcp-firebaseapphosting-backends-update-actas")
PERMS = ("firebaseapphosting.backends.update", "firebaseapphosting.builds.create",
         "firebaseapphosting.rollouts.create", "iam.serviceAccounts.actAs")


def paths(*, backend=True, backend_status="collected", permissions=PERMS,
          deleted=False, reconciling=False, sa_disabled=False, runner_ready=True,
          backend_condition=None):
    role = {"name": "projects/p1/roles/apphostingDeployer",
            "includedPermissions": [p for p in permissions if p != "iam.serviceAccounts.actAs"]
            if backend_condition else list(permissions)}
    bindings = [{"role": role["name"], "members": [SOURCE],
                 **({"condition": {"title": "backend", "expression": backend_condition}}
                    if backend_condition else {})}]
    if backend_condition and "iam.serviceAccounts.actAs" in permissions:
        bindings.append({"role": "roles/iam.serviceAccountUser", "members": [SOURCE]})
    if runner_ready:
        bindings.append({"role": "roles/firebaseapphosting.computeRunner", "members": [TARGET]})
    backend_items = ([{"name": BACKEND, "serviceAccount": "original@p1.iam.gserviceaccount.com",
                       **({"deleteTime": "2026-10-01T00:00:00Z"} if deleted else {}),
                       **({"reconciling": True} if reconciling else {})}]
                     if backend else [])
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123"}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": bindings}]),
        ("iam_role", PROJECT, [role, {"name": "roles/firebaseapphosting.computeRunner",
                               "includedPermissions": ["artifactregistry.repositories.downloadArtifacts"]}]),
        ("service_account", PROJECT, [{"email": EMAIL, "projectId": "p1",
                                       "disabled": sa_disabled}]),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("firebase_apphosting_backend", PROJECT, backend_items, backend_status),
    ])
    return {tid: grant.confidence for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_existing_backend_and_exact_permissions_reach_target_conditionally():
    assert paths().get(TARGET) == "conditional"


def test_missing_deleted_or_reconciling_backend_is_not_a_confirmed_route():
    assert TARGET not in paths(backend=False)
    assert TARGET not in paths(deleted=True)
    assert "unknown" in paths(reconciling=True).values()
    assert "unknown" in paths(backend=False, backend_status="partial").values()
    assert "unknown" in paths(runner_ready=False).values()


def test_every_exact_grant_is_required():
    for permission in PERMS:
        assert TARGET not in paths(permissions=tuple(p for p in PERMS if p != permission))
    assert TARGET not in paths(sa_disabled=True)
    assert paths(backend_condition=f'resource.name == "{BACKEND}"').get(TARGET) == "conditional"
    assert TARGET not in paths(backend_condition='resource.name == "projects/p1/locations/us-east1/backends/other"')
