"""Build and rollout must meet on one inventoried App Hosting backend and SA."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
EMAIL = "runner@p1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + EMAIL
BACKEND = PROJECT + "/locations/us-central1/backends/web"
OTHER = PROJECT + "/locations/us-central1/backends/other"
ENTRY = next(e for e in privesc.catalog()["entries"]
             if e["id"] == "gcp-firebaseapphosting-build-rollout-existing-backend")
BUILD = "firebaseapphosting.builds.create"
ROLLOUT = "firebaseapphosting.rollouts.create"


def paths(*, backends=None, inventory="collected", permissions=(BUILD, ROLLOUT),
          runner=True, disabled=False, split=False, cross_project=False):
    home = "projects/p2" if cross_project else PROJECT
    email = "runner@p2.iam.gserviceaccount.com" if cross_project else EMAIL
    target = "serviceAccount:" + email
    if backends is None:
        backends = [{"name": BACKEND, "serviceAccount": email}]
    deploy_role = {"name": "projects/p1/roles/apphostingDeployer",
                   "includedPermissions": list(permissions)}
    bindings = [{"role": deploy_role["name"], "members": [SOURCE]}]
    roles = [deploy_role, {"name": "roles/firebaseapphosting.computeRunner",
                           "includedPermissions": ["artifactregistry.repositories.downloadArtifacts"]}]
    if split:
        roles += [{"name": "projects/p1/roles/buildOnly", "includedPermissions": [BUILD]},
                  {"name": "projects/p1/roles/rolloutOnly", "includedPermissions": [ROLLOUT]}]
        bindings = [
            {"role": "projects/p1/roles/buildOnly", "members": [SOURCE],
             "condition": {"title": "build", "expression": f'resource.name == "{BACKEND}"'}},
            {"role": "projects/p1/roles/rolloutOnly", "members": [SOURCE],
             "condition": {"title": "rollout", "expression": f'resource.name == "{OTHER}"'}},
        ]
    if runner:
        bindings.append({"role": "roles/firebaseapphosting.computeRunner", "members": [target]})
    rows = [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123"}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": bindings}]),
        ("iam_role", PROJECT, roles),
        ("service_account", home, [{"email": email, "projectId": home.split('/')[1],
                                    "disabled": disabled}]),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("firebase_apphosting_backend", PROJECT, backends, inventory),
    ]
    if cross_project:
        rows.append(("project", home, [{"projectId": "p2", "name": "projects/456"}]))
        rows.append(("iam_deny_policy", home, [], "empty"))
    snap = snapshot("gcp", rows)
    return {tid: grant.confidence for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_exact_existing_backend_reaches_recorded_service_account():
    assert paths().get(TARGET) == "conditional"
    assert paths(cross_project=True).get("serviceAccount:runner@p2.iam.gserviceaccount.com") == "conditional"


def test_no_backend_or_no_complete_permission_pair_emits_no_target():
    assert TARGET not in paths(backends=[])
    assert TARGET not in paths(backends=[{"name": BACKEND, "serviceAccount": EMAIL,
                                         "deleteTime": "2026-10-01T00:00:00Z"}])
    assert TARGET not in paths(backends=[{"name": BACKEND, "serviceAccount": EMAIL,
                                         "reconciling": True}])
    assert TARGET not in paths(permissions=(BUILD,))
    assert TARGET not in paths(permissions=(ROLLOUT,))
    assert TARGET not in paths(backends=[{"name": BACKEND, "serviceAccount": EMAIL},
                                         {"name": OTHER, "serviceAccount": EMAIL}], split=True)
    assert TARGET not in paths(disabled=True)
    assert "unknown" in paths(runner=False).values()
    assert "unknown" in paths(backends=[], inventory="partial").values()


def test_ambiguous_or_wrong_service_account_binding_does_not_create_edge():
    assert TARGET not in paths(backends=[{"name": BACKEND, "serviceAccount": EMAIL},
                                         {"name": BACKEND, "serviceAccount": "other@p1.iam.gserviceaccount.com"}])
    assert TARGET not in paths(backends=[{"name": BACKEND,
                                         "serviceAccount": "other@p1.iam.gserviceaccount.com"}])
