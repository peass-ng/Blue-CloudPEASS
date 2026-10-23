"""App Engine direct API deployment has an exact app, staging, and runtime path."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
TARGET = "runtime@p1.iam.gserviceaccount.com"
REPO = PROJECT + "/locations/us/repositories/gcr.io"
TECHNIQUE = "gcp-appengine-versions-create-actas"


def snapshot(*, app=True, stage=True, upload=True, build=False, other_project_stage=False):
    source_permissions = ["appengine.versions.create", "iam.serviceAccounts.actAs"]
    if stage:
        source_permissions.append("storage.objects.create")
    if build:
        source_permissions.append("cloudbuild.builds.create")

    def row(kind, items, scope=PROJECT, status="collected"):
        return {"type": kind, "scope": scope, "service": kind, "items": items,
                "status": status, "error": None}

    cols = [
        row("project", [{"projectId": "p1", "name": "projects/123"}]),
        row("iam_role", [{"name": PROJECT + "/roles/deployer", "includedPermissions": source_permissions},
                         {"name": PROJECT + "/roles/runtime", "includedPermissions":
                          ["artifactregistry.repositories.uploadArtifacts"] if upload else []}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": PROJECT + "/roles/deployer", "members": ["user:source@example.com"]},
            {"role": PROJECT + "/roles/runtime", "members": ["serviceAccount:" + TARGET]},
        ]}]),
        row("service_account", [{"email": TARGET, "projectId": "p1", "iamPolicy": {"bindings": []}}]),
        row("app_engine_application", [{"name": "apps/p1", "codeBucket": "staging.p1.appspot.com", "gcrDomain": "gcr.io",
                                        "servingStatus": "SERVING"}] if app else [], status="collected" if app else "empty"),
        row("artifact_repository", [{"name": REPO, "format": "DOCKER"}]),
        row("iam_deny_policy", [], status="empty"),
        row("org_policy_effective", [], status="empty"),
    ]
    if other_project_stage:
        cols[1]["items"][0]["includedPermissions"].remove("storage.objects.create")
        cols.append(row("iam_role", [{"name": "projects/p2/roles/stager",
                                     "includedPermissions": ["storage.objects.create"]}], scope="projects/p2"))
        cols.append(row("iam_policy", [{"name": "projects/p2", "bindings": [
            {"role": "projects/p2/roles/stager", "members": ["user:source@example.com"]}]}], scope="projects/p2"))
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "collections": cols, "metadata": {}}


def outcome(snap):
    model = GcpModel(snap)
    source = model.principals["user:source@example.com"]
    target = model.sas["serviceAccount:" + TARGET]
    direct = model.selector("gcp_appengine_deploy_path", True, {target.id: target}, source)
    entry, = [e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE]
    reaches = [r for r in Evaluator(model, [entry]).run() if r.source.id == source.id]
    return direct.get(target.id), reaches


def test_direct_api_path_without_caller_cloudbuild_permission():
    verdict, reaches = outcome(snapshot(build=False))
    assert verdict[0] == "conditional"
    assert reaches


def test_missing_app_cannot_deploy_version():
    assert outcome(snapshot(app=False)) == (None, [])


def test_unproven_staging_or_runtime_upload_stays_unknown():
    assert outcome(snapshot(stage=False))[0][0] == "unknown"
    assert outcome(snapshot(upload=False))[0][0] == "unknown"
    assert outcome(snapshot(other_project_stage=True))[0][0] == "unknown"


def test_missing_app_inventory_stays_unknown():
    snap = snapshot()
    app = next(c for c in snap["collections"] if c["type"] == "app_engine_application")
    app["status"] = "denied"
    app["items"] = []
    assert outcome(snap)[0][0] == "unknown"


def test_unrelated_repository_or_disabled_app_cannot_prove_deployment():
    snap = snapshot()
    repo = next(c for c in snap["collections"] if c["type"] == "artifact_repository")
    repo["items"][0]["name"] = PROJECT + "/locations/us-central1/repositories/other"
    assert outcome(snap)[0][0] == "unknown"
    snap = snapshot()
    app = next(c for c in snap["collections"] if c["type"] == "app_engine_application")
    app["items"][0]["servingStatus"] = "SYSTEM_DISABLED"
    assert outcome(snap) == (None, [])


def test_unrelated_bucket_ownership_stays_unresolved():
    snap = snapshot()
    snap["collections"].append({"type": "bucket", "scope": "projects/p2", "service": "bucket",
                                "items": [{"name": "staging.p1.appspot.com"}],
                                "status": "collected", "error": None})
    assert outcome(snap)[0][0] == "unknown"


def test_missing_actas_does_not_reach_runtime_account():
    snap = snapshot()
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")
    role["items"][0]["includedPermissions"].remove("iam.serviceAccounts.actAs")
    assert outcome(snap)[1] == []


def test_archived_unreviewed_contract_remains_held():
    from peaso.privesc.versioned_catalog import _verified_prior
    archived, _ = _verified_prior()
    old = archived[TECHNIQUE]
    model = GcpModel(snapshot())
    assert Evaluator(model, [old]).run() == []
    assert any(row["status"] == "unresolved" and TECHNIQUE in row["reason"]
               for row in model.coverage)


def legacy_snapshot(*, visible=True, enforced=False, status="collected", rules=None):
    snap = snapshot()
    legacy = "p1@appspot.gserviceaccount.com"
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")
    role["items"][0]["includedPermissions"].remove("iam.serviceAccounts.actAs")
    policy = next(c for c in snap["collections"] if c["type"] == "iam_policy")
    policy["items"][0]["bindings"][1]["members"] = ["serviceAccount:" + legacy]
    account = next(c for c in snap["collections"] if c["type"] == "service_account")
    account["items"][0]["email"] = legacy
    spec = {"rules": [{"enforce": enforced}] if rules is None else rules}
    snap["collections"].append({"type": "app_engine_legacy_constraint", "scope": PROJECT,
        "service": "orgpolicy", "status": status,
        "items": [{"name": PROJECT + "/constraints/appengine.enforceServiceAccountActAsCheck",
                   "visible": visible, "constraintDefault": "ALLOW",
                   "effectivePolicy": {"name": PROJECT + "/policies/appengine.enforceServiceAccountActAsCheck",
                                       "spec": spec}}] if status == "collected" else [],
        "error": None})
    snap["collections"].append({"type": "app_engine_application_identity", "scope": PROJECT,
        "service": "appengine", "status": "collected",
        "items": [{"name": "apps/p1", "serviceAccount": legacy,
                   "_field_mask": "name,serviceAccount"}], "error": None})
    return snap


def legacy_outcome(snap):
    model = GcpModel(snap)
    source = model.principals["user:source@example.com"]
    target = model.sas["serviceAccount:p1@appspot.gserviceaccount.com"]
    direct = model.selector("gcp_appengine_legacy_actas_unenforced", True,
                            {target.id: target}, source)
    entry, = [e for e in privesc.catalog()["entries"] if e["id"] ==
              "gcp-appengine-versions-create-legacy-default-sa-no-actas"]
    reaches = [r for r in Evaluator(model, [entry]).run() if r.source.id == source.id]
    return direct.get(target.id), reaches


def test_legacy_unenforced_default_account_path_is_conditional():
    verdict, reaches = legacy_outcome(legacy_snapshot())
    assert verdict is None
    assert reaches


def test_enforced_or_modern_app_engine_has_no_legacy_path():
    assert legacy_outcome(legacy_snapshot(enforced=True)) == (None, [])
    assert legacy_outcome(legacy_snapshot(visible=False)) == (None, [])


def test_legacy_policy_denied_or_ambiguous_stays_unknown():
    assert legacy_outcome(legacy_snapshot(status="denied"))[0][0] == "unknown"
    assert legacy_outcome(legacy_snapshot(rules=[{"condition": {"expression": "x"},
                                                   "enforce": False}]))[0][0] == "unknown"


def test_legacy_default_constraint_can_inherit_allow_default():
    verdict, reaches = legacy_outcome(legacy_snapshot(rules=[]))
    assert verdict is None
    assert reaches


def test_user_managed_app_default_cannot_use_legacy_exception():
    snap = legacy_snapshot()
    identity = next(c for c in snap["collections"] if c["type"] == "app_engine_application_identity")
    identity["items"][0]["serviceAccount"] = "managed@p1.iam.gserviceaccount.com"
    assert legacy_outcome(snap) == (None, [])


def test_legacy_policy_or_app_identity_from_another_project_stays_unknown():
    snap = legacy_snapshot()
    constraint = next(c for c in snap["collections"] if c["type"] == "app_engine_legacy_constraint")
    constraint["items"][0]["effectivePolicy"]["name"] = (
        "projects/p2/policies/appengine.enforceServiceAccountActAsCheck")
    assert legacy_outcome(snap)[0][0] == "unknown"
    snap = legacy_snapshot()
    identity = next(c for c in snap["collections"] if c["type"] == "app_engine_application_identity")
    identity["items"][0]["name"] = "apps/p2"
    assert legacy_outcome(snap)[0][0] == "unknown"
