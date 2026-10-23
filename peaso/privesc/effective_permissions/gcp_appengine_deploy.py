"""Bound App Engine version deployment to an existing app and deployable source."""
from __future__ import annotations

import re

from . import inventory_status, items


_GCR_REPOSITORIES = {"gcr.io": ("us", "gcr.io"),
                     "us.gcr.io": ("us", "us.gcr.io"),
                     "eu.gcr.io": ("europe", "eu.gcr.io"),
                     "asia.gcr.io": ("asia", "asia.gcr.io")}


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    snap = model.snapshot
    app_status = {model._norm_scope(s): status for s, status in inventory_status(snap, "app_engine_application").items()}
    repo_status = {model._norm_scope(s): status for s, status in inventory_status(snap, "artifact_repository").items()}
    apps = {}
    for scope, item in items(snap, "app_engine_application"):
        project = model._norm_scope(scope)
        if item.get("name") == "apps/" + project.split("/", 1)[-1]:
            apps.setdefault(project, []).append(item)
    repos = {}
    for scope, item in items(snap, "artifact_repository"):
        project = model._norm_scope(scope)
        name = item.get("name")
        if isinstance(name, str) and re.fullmatch(re.escape(project) + r"/locations/[^/]+/repositories/[^/]+", name):
            model.parents.setdefault(name, project)
            repos.setdefault(project, []).append((name, item))
    out = {}
    for tid, target in candidates.items():
        project = target.scope
        if app_status.get(project) not in ("collected", "empty"):
            out[tid] = ("unknown", "appengine_application_inventory_incomplete")
            continue
        active = [app for app in apps.get(project, ()) if app.get("servingStatus") == "SERVING"]
        if not active:
            if apps.get(project) and any(app.get("servingStatus") not in
                                         ("USER_DISABLED", "SYSTEM_DISABLED") for app in apps[project]):
                out[tid] = ("unknown", "appengine_application_serving_state_unresolved")
            continue
        if len(active) != 1 or not model.check(source, {"action": "appengine.versions.create"}, project):
            out[tid] = ("unknown", "appengine_application_or_create_scope_unresolved")
            continue
        app = active[0]
        # A project-level Storage grant covers the application's own staging
        # bucket. A grant on another bucket/project cannot be paired with it.
        bucket = app.get("codeBucket")
        stage = None
        if isinstance(bucket, str) and bucket and model.bucket_projects.get(bucket, project) == project:
            bucket_resource = f"//storage.googleapis.com/projects/_/buckets/{bucket}"
            model.parents.setdefault(bucket_resource, project)
            stage = model.check(source, {"action": "storage.objects.create"}, bucket_resource)
        # Current Artifact Registry-backed standard deployments need the
        # selected runtime SA to upload the image. A flexible route adds pull
        # permission; standard is enough to establish this technique.
        upload = None
        expected = _GCR_REPOSITORIES.get(app.get("gcrDomain"))
        for repo, item in repos.get(project, ()):
            if expected and not repo.endswith(f"/locations/{expected[0]}/repositories/{expected[1]}"):
                continue
            if not expected:
                continue
            if item.get("format") not in (None, "DOCKER"):
                continue
            grant = model.check(target, {"action": "artifactregistry.repositories.uploadArtifacts"}, repo)
            if grant and grant.confidence != "unknown":
                upload = grant
                break
        if stage and stage.confidence != "unknown" and upload:
            out[tid] = ("conditional", "existing_app_staging_bucket_and_runtime_registry_access")
        else:
            # A pre-staged object, controlled image, uncollected bucket grant,
            # or legacy image path could still be usable; never call it absent.
            out[tid] = ("unknown", "appengine_source_staging_or_runtime_registry_unresolved")
        if repo_status.get(project) not in ("collected", "empty") and out[tid][0] != "conditional":
            out[tid] = ("unknown", "artifact_repository_inventory_incomplete")
    return out


def legacy_selector(model, value, candidates, source):
    """Only the visible and explicitly unenforced legacy constraint waives actAs."""
    if value is not True or source is None:
        return {}
    snap = model.snapshot
    statuses = {model._norm_scope(scope): status for scope, status in
                inventory_status(snap, "app_engine_legacy_constraint").items()}
    records = {}
    for scope, item in items(snap, "app_engine_legacy_constraint"):
        records.setdefault(model._norm_scope(scope), []).append(item)
    identities = {}
    for scope, item in items(snap, "app_engine_application_identity"):
        identities.setdefault(model._norm_scope(scope), []).append(item)
    identity_status = {model._norm_scope(scope): status for scope, status in
                       inventory_status(snap, "app_engine_application_identity").items()}
    out = {}
    for tid, target in candidates.items():
        project = target.scope
        expected = project.split("/", 1)[-1] + "@appspot.gserviceaccount.com"
        if target.attrs.get("email") != expected:
            continue
        if identity_status.get(project) not in ("collected", "empty"):
            out[tid] = ("unknown", "appengine_application_default_identity_not_collected")
            continue
        app_identities = identities.get(project, ())
        if (len(app_identities) != 1 or
                app_identities[0].get("name") != "apps/" + project.split("/", 1)[-1] or
                not isinstance(app_identities[0].get("serviceAccount"), str)):
            out[tid] = ("unknown", "appengine_application_default_identity_unresolved")
            continue
        if app_identities[0]["serviceAccount"] != expected:
            continue
        if model.check(source, {"action": "iam.serviceAccounts.actAs"},
                       target.attrs.get("resource") or f"{project}/serviceAccounts/{expected}"):
            continue
        if statuses.get(project) not in ("collected", "empty"):
            out[tid] = ("unknown", "appengine_legacy_constraint_visibility_not_collected")
            continue
        rows = records.get(project, ())
        if (len(rows) != 1 or
                rows[0].get("name") != f"{project}/constraints/appengine.enforceServiceAccountActAsCheck" or
                rows[0].get("visible") not in (True, False)):
            out[tid] = ("unknown", "appengine_legacy_constraint_visibility_ambiguous")
            continue
        if rows[0]["visible"] is False:
            continue
        policy = rows[0].get("effectivePolicy")
        if (not isinstance(policy, dict) or
                policy.get("name") != f"{project}/policies/appengine.enforceServiceAccountActAsCheck"):
            out[tid] = ("unknown", "appengine_legacy_effective_policy_identity_unresolved")
            continue
        rules = (policy.get("spec") or {}).get("rules")
        if rules == [] and rows[0].get("constraintDefault") in ("ALLOW", "DENY"):
            if rows[0]["constraintDefault"] == "ALLOW":
                out[tid] = None
            continue
        if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
            out[tid] = ("unknown", "appengine_legacy_effective_policy_incomplete")
            continue
        rule = rules[0]
        if "condition" in rule or type(rule.get("enforce")) is not bool:
            out[tid] = ("unknown", "appengine_legacy_effective_policy_conditional")
        elif rule["enforce"] is False:
            out[tid] = None
    return out
