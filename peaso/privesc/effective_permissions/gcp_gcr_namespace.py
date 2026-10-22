"""Join a missing redirected gcr.io repository to one tagged workload image."""
from __future__ import annotations

from . import inventory_status, items


HOSTS = {"gcr.io": "us", "us.gcr.io": "us", "eu.gcr.io": "europe",
         "asia.gcr.io": "asia"}
REDIRECTED = {"REDIRECTION_FROM_GCR_IO_ENABLED",
              "REDIRECTION_FROM_GCR_IO_ENABLED_AND_COPYING"}


def _image(image):
    if not isinstance(image, str) or "@" in image:
        return None
    parts = image.split("/", 2)
    if len(parts) != 3 or parts[0] not in HOSTS or not parts[1] or not parts[2]:
        return None
    if ":" in parts[2] and (not parts[2].rsplit(":", 1)[-1] or "/" in parts[2].rsplit(":", 1)[-1]):
        return None
    return parts[0], parts[1], parts[2]


def _images(kind, item):
    template = item.get("template")
    if kind == "cloudrun_job":
        template = template.get("template") if isinstance(template, dict) else None
    if not isinstance(template, dict):
        return ()
    containers = template.get("containers")
    if not isinstance(containers, list):
        return ()
    return tuple(container.get("image") for container in containers if isinstance(container, dict))


def _covered_location(snap, project, location):
    metadata = snap.get("metadata") or {}
    skipped = (metadata.get("regional_policy_skips") or {}).get("artifactregistry", {}).get(project, ())
    if location in skipped:
        return False
    selection = metadata.get("artifactregistry_location_selection")
    mode = metadata.get("artifactregistry_location_mode")
    return mode == "discovered" or (mode == "selected" and
                                    isinstance(selection, list) and location in selection)


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    snap = model.snapshot
    repo_status = {model._norm_scope(s): st for s, st in
                   inventory_status(snap, "artifact_repository").items()}
    repos = {}
    for scope, item in items(snap, "artifact_repository"):
        repos.setdefault(model._norm_scope(scope), set()).add(model._norm_scope(item.get("name")))
    facts = {}
    for scope, item in items(snap, "gcp_v4_workload_facts"):
        project = model._norm_scope(scope)
        if item.get("scope") == project and item.get("name") == project:
            facts.setdefault(project, []).append(item)
    consumers = {}
    for kind in ("cloudrun_service", "cloudrun_job"):
        for project, records in ((model.run_services_by_project if kind == "cloudrun_service"
                                  else model.run_jobs_by_project).items()):
            for _, email, item in records:
                if not isinstance(email, str):
                    continue
                for image in _images(kind, item):
                    parsed = _image(image)
                    if parsed:
                        host, image_project, _ = parsed
                        repo_project = model._norm_scope(f"projects/{image_project}")
                        consumers.setdefault(email, []).append((repo_project, host, image, kind))
    out = {}
    for tid, target in candidates.items():
        if target.attrs.get("disabled") is True:
            continue
        email = target.attrs.get("email")
        paths = consumers.get(email, ())
        unresolved = False
        for project, host, image, kind in paths:
            location = HOSTS[host]
            repo = f"{project}/locations/{location}/repositories/{host}"
            if not _covered_location(snap, project, location) or repo_status.get(project) not in ("collected", "empty"):
                unresolved = True
                continue
            if repo in repos.get(project, ()):
                continue
            project_facts = facts.get(project, ())
            if len(project_facts) != 1:
                unresolved = True
                continue
            artifact = project_facts[0].get("artifact_registry")
            if (not isinstance(artifact, dict) or
                    artifact.get("settings_status") not in ("collected", "empty")):
                unresolved = True
                continue
            state = artifact.get("redirection_state")
            if state not in REDIRECTED:
                if state not in ("REDIRECTION_FROM_GCR_IO_DISABLED",):
                    unresolved = True
                continue
            parent = f"{project}/locations/{location}"
            model.parents.setdefault(parent, project)
            model.parents.setdefault(repo, parent)
            create = model.check(source, {"action": "artifactregistry.repositories.create"}, parent)
            upload = model.check(source, {"action": "artifactregistry.repositories.uploadArtifacts"}, repo)
            if not create or not upload:
                continue
            if create.confidence == "unknown" or upload.confidence == "unknown":
                unresolved = True
                continue
            # A future deployment or execution must fetch this mutable image
            # reference after an attacker push. This is a conditional edge.
            out[tid] = ("conditional", f"missing_redirected_{host}_repo_tagged_{kind}_consumer")
            break
        if tid not in out and unresolved:
            out[tid] = ("unknown", "gcr_namespace_or_consumer_coverage_unresolved")
    return out
