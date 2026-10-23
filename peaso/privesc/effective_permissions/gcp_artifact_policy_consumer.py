"""Bound repository policy control to a mutable image and its runtime account."""
from __future__ import annotations

import re

from . import inventory_status, items
from .gcp_gcr_namespace import HOSTS, _images


PKG = re.compile(r"([a-z][a-z0-9-]*)-docker\.pkg\.dev/([^/]+)/([^/]+)/(.+)\Z")
REPO = re.compile(r"projects/[^/]+/locations/[^/]+/repositories/[^/]+\Z")
MEMBER_CONSTRAINTS = {"iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"}


def _repository_for_image(model, image):
    if not isinstance(image, str) or "@" in image:
        return None
    parts = image.split("/", 2)
    if len(parts) == 3 and parts[0] in HOSTS and parts[1] and parts[2]:
        if ":" in parts[2] and not parts[2].rsplit(":", 1)[-1]:
            return None
        project = model._norm_scope("projects/" + parts[1])
        return f"{project}/locations/{HOSTS[parts[0]]}/repositories/{parts[0]}"
    match = PKG.fullmatch(image)
    if match:
        location, project_id, repository, rest = match.groups()
        if rest and "/" not in repository and (":" not in rest or rest.rsplit(":", 1)[-1]):
            project = model._norm_scope("projects/" + project_id)
            return f"{project}/locations/{location}/repositories/{repository}"
    return None


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    snap = model.snapshot
    status = {model._norm_scope(scope): value for scope, value in
              inventory_status(snap, "artifact_repository").items()}
    repos = {}
    for scope, item in items(snap, "artifact_repository"):
        project = model._norm_scope(scope)
        name = model._norm_scope(item.get("name"))
        if REPO.fullmatch(name) and name.startswith(project + "/"):
            repos.setdefault(name, []).append(item)
    constraints = {model._norm_scope(scope) for scope, item in items(snap, "org_policy_effective")
                   if item.get("constraint") in MEMBER_CONSTRAINTS}
    consumer_repos = {}
    for kind, records in (("cloudrun_service", model.run_services_by_project),
                          ("cloudrun_job", model.run_jobs_by_project)):
        for _, workloads in records.items():
            for _, email, item in workloads:
                if not isinstance(email, str):
                    continue
                for image in _images(kind, item):
                    repo = _repository_for_image(model, image)
                    if repo:
                        consumer_repos.setdefault(email, set()).add(repo)
    out = {}
    for tid, target in candidates.items():
        if target.attrs.get("disabled") is True:
            continue
        unresolved = False
        for repo in consumer_repos.get(target.attrs.get("email"), ()):
            project = repo.split("/locations/", 1)[0]
            if status.get(project) not in ("collected", "empty"):
                unresolved = True
                continue
            rows = repos.get(repo, ())
            if len(rows) != 1:
                if not rows:
                    continue
                unresolved = True
                continue
            item = rows[0]
            if item.get("format") != "DOCKER":
                continue
            if (item.get("mode") not in (None, "STANDARD_REPOSITORY") or
                    "remoteRepositoryConfig" in item or "virtualRepositoryConfig" in item):
                continue
            docker = item.get("dockerConfig")
            if isinstance(docker, dict) and docker.get("immutableTags") is True:
                unresolved = True
                continue
            model.parents.setdefault(repo, project)
            policy = model.check(source, {"action": "artifactregistry.repositories.setIamPolicy"}, repo)
            if policy is None:
                continue
            if (policy.confidence == "unknown" or project in constraints or
                    inventory_status(snap, "org_policy_effective").get(project)
                    not in ("collected", "empty")):
                unresolved = True
                continue
            out[tid] = ("conditional", "exact_repository_policy_self_grant_and_tagged_consumer")
            break
        if tid not in out and unresolved:
            out[tid] = ("unknown", "artifact_repository_policy_or_consumer_unresolved")
    return out
