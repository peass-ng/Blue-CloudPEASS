"""Join a writable Docker repository to an exact tagged Cloud Run consumer."""
from __future__ import annotations

from . import inventory_status, items
from .gcp_artifact_policy_consumer import REPO, _repository_for_image
from .gcp_gcr_namespace import HOSTS, REDIRECTED, _images


def _legacy_registry_state(model, repository):
    host = repository.rsplit("/repositories/", 1)[-1]
    if host not in HOSTS:
        return "redirected"
    project = repository.split("/locations/", 1)[0]
    facts = [item for scope, item in items(model.snapshot, "gcp_v4_workload_facts")
             if model._norm_scope(scope) == project and item.get("name") == project
             and item.get("scope") == project]
    if len(facts) != 1:
        return "unknown"
    artifact = facts[0].get("artifact_registry")
    if not isinstance(artifact, dict) or artifact.get("settings_status") not in ("collected", "empty"):
        return "unknown"
    state = artifact.get("redirection_state")
    if state in REDIRECTED:
        return "redirected"
    if state == "REDIRECTION_FROM_GCR_IO_DISABLED":
        return "disabled"
    return "unknown"


def _gke_consumers(model):
    """Return only Pods whose KSA can impersonate a named Google service account."""
    out = []
    for cluster_name, joined in (model.related_k8s or {}).items():
        if cluster_name in model.__dict__.get("_ambiguous_k8s", ()):
            continue
        cluster = model.gke.get(cluster_name)
        if not isinstance(cluster, dict):
            continue
        project = cluster_name.split("/locations/", 1)[0]
        pool = (cluster.get("workloadIdentityConfig") or {}).get("workloadPool")
        if not isinstance(pool, str) or pool != project.removeprefix("projects/") + ".svc.id.goog":
            continue
        cid, snap = joined
        required_kinds = ("pod", "serviceaccount") if (cluster.get("autopilot") or {}).get("enabled") is True \
            else ("pod", "serviceaccount", "node")
        if any(inventory_status(snap, kind) == {} or any(
                state not in ("collected", "empty") for state in inventory_status(snap, kind).values())
               for kind in required_kinds):
            continue
        def same_cluster(item):
            meta = item.get("metadata") or {}
            provenance = item.get("provenance") or {}
            return str(provenance.get("cluster_id") or meta.get("cluster_id") or
                       (snap.get("metadata") or {}).get("cluster_id") or cid) == cid
        accounts = {(m.get("namespace"), m.get("name")): item
                    for _, item in items(snap, "serviceaccount") if same_cluster(item)
                    for m in [item.get("metadata") or {}] if m.get("namespace") and m.get("name")}
        nodes = {(item.get("metadata") or {}).get("name"): item
                 for _, item in items(snap, "node") if same_cluster(item)}
        nodepools = {row.get("name"): row for row in cluster.get("nodePools") or ()
                     if isinstance(row, dict) and isinstance(row.get("name"), str)}
        for _, pod in items(snap, "pod"):
            if not same_cluster(pod) or (pod.get("status") or {}).get("phase") != "Running":
                continue
            spec, meta = pod.get("spec") or {}, pod.get("metadata") or {}
            namespace = meta.get("namespace")
            ksa_name = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
            account = accounts.get((namespace, ksa_name))
            node = nodes.get(spec.get("nodeName"))
            if not account or not isinstance(namespace, str):
                continue
            if (cluster.get("autopilot") or {}).get("enabled") is not True:
                if not node:
                    continue
                nodepool_name = ((node.get("metadata") or {}).get("labels") or {}).get("cloud.google.com/gke-nodepool")
                nodepool = nodepools.get(nodepool_name)
                if ((nodepool or {}).get("config") or {}).get("workloadMetadataConfig", {}).get("mode") != "GKE_METADATA":
                    continue
            mounted = spec.get("automountServiceAccountToken")
            if mounted is None:
                mounted = account.get("automountServiceAccountToken")
            if mounted is False:
                projected = {volume.get("name") for volume in spec.get("volumes") or ()
                             if isinstance(volume, dict) and any(
                                 isinstance(source.get("serviceAccountToken"), dict)
                                 for source in (volume.get("projected") or {}).get("sources") or ()
                                 if isinstance(source, dict))}
                if not any(mount.get("name") in projected and mount.get("mountPath")
                           for container in spec.get("containers") or () if isinstance(container, dict)
                           for mount in container.get("volumeMounts") or () if isinstance(mount, dict)):
                    continue
            email = ((account.get("metadata") or {}).get("annotations") or {}).get("iam.gke.io/gcp-service-account")
            if not isinstance(email, str) or "@" not in email:
                continue
            principal = model._principal(f"serviceAccount:{pool}[{namespace}/{ksa_name}]", project)
            principal.attrs.setdefault("grants", tuple(model.grants.get(principal.id, ())))
            target = model.sas.get("serviceAccount:" + email)
            if target is None:
                continue
            impersonate = model.check(principal, {"action": "iam.serviceAccounts.getAccessToken"},
                                      target.attrs.get("resource"))
            if impersonate is None:
                continue
            containers = spec.get("containers")
            if not isinstance(containers, list):
                continue
            binary = cluster.get("binaryAuthorization")
            for container in containers:
                if (not isinstance(container, dict) or
                        container.get("imagePullPolicy") not in ("Always", "IfNotPresent")):
                    continue
                image = container.get("image")
                if not isinstance(image, str):
                    continue
                repository = _repository_for_image(model, image)
                if repository:
                    out.append((email, repository, pod.get("metadata", {}).get("name"),
                                {"binaryAuthorization": binary, "_gke_impersonation": impersonate}))
    return out


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    status = {model._norm_scope(scope): state for scope, state in
              inventory_status(model.snapshot, "artifact_repository").items()}
    repositories = {}
    for scope, item in items(model.snapshot, "artifact_repository"):
        project = model._norm_scope(scope)
        name = model._norm_scope(item.get("name"))
        if REPO.fullmatch(name) and name.startswith(project + "/"):
            repositories.setdefault(name, []).append(item)
    consumers = {}
    for kind, records in (("cloudrun_service", model.run_services_by_project),
                          ("cloudrun_job", model.run_jobs_by_project),
                          ("cloudrun_worker_pool", model.run_worker_pools_by_project)):
        for workloads in records.values():
            for resource, email, item in workloads:
                if not isinstance(email, str):
                    continue
                for image in _images(kind, item):
                    repository = _repository_for_image(model, image)
                    if repository:
                        consumers.setdefault(email, []).append((repository, resource, item))
    for scope, trigger in items(model.snapshot, "cloudbuild_trigger"):
        if trigger.get("disabled") is True:
            continue
        resource = model._norm_scope(trigger.get("resourceName"))
        project = model._norm_scope(scope)
        if not (resource.startswith(project + "/locations/") and "/triggers/" in resource):
            continue
        raw_account = trigger.get("serviceAccount")
        if not raw_account:
            location = resource.split("/locations/", 1)[-1].split("/", 1)[0]
            raw_account = model.cloudbuild_default_by_location.get((project, location))
        email = (raw_account.rsplit("/serviceAccounts/", 1)[-1]
                 if isinstance(raw_account, str) and "/serviceAccounts/" in raw_account
                 else raw_account)
        if not isinstance(email, str) or "@" not in email:
            continue
        build = trigger.get("build")
        steps = build.get("steps") if isinstance(build, dict) else None
        if not isinstance(steps, list):
            continue
        for step in steps:
            image = step.get("name") if isinstance(step, dict) else None
            if not isinstance(image, str) or "$" in image:
                continue
            repository = _repository_for_image(model, image)
            if repository:
                consumers.setdefault(email, []).append((repository, resource, trigger))
    for email, repository, resource, pod in _gke_consumers(model):
        consumers.setdefault(email, []).append((repository, resource, pod))
    out = {}
    for tid, target in candidates.items():
        if target.attrs.get("disabled") is True:
            continue
        unresolved = False
        for repository, _resource, workload in consumers.get(target.attrs.get("email"), ()):
            project = repository.split("/locations/", 1)[0]
            if status.get(project) not in ("collected", "empty"):
                unresolved = True
                continue
            rows = repositories.get(repository, ())
            if len(rows) != 1:
                if rows:
                    unresolved = True
                continue
            item = rows[0]
            legacy = _legacy_registry_state(model, repository)
            if legacy == "disabled":
                continue
            if legacy == "unknown":
                unresolved = True
                continue
            if item.get("format") != "DOCKER":
                continue
            if (item.get("mode") not in (None, "STANDARD_REPOSITORY") or
                    "remoteRepositoryConfig" in item or "virtualRepositoryConfig" in item):
                continue
            docker = item.get("dockerConfig")
            if isinstance(docker, dict) and docker.get("immutableTags") is True:
                continue
            authorization = workload.get("binaryAuthorization")
            if authorization and authorization not in ({"useDefault": False}, {"enabled": False}):
                unresolved = True
                continue
            impersonation = workload.get("_gke_impersonation")
            if impersonation is not None and impersonation.confidence == "unknown":
                unresolved = True
                continue
            parent = repository.rsplit("/repositories/", 1)[0]
            model.parents.setdefault(parent, project)
            model.parents.setdefault(repository, parent)
            grant = model.check(source, {"action": "artifactregistry.repositories.uploadArtifacts"}, repository)
            if grant is None:
                continue
            if grant.confidence == "unknown":
                unresolved = True
                continue
            out[tid] = ("conditional", "exact_writable_repository_tagged_cloudrun_consumer")
            break
        if tid not in out and unresolved:
            out[tid] = ("unknown", "artifact_upload_consumer_or_policy_unresolved")
    return out
