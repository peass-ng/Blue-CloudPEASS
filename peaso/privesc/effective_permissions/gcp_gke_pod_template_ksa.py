"""Bind GKE workload writes to a KSA in the same Kubernetes namespace."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster


CREATE = {
    "pod": "container.pods.create",
    "deployment": "container.deployments.create",
    "daemonset": "container.daemonSets.create",
    "job": "container.jobs.create",
    "cronjob": "container.cronJobs.create",
    "statefulset": "container.statefulSets.create",
    "replicaset": "container.replicaSets.create",
    "replicationcontroller": "container.replicationControllers.create",
}
UPDATE = {
    "deployment": "container.deployments.update",
    "daemonset": "container.daemonSets.update",
    "cronjob": "container.cronJobs.update",
    "statefulset": "container.statefulSets.update",
    "replicaset": "container.replicaSets.update",
    "replicationcontroller": "container.replicationControllers.update",
}


def _derived(grant):
    return grant is not None and grant.confidence == "derived"


def _existing_template(snapshot, cluster_id, kind, namespace):
    for _, item in items(snapshot, kind):
        if not _same_cluster(item, cluster_id, snapshot):
            continue
        metadata = item.get("metadata") or {}
        if metadata.get("namespace") != namespace or not metadata.get("name"):
            continue
        spec = item.get("spec") or {}
        template = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") if kind == "cronjob" else spec.get("template")
        pod_spec = (template or {}).get("spec") if isinstance(template, dict) else None
        if isinstance(pod_spec, dict) and pod_spec.get("containers"):
            return True
    return False


def select(model, candidates, source):
    if source is None or source.kind not in ("gcp_user", "gcp_service_account"):
        return {}
    if not isinstance(source.attrs.get("email"), str) or not source.attrs["email"]:
        return {}
    out = {}
    for target_id, target in candidates.items():
        resource = target.attrs.get("gke_cluster") or target.scope
        cluster = model.gke.get(resource)
        if not isinstance(cluster, dict):
            continue
        grants = {action: model.check(source, {"action": action}, resource)
                  for action in set(CREATE.values()) | set(UPDATE.values())}
        if not any(grants.values()):
            continue
        project = resource.split("/locations/", 1)[0]
        if model.gke_status.get(project) not in ("collected", "empty") or cluster.get("status") != "RUNNING":
            out[target_id] = ("unknown", "gke_cluster_state_unresolved")
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if authentication is None:
            continue
        if not _derived(authentication):
            out[target_id] = ("unknown", "gke_principal_authentication_unverified")
            continue
        joined = (getattr(model, "related_k8s", None) or {}).get(resource)
        if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
            out[target_id] = ("unknown", "gke_pod_template_k8s_not_joined")
            continue
        cluster_id, snapshot = joined
        if (snapshot.get("metadata") or {}).get("cluster_id") != cluster_id or not _complete(snapshot, "serviceaccount"):
            out[target_id] = ("unknown", "gke_ksa_inventory_incomplete")
            continue
        if target.attrs.get("aggregate"):
            out[target_id] = ("unknown", "gke_target_ksa_unresolved")
            continue
        namespace, sa_name = target.attrs.get("namespace"), target.attrs.get("name")
        sas = [item for _, item in items(snapshot, "serviceaccount")
               if _same_cluster(item, cluster_id, snapshot)
               and (item.get("metadata") or {}).get("namespace") == namespace
               and (item.get("metadata") or {}).get("name") == sa_name]
        if len(sas) != 1:
            out[target_id] = ("unknown", "gke_target_ksa_unresolved")
            continue
        create = any(_derived(grants[action]) for action in CREATE.values())
        uncertain = any(grant is not None and not _derived(grant)
                        for grant in grants.values())
        update = False
        for kind, action in UPDATE.items():
            if grants[action] is None:
                continue
            if not _complete(snapshot, kind):
                uncertain = True
                continue
            if _existing_template(snapshot, cluster_id, kind, namespace):
                if _derived(grants[action]):
                    update = True
                else:
                    uncertain = True
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if create or update:
            if not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True or networks.get("enabled") is True:
                out[target_id] = ("unknown", "gke_pod_template_endpoint_unresolved")
            else:
                out[target_id] = ("conditional", "exact_gke_pod_template_ksa_path")
        elif uncertain:
            out[target_id] = ("unknown", "gke_pod_template_authority_or_inventory_unresolved")
    return out
