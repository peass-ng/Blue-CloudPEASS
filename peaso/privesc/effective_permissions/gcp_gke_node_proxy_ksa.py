"""Bound GKE kubelet proxy execution to the target Pod's mounted KSA token."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster


def _running_names(pod):
    status = pod.get("status") or {}
    if status.get("phase") != "Running":
        return set()
    declared = {item.get("name") for item in ((pod.get("spec") or {}).get("containers") or [])
                if isinstance(item, dict)}
    return {item.get("name") for item in (status.get("containerStatuses") or [])
            if isinstance(item, dict) and item.get("name") in declared
            and isinstance((item.get("state") or {}).get("running"), dict)}


def _token_in_running_container(pod, sa):
    running = _running_names(pod)
    if not running:
        return False
    spec = pod.get("spec") or {}
    automount = spec.get("automountServiceAccountToken")
    if automount is None:
        automount = sa.get("automountServiceAccountToken")
    if automount is not False:
        return True
    projected = {volume.get("name") for volume in (spec.get("volumes") or [])
                 if isinstance(volume, dict) and any(
                     isinstance(source.get("serviceAccountToken"), dict)
                     for source in ((volume.get("projected") or {}).get("sources") or [])
                     if isinstance(source, dict))}
    return any(container.get("name") in running and any(
               mount.get("name") in projected and mount.get("mountPath")
               for mount in (container.get("volumeMounts") or []) if isinstance(mount, dict))
               for container in (spec.get("containers") or []) if isinstance(container, dict))


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
        project = resource.split("/locations/", 1)[0]
        proxy = model.check(source, {"action": "container.nodes.proxy"}, resource)
        if proxy is None:
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if authentication is None or authentication.confidence != "derived":
            out[target_id] = ("unknown", "gke_principal_authentication_unverified")
            continue
        if (model.gke_status.get(project) not in ("collected", "empty")
                or cluster.get("status") != "RUNNING" or proxy.confidence != "derived"):
            out[target_id] = ("unknown", "gke_node_proxy_cluster_or_permission_unresolved")
            continue
        if (cluster.get("autopilot") or {}).get("enabled") is True:
            out[target_id] = ("unknown", "gke_autopilot_node_proxy_unresolved")
            continue
        joined = (getattr(model, "related_k8s", None) or {}).get(resource)
        if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
            out[target_id] = ("unknown", "gke_node_proxy_k8s_not_joined")
            continue
        cluster_id, snapshot = joined
        if ((snapshot.get("metadata") or {}).get("cluster_id") != cluster_id
                or not all(_complete(snapshot, kind) for kind in ("node", "pod", "serviceaccount"))):
            out[target_id] = ("unknown", "gke_node_proxy_inventory_incomplete")
            continue
        if target.attrs.get("aggregate"):
            out[target_id] = ("unknown", "gke_running_ksa_unresolved")
            continue
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                or networks.get("enabled") is True):
            out[target_id] = ("unknown", "gke_node_proxy_endpoint_unresolved")
            continue
        namespace, sa_name = target.attrs.get("namespace"), target.attrs.get("name")
        sas = [item for _, item in items(snapshot, "serviceaccount")
               if _same_cluster(item, cluster_id, snapshot)
               and (item.get("metadata") or {}).get("namespace") == namespace
               and (item.get("metadata") or {}).get("name") == sa_name]
        if len(sas) != 1:
            out[target_id] = ("unknown", "gke_target_ksa_unresolved")
            continue
        nodes = {(item.get("metadata") or {}).get("name") for _, item in items(snapshot, "node")
                 if _same_cluster(item, cluster_id, snapshot)
                 and isinstance((item.get("spec") or {}).get("providerID"), str)
                 and item["spec"]["providerID"].startswith("gce://")}
        viable = any(
            _same_cluster(pod, cluster_id, snapshot)
            and (pod.get("metadata") or {}).get("namespace") == namespace
            and ((pod.get("spec") or {}).get("serviceAccountName") or
                 (pod.get("spec") or {}).get("serviceAccount") or "default") == sa_name
            and (pod.get("spec") or {}).get("nodeName") in nodes
            and _token_in_running_container(pod, sas[0])
            for _, pod in items(snapshot, "pod"))
        out[target_id] = (("conditional", "exact_gke_node_proxy_running_ksa") if viable else
                          ("unknown", "gke_node_proxy_running_container_or_token_unresolved"))
    return out
