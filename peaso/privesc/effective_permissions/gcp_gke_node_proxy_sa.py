"""Bound GKE node-proxy execution to the node pool's real service account."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster


def _pool_email(model, project, pool):
    config = pool.get("config") or {}
    email = config.get("serviceAccount")
    if email in (None, "", "default"):
        number = next((n for n, p in model.project_alias.items() if p == project.split("/", 1)[1]), None)
        return f"{number}-compute@developer.gserviceaccount.com" if number else None
    return email if isinstance(email, str) else None


def _metadata_mode(cluster, pool):
    config = pool.get("config") or {}
    metadata = config.get("workloadMetadataConfig") or {}
    mode = str(metadata.get("mode") or metadata.get("nodeMetadata") or "").upper()
    if not mode and not (cluster.get("workloadIdentityConfig") or {}).get("workloadPool"):
        return "GCE_METADATA"
    return mode


def _running_container(pod):
    status = pod.get("status") or {}
    if status.get("phase") != "Running":
        return False
    names = {item.get("name") for item in ((pod.get("spec") or {}).get("containers") or [])
             if isinstance(item, dict)}
    return any(isinstance(item, dict) and item.get("name") in names
               and isinstance((item.get("state") or {}).get("running"), dict)
               for item in (status.get("containerStatuses") or []))


def select(model, candidates, source):
    if source is None or source.kind not in ("gcp_user", "gcp_service_account"):
        return {}
    if not isinstance(source.attrs.get("email"), str) or not source.attrs["email"]:
        return {}
    out = {}
    for target_id, target in candidates.items():
        email = target.attrs.get("email")
        if not isinstance(email, str) or target.attrs.get("disabled") is True or source.id == target_id:
            continue
        for resource, cluster in model.gke.items():
            project = resource.split("/locations/", 1)[0]
            pools = cluster.get("nodePools")
            if not isinstance(pools, list):
                continue
            matches = [pool for pool in pools if isinstance(pool, dict)
                       and _pool_email(model, project, pool) == email]
            if not matches:
                continue
            proxy = model.check(source, {"action": "container.nodes.proxy"}, resource)
            if proxy is None:
                continue
            authentication = model.check(source, {"action": "container.clusters.get"}, resource)
            if authentication is None or authentication.confidence != "derived":
                out.setdefault(target_id, ("unknown", "gke_principal_authentication_unverified"))
                continue
            if (model.gke_status.get(project) not in ("collected", "empty")
                    or cluster.get("status") != "RUNNING" or proxy.confidence != "derived"):
                out.setdefault(target_id, ("unknown", "gke_node_proxy_cluster_or_permission_unresolved"))
                continue
            if (cluster.get("autopilot") or {}).get("enabled") is True:
                out.setdefault(target_id, ("unknown", "gke_autopilot_node_proxy_unresolved"))
                continue
            joined = (getattr(model, "related_k8s", None) or {}).get(resource)
            if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
                out.setdefault(target_id, ("unknown", "gke_node_proxy_k8s_not_joined"))
                continue
            cluster_id, snapshot = joined
            if ((snapshot.get("metadata") or {}).get("cluster_id") != cluster_id
                    or not _complete(snapshot, "node") or not _complete(snapshot, "pod")):
                out.setdefault(target_id, ("unknown", "gke_node_proxy_inventory_incomplete"))
                continue
            private = cluster.get("privateClusterConfig") or {}
            networks = cluster.get("masterAuthorizedNetworksConfig") or {}
            if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                    or networks.get("enabled") is True):
                out.setdefault(target_id, ("unknown", "gke_node_proxy_endpoint_unresolved"))
                continue
            nodes = {}
            for _, node in items(snapshot, "node"):
                if not _same_cluster(node, cluster_id, snapshot):
                    continue
                name = (node.get("metadata") or {}).get("name")
                pool_name = ((node.get("metadata") or {}).get("labels") or {}).get("cloud.google.com/gke-nodepool")
                provider = (node.get("spec") or {}).get("providerID")
                if isinstance(name, str) and isinstance(pool_name, str) and isinstance(provider, str) and provider.startswith("gce://"):
                    nodes[name] = pool_name
            pods = {node_name: [] for node_name in nodes}
            for _, pod in items(snapshot, "pod"):
                if not _same_cluster(pod, cluster_id, snapshot):
                    continue
                node_name = (pod.get("spec") or {}).get("nodeName")
                if node_name in pods and _running_container(pod):
                    pods[node_name].append(pod)
            for pool in matches:
                name = pool.get("name")
                if not isinstance(name, str) or pool.get("status") not in (None, "RUNNING"):
                    continue
                mode = _metadata_mode(cluster, pool)
                usable = any(
                    mode in ("GCE_METADATA", "EXPOSE") or
                    mode in ("GKE_METADATA", "GKE_METADATA_SERVER", "SECURE") and
                    (pod.get("spec") or {}).get("hostNetwork") is True
                    for node_name, node_pool in nodes.items() if node_pool == name
                    for pod in pods[node_name])
                if usable:
                    out[target_id] = ("conditional", "exact_gke_node_proxy_metadata_path")
                    break
            if out.get(target_id, (None,))[0] == "conditional":
                break
            out.setdefault(target_id, ("unknown", "gke_node_proxy_pod_or_metadata_unresolved"))
    return out
