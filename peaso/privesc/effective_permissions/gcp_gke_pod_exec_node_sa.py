"""Bind GKE Pod exec to a running container on the target node pool."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster
from .gcp_gke_node_proxy_sa import _metadata_mode, _pool_email, _running_container


def select(model, candidates, source):
    if source is None or source.kind not in ("gcp_user", "gcp_service_account"):
        return {}
    if not isinstance(source.attrs.get("email"), str) or not source.attrs["email"]:
        return {}
    out = {}
    for target_id, target in candidates.items():
        email = target.attrs.get("email")
        if not isinstance(email, str) or target.attrs.get("disabled") is True or target_id == source.id:
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
            grant = model.check(source, {"action": "container.pods.exec"}, resource)
            if grant is None:
                continue
            authentication = model.check(source, {"action": "container.clusters.get"}, resource)
            if authentication is None:
                continue
            if authentication.confidence != "derived" or grant.confidence != "derived":
                out.setdefault(target_id, ("unknown", "gke_pod_exec_permission_unresolved"))
                continue
            if (model.gke_status.get(project) not in ("collected", "empty")
                    or cluster.get("status") != "RUNNING"
                    or (cluster.get("autopilot") or {}).get("enabled") is True):
                out.setdefault(target_id, ("unknown", "gke_standard_cluster_state_unresolved"))
                continue
            private = cluster.get("privateClusterConfig") or {}
            networks = cluster.get("masterAuthorizedNetworksConfig") or {}
            if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                    or networks.get("enabled") is True):
                out.setdefault(target_id, ("unknown", "gke_api_endpoint_unresolved"))
                continue
            joined = (getattr(model, "related_k8s", None) or {}).get(resource)
            if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
                out.setdefault(target_id, ("unknown", "gke_pod_exec_k8s_not_joined"))
                continue
            cluster_id, snapshot = joined
            if ((snapshot.get("metadata") or {}).get("cluster_id") != cluster_id
                    or not _complete(snapshot, "node") or not _complete(snapshot, "pod")):
                out.setdefault(target_id, ("unknown", "gke_pod_exec_inventory_incomplete"))
                continue
            nodes = {}
            for _, node in items(snapshot, "node"):
                if not _same_cluster(node, cluster_id, snapshot):
                    continue
                meta, spec = node.get("metadata") or {}, node.get("spec") or {}
                name = meta.get("name")
                pool = (meta.get("labels") or {}).get("cloud.google.com/gke-nodepool")
                if isinstance(name, str) and isinstance(pool, str) and str(spec.get("providerID") or "").startswith("gce://"):
                    nodes[name] = pool
            for pool in matches:
                name = pool.get("name")
                if not isinstance(name, str) or pool.get("status") not in (None, "RUNNING"):
                    continue
                mode = _metadata_mode(cluster, pool)
                if mode not in ("GCE_METADATA", "EXPOSE", "SECURE", "GKE_METADATA", "GKE_METADATA_SERVER"):
                    out.setdefault(target_id, ("unknown", "gke_node_metadata_mode_unresolved"))
                    continue
                viable = any(
                    _same_cluster(pod, cluster_id, snapshot)
                    and (pod.get("metadata") or {}).get("name")
                    and (pod.get("metadata") or {}).get("namespace")
                    and nodes.get((pod.get("spec") or {}).get("nodeName")) == name
                    and _running_container(pod)
                    and (pod.get("spec") or {}).get("runtimeClassName") != "gvisor"
                    and (mode in ("GCE_METADATA", "EXPOSE", "SECURE") or
                         (pod.get("spec") or {}).get("hostNetwork") is True)
                    for _, pod in items(snapshot, "pod"))
                if viable:
                    out[target_id] = ("conditional", "exact_gke_pod_exec_node_metadata_path")
                    break
            if out.get(target_id, (None,))[0] == "conditional":
                break
    return out
