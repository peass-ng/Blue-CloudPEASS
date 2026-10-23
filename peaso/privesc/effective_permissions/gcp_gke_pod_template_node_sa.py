"""Bind GKE workload writes to the exact node-pool service account."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster
from .gcp_gke_node_proxy_sa import _metadata_mode, _pool_email, _running_container
from .gcp_gke_pod_template_ksa import CREATE, UPDATE, _existing_template


def _derived(grant):
    return grant is not None and grant.confidence == "derived"


def _ready_nodes(snapshot, cluster_id):
    out = set()
    for _, node in items(snapshot, "node"):
        if not _same_cluster(node, cluster_id, snapshot):
            continue
        metadata, spec, status = (node.get("metadata") or {}, node.get("spec") or {}, node.get("status") or {})
        pool = (metadata.get("labels") or {}).get("cloud.google.com/gke-nodepool")
        ready = any(condition.get("type") == "Ready" and condition.get("status") == "True"
                    for condition in (status.get("conditions") or []) if isinstance(condition, dict))
        if (isinstance(pool, str) and pool and isinstance(metadata.get("name"), str)
                and str(spec.get("providerID") or "").startswith("gce://") and ready):
            out.add((metadata["name"], pool))
    return out


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
            actions = set(CREATE.values()) | set(UPDATE.values()) | {"container.pods.update"}
            grants = {action: model.check(source, {"action": action}, resource) for action in actions}
            if not any(grants.values()):
                continue
            authentication = model.check(source, {"action": "container.clusters.get"}, resource)
            if authentication is None:
                continue
            if not _derived(authentication):
                out.setdefault(target_id, ("unknown", "gke_principal_authentication_unverified"))
                continue
            if (model.gke_status.get(project) not in ("collected", "empty")
                    or cluster.get("status") != "RUNNING"
                    or (cluster.get("autopilot") or {}).get("enabled") is True):
                out.setdefault(target_id, ("unknown", "gke_standard_cluster_state_unresolved"))
                continue
            joined = (getattr(model, "related_k8s", None) or {}).get(resource)
            if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
                out.setdefault(target_id, ("unknown", "gke_node_sa_k8s_not_joined"))
                continue
            cluster_id, snapshot = joined
            if ((snapshot.get("metadata") or {}).get("cluster_id") != cluster_id
                    or not _complete(snapshot, "node")):
                out.setdefault(target_id, ("unknown", "gke_node_inventory_incomplete"))
                continue
            private = cluster.get("privateClusterConfig") or {}
            networks = cluster.get("masterAuthorizedNetworksConfig") or {}
            if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                    or networks.get("enabled") is True):
                out.setdefault(target_id, ("unknown", "gke_api_endpoint_unresolved"))
                continue
            nodes = _ready_nodes(snapshot, cluster_id)
            all_nodes = {(metadata.get("name"), (metadata.get("labels") or {}).get("cloud.google.com/gke-nodepool"))
                         for _, node in items(snapshot, "node") if _same_cluster(node, cluster_id, snapshot)
                         for metadata in [node.get("metadata") or {}]
                         if isinstance(metadata.get("name"), str)
                         and str((node.get("spec") or {}).get("providerID") or "").startswith("gce://")}
            uncertain = any(grant is not None and not _derived(grant) for grant in grants.values())
            for pool in matches:
                name = pool.get("name")
                if not isinstance(name, str) or pool.get("status") not in (None, "RUNNING"):
                    uncertain = True
                    continue
                if not any(node_pool == name for _, node_pool in all_nodes):
                    uncertain = True
                    continue
                mode = _metadata_mode(cluster, pool)
                if mode not in ("GCE_METADATA", "EXPOSE", "GKE_METADATA", "GKE_METADATA_SERVER", "SECURE"):
                    uncertain = True
                    continue
                # Creation can set hostNetwork and node affinity. A Pod update
                # cannot change either field, so it needs a running matching Pod.
                schedulable = any(node_pool == name for _, node_pool in nodes)
                create = schedulable and any(_derived(grants[action]) for action in CREATE.values())
                update = False
                for kind, action in UPDATE.items():
                    if grants[action] is None:
                        continue
                    if not _complete(snapshot, kind):
                        uncertain = True
                        continue
                    if schedulable and any(_existing_template(snapshot, cluster_id, kind, ns)
                           for ns in {(item.get("metadata") or {}).get("namespace")
                                      for _, item in items(snapshot, kind)} if isinstance(ns, str)):
                        if _derived(grants[action]):
                            update = True
                        else:
                            uncertain = True
                pod_update = False
                if grants["container.pods.update"] is not None:
                    if not _complete(snapshot, "pod"):
                        uncertain = True
                    else:
                        pod_update = any(
                            _same_cluster(pod, cluster_id, snapshot)
                            and (pod.get("spec") or {}).get("nodeName") in
                                {node for node, node_pool in all_nodes if node_pool == name}
                            and _running_container(pod)
                            and (mode in ("GCE_METADATA", "EXPOSE", "SECURE") or
                                 (pod.get("spec") or {}).get("hostNetwork") is True)
                            for _, pod in items(snapshot, "pod"))
                        pod_update = pod_update and _derived(grants["container.pods.update"])
                if create or update or pod_update:
                    out[target_id] = ("conditional", "exact_gke_node_pool_workload_metadata_path")
                    break
                if not schedulable and any(grants[action] is not None for action in
                                           set(CREATE.values()) | set(UPDATE.values())):
                    uncertain = True
            if out.get(target_id, (None,))[0] == "conditional":
                break
            if uncertain:
                out.setdefault(target_id, ("unknown", "gke_node_pool_workload_path_unresolved"))
    return out
