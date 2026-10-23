"""Bind a GKE node-pool metadata downgrade to a usable workload path."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster
from .gcp_gke_node_proxy_sa import _metadata_mode, _pool_email, _running_container
from .gcp_gke_pod_template_ksa import CREATE, UPDATE, _existing_template
from .gcp_gke_pod_template_node_sa import _ready_nodes


def _derived(grant):
    return grant is not None and grant.confidence == "derived"


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
            update = model.check(source, {"action": "container.clusters.update"}, resource)
            if update is None:
                continue
            actions = set(CREATE.values()) | set(UPDATE.values()) | {
                "container.pods.update", "container.pods.exec", "container.nodes.proxy"}
            grants = {action: model.check(source, {"action": action}, resource) for action in actions}
            if not any(grants.values()):
                continue
            authentication = model.check(source, {"action": "container.clusters.get"}, resource)
            if authentication is None or not _derived(authentication) or not _derived(update):
                out.setdefault(target_id, ("unknown", "gke_nodepool_update_or_auth_unresolved"))
                continue
            if (model.gke_status.get(project) not in ("collected", "empty")
                    or cluster.get("status") != "RUNNING"):
                out.setdefault(target_id, ("unknown", "gke_nodepool_cluster_state_unresolved"))
                continue
            if (cluster.get("autopilot") or {}).get("enabled") is True:
                continue
            private = cluster.get("privateClusterConfig") or {}
            networks = cluster.get("masterAuthorizedNetworksConfig") or {}
            if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                    or networks.get("enabled") is True):
                out.setdefault(target_id, ("unknown", "gke_nodepool_api_endpoint_unresolved"))
                continue
            joined = (getattr(model, "related_k8s", None) or {}).get(resource)
            if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
                out.setdefault(target_id, ("unknown", "gke_nodepool_k8s_not_joined"))
                continue
            cluster_id, snapshot = joined
            if ((snapshot.get("metadata") or {}).get("cluster_id") != cluster_id
                    or not _complete(snapshot, "node")):
                out.setdefault(target_id, ("unknown", "gke_nodepool_node_inventory_incomplete"))
                continue
            nodes = {}
            for _, node in items(snapshot, "node"):
                if not _same_cluster(node, cluster_id, snapshot):
                    continue
                meta, spec = node.get("metadata") or {}, node.get("spec") or {}
                name = meta.get("name")
                pool_name = (meta.get("labels") or {}).get("cloud.google.com/gke-nodepool")
                if (isinstance(name, str) and isinstance(pool_name, str)
                        and str(spec.get("providerID") or "").startswith("gce://")):
                    nodes[name] = pool_name
            ready = _ready_nodes(snapshot, cluster_id)
            uncertain = False
            for pool in matches:
                name = pool.get("name")
                if not isinstance(name, str) or pool.get("status") not in (None, "RUNNING"):
                    uncertain = True
                    continue
                mode = _metadata_mode(cluster, pool)
                if mode in ("GCE_METADATA", "EXPOSE", "SECURE"):
                    continue  # The node SA is already exposed without this downgrade.
                if mode not in ("GKE_METADATA", "GKE_METADATA_SERVER"):
                    uncertain = True
                    continue
                if not (cluster.get("workloadIdentityConfig") or {}).get("workloadPool"):
                    uncertain = True
                    continue
                if not any(node_pool == name for node_pool in nodes.values()):
                    uncertain = True
                    continue
                schedulable = any(node_pool == name for _, node_pool in ready)
                create = schedulable and any(_derived(grants[action]) for action in CREATE.values())
                controller_update = False
                for kind, action in UPDATE.items():
                    if grants[action] is None:
                        continue
                    if not _complete(snapshot, kind):
                        uncertain = True
                        continue
                    if schedulable and any(_existing_template(snapshot, cluster_id, kind, ns)
                                           for ns in {(item.get("metadata") or {}).get("namespace")
                                                      for _, item in items(snapshot, kind)} if isinstance(ns, str)):
                        controller_update |= _derived(grants[action])
                read = False
                read_actions = ("container.pods.update", "container.pods.exec", "container.nodes.proxy")
                if any(grants[action] is not None for action in read_actions):
                    if not _complete(snapshot, "pod"):
                        uncertain = True
                    else:
                        read = any(
                            _same_cluster(pod, cluster_id, snapshot)
                            and (pod.get("metadata") or {}).get("name")
                            and (pod.get("metadata") or {}).get("namespace")
                            and nodes.get((pod.get("spec") or {}).get("nodeName")) == name
                            and _running_container(pod)
                            and (pod.get("spec") or {}).get("runtimeClassName") != "gvisor"
                            and (pod.get("spec") or {}).get("hostNetwork") is not True
                            for _, pod in items(snapshot, "pod"))
                        read = read and any(_derived(grants[action]) for action in read_actions)
                if create or controller_update or read:
                    out[target_id] = ("conditional", "exact_gke_nodepool_metadata_downgrade_path")
                    break
                if not schedulable and any(grants[action] is not None for action in
                                           set(CREATE.values()) | set(UPDATE.values())):
                    uncertain = True
            if out.get(target_id, (None,))[0] == "conditional":
                break
            if uncertain:
                out.setdefault(target_id, ("unknown", "gke_nodepool_workload_path_unresolved"))
    return out
