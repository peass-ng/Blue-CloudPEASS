"""Bound GKE mutating-webhook paths to an exact cluster and active KSA."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster


def select(model, candidates, source):
    if source is None or source.kind not in ("gcp_user", "gcp_service_account"):
        return {}
    if not isinstance(source.attrs.get("email"), str) or not source.attrs["email"]:
        return {}
    active = {node.id for node in model._ksa_targets("running_pod")
              if not node.attrs.get("aggregate")}
    out = {}
    for target_id, target in candidates.items():
        resource = target.attrs.get("gke_cluster") or target.scope
        cluster = model.gke.get(resource)
        if not isinstance(cluster, dict):
            continue
        project = resource.split("/locations/", 1)[0]
        if model.gke_status.get(project) not in ("collected", "empty") or cluster.get("status") != "RUNNING":
            out[target_id] = ("unknown", "gke_cluster_state_unresolved")
            continue
        create = model.check(source, {"action": "container.mutatingWebhookConfigurations.create"}, resource)
        update = model.check(source, {"action": "container.mutatingWebhookConfigurations.update"}, resource)
        if create is None and update is None:
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if authentication is None or authentication.confidence != "derived":
            out[target_id] = ("unknown", "gke_principal_authentication_unverified")
            continue
        joined = (getattr(model, "related_k8s", None) or {}).get(resource)
        if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
            out[target_id] = ("unknown", "gke_ksa_inventory_not_joined")
            continue
        cluster_id, snapshot = joined
        if (snapshot.get("metadata") or {}).get("cluster_id") != cluster_id:
            out[target_id] = ("unknown", "gke_ksa_inventory_scope_unresolved")
            continue
        if target.attrs.get("aggregate"):
            out[target_id] = ("unknown", "gke_ksa_inventory_incomplete")
            continue
        namespace = target.attrs.get("namespace")
        if namespace in ("kube-system", "gke-system"):
            out[target_id] = ("unknown", "gke_system_namespace_admission_unresolved")
            continue
        certain_create = create is not None and create.confidence == "derived"
        certain_update = False
        if update is not None and update.confidence == "derived":
            if not _complete(snapshot, "mutatingwebhookconfiguration"):
                out[target_id] = ("unknown", "gke_webhook_configuration_inventory_incomplete")
            else:
                certain_update = any(_same_cluster(item, cluster_id, snapshot)
                                     and isinstance((item.get("metadata") or {}).get("name"), str)
                                     for _, item in items(snapshot, "mutatingwebhookconfiguration"))
        if not certain_create and not certain_update:
            if (create is not None and create.confidence != "derived"
                    or update is not None and update.confidence != "derived"):
                out.setdefault(target_id, ("unknown", "gke_webhook_write_permission_unresolved"))
            continue
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if (target_id not in active or not cluster.get("endpoint")
                or private.get("enablePrivateEndpoint") is True or networks.get("enabled") is True):
            out[target_id] = ("unknown", "gke_webhook_target_or_endpoint_unresolved")
            continue
        out[target_id] = ("conditional", "gke_active_ksa_mutating_webhook_path")
    return out
