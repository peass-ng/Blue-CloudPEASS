"""Bind GKE IAM Secret reads to an existing, current KSA token Secret."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster


def _derived(grant):
    return grant is not None and grant.confidence == "derived"


def _known_from_list(model, source, resource, snapshot, cluster_id, sa, secret_name):
    namespace = (sa.get("metadata") or {}).get("namespace")
    if _derived(model.check(source, {"action": "container.serviceAccounts.list"}, resource)):
        if any(ref.get("name") == secret_name for ref in (sa.get("secrets") or [])
               if isinstance(ref, dict)):
            return True
    if _derived(model.check(source, {"action": "container.pods.list"}, resource)):
        if not _complete(snapshot, "pod"):
            return None
        for _, pod in items(snapshot, "pod"):
            if not _same_cluster(pod, cluster_id, snapshot):
                continue
            if (pod.get("metadata") or {}).get("namespace") != namespace:
                continue
            if any((volume.get("secret") or {}).get("secretName") == secret_name
                   for volume in ((pod.get("spec") or {}).get("volumes") or []) if isinstance(volume, dict)):
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
        listing = model.check(source, {"action": "container.secrets.list"}, resource)
        getting = model.check(source, {"action": "container.secrets.get"}, resource)
        if listing is None and getting is None:
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if authentication is None:
            continue
        project = resource.split("/locations/", 1)[0]
        if (model.gke_status.get(project) not in ("collected", "empty")
                or cluster.get("status") != "RUNNING"
                or not _derived(authentication)):
            out[target_id] = ("unknown", "gke_secret_read_cluster_or_auth_unresolved")
            continue
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                or networks.get("enabled") is True):
            out[target_id] = ("unknown", "gke_secret_read_endpoint_unresolved")
            continue
        joined = (getattr(model, "related_k8s", None) or {}).get(resource)
        if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
            out[target_id] = ("unknown", "gke_secret_read_k8s_not_joined")
            continue
        cluster_id, snapshot = joined
        secret_kind = "secret_metadata" if _complete(snapshot, "secret_metadata") else "secret"
        if ((snapshot.get("metadata") or {}).get("cluster_id") != cluster_id
                or not _complete(snapshot, "serviceaccount") or not _complete(snapshot, secret_kind)):
            out[target_id] = ("unknown", "gke_secret_or_ksa_inventory_incomplete")
            continue
        if target.attrs.get("aggregate"):
            out[target_id] = ("unknown", "gke_target_ksa_unresolved")
            continue
        namespace, sa_name = target.attrs.get("namespace"), target.attrs.get("name")
        sas = [sa for _, sa in items(snapshot, "serviceaccount")
               if _same_cluster(sa, cluster_id, snapshot)
               and (sa.get("metadata") or {}).get("namespace") == namespace
               and (sa.get("metadata") or {}).get("name") == sa_name]
        if len(sas) != 1:
            out[target_id] = ("unknown", "gke_target_ksa_unresolved")
            continue
        sa = sas[0]
        sa_uid = (sa.get("metadata") or {}).get("uid")
        if not isinstance(sa_uid, str) or not sa_uid:
            out[target_id] = ("unknown", "gke_target_ksa_uid_unresolved")
            continue
        uncertain = False
        for _, secret in items(snapshot, secret_kind):
            if not _same_cluster(secret, cluster_id, snapshot):
                continue
            metadata = secret.get("metadata") or {}
            annotations = metadata.get("annotations") or {}
            if (metadata.get("namespace") != namespace or
                    secret.get("type") != "kubernetes.io/service-account-token" or
                    annotations.get("kubernetes.io/service-account.name") != sa_name):
                continue
            uid = annotations.get("kubernetes.io/service-account.uid")
            if not uid:
                uncertain = True
                continue
            if uid != sa_uid or "kubernetes.io/legacy-token-invalid-since" in (metadata.get("labels") or {}):
                continue
            name = metadata.get("name")
            if not isinstance(name, str) or not name:
                uncertain = True
                continue
            if _derived(listing):
                out[target_id] = ("conditional", "exact_gke_list_current_ksa_token_secret")
                break
            if getting is not None:
                known = _known_from_list(model, source, resource, snapshot, cluster_id, sa, name)
                if known is True and _derived(getting):
                    out[target_id] = ("conditional", "exact_gke_get_discoverable_ksa_token_secret")
                    break
                uncertain = True
            elif listing is not None:
                uncertain = True
        else:
            if uncertain:
                out[target_id] = ("unknown", "gke_token_secret_or_name_unresolved")
    return out
