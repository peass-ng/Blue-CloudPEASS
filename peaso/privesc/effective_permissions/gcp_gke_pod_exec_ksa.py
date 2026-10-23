"""Bind GKE Pod exec to the target KSA token mounted in a running container."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster
from .gcp_gke_node_proxy_ksa import _running_names


def _mounted_token(snapshot, cluster_id, pod, namespace, sa_name, sa, eligible_names=None):
    """Return yes, unknown, or no for an API-usable token in a running container."""
    running = _running_names(pod)
    if not running:
        return "unknown" if (pod.get("status") or {}).get("phase") == "Running" else "no"
    if eligible_names is not None:
        running &= eligible_names
        if not running:
            return "no"
    spec = pod.get("spec") or {}
    volumes = {volume.get("name"): volume for volume in (spec.get("volumes") or [])
               if isinstance(volume, dict) and isinstance(volume.get("name"), str)}
    result = "no"
    for container in (spec.get("containers") or []):
        if not isinstance(container, dict) or container.get("name") not in running:
            continue
        for mount in (container.get("volumeMounts") or []):
            if not isinstance(mount, dict) or not mount.get("mountPath"):
                continue
            volume = volumes.get(mount.get("name")) or {}
            for source in ((volume.get("projected") or {}).get("sources") or []):
                token = source.get("serviceAccountToken") if isinstance(source, dict) else None
                if not isinstance(token, dict) or not token.get("path"):
                    continue
                if token.get("audience"):
                    result = "unknown"
                else:
                    return "yes"
            secret_name = (volume.get("secret") or {}).get("secretName")
            if not isinstance(secret_name, str):
                continue
            kind = "secret_metadata" if _complete(snapshot, "secret_metadata") else "secret"
            if not _complete(snapshot, kind):
                result = "unknown"
                continue
            secrets = [secret for _, secret in items(snapshot, kind)
                       if _same_cluster(secret, cluster_id, snapshot)
                       and (secret.get("metadata") or {}).get("namespace") == namespace
                       and (secret.get("metadata") or {}).get("name") == secret_name]
            if len(secrets) != 1:
                result = "unknown"
                continue
            secret = secrets[0]
            annotations = ((secret.get("metadata") or {}).get("annotations") or {})
            if (secret.get("type") == "kubernetes.io/service-account-token"
                    and annotations.get("kubernetes.io/service-account.name") == sa_name):
                uid = annotations.get("kubernetes.io/service-account.uid")
                sa_uid = (sa.get("metadata") or {}).get("uid")
                if not uid or not sa_uid:
                    result = "unknown"
                elif uid == sa_uid:
                    return "yes"
    return result


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
        grant = model.check(source, {"action": "container.pods.exec"}, resource)
        if grant is None:
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if authentication is None:
            continue
        project = resource.split("/locations/", 1)[0]
        if (model.gke_status.get(project) not in ("collected", "empty")
                or cluster.get("status") != "RUNNING"
                or grant.confidence != "derived" or authentication.confidence != "derived"):
            out[target_id] = ("unknown", "gke_pod_exec_cluster_or_permission_unresolved")
            continue
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                or networks.get("enabled") is True):
            out[target_id] = ("unknown", "gke_pod_exec_endpoint_unresolved")
            continue
        joined = (getattr(model, "related_k8s", None) or {}).get(resource)
        if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
            out[target_id] = ("unknown", "gke_pod_exec_k8s_not_joined")
            continue
        cluster_id, snapshot = joined
        if ((snapshot.get("metadata") or {}).get("cluster_id") != cluster_id
                or not _complete(snapshot, "pod") or not _complete(snapshot, "serviceaccount")):
            out[target_id] = ("unknown", "gke_pod_exec_inventory_incomplete")
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
        uncertain = False
        for _, pod in items(snapshot, "pod"):
            if not _same_cluster(pod, cluster_id, snapshot):
                continue
            metadata, spec = pod.get("metadata") or {}, pod.get("spec") or {}
            if (metadata.get("namespace") != namespace
                    or (spec.get("serviceAccountName") or spec.get("serviceAccount") or "default") != sa_name
                    or (pod.get("status") or {}).get("phase") != "Running"):
                continue
            if not metadata.get("name"):
                uncertain = True
                continue
            mounted = _mounted_token(snapshot, cluster_id, pod, namespace, sa_name, sas[0])
            if mounted == "yes":
                out[target_id] = ("conditional", "exact_gke_pod_exec_mounted_ksa")
                break
            if mounted == "unknown":
                uncertain = True
        else:
            if uncertain:
                out[target_id] = ("unknown", "gke_pod_exec_token_mount_unresolved")
    return out
