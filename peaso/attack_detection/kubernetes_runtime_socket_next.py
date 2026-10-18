"""Observe an accepted privileged Pod mounting a host runtime socket.

No assertion of scheduling, socket existence, use, node escape, or malicious intent.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit

SOCKET_PATHS = frozenset({
    "/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock",
    "/run/crio/crio.sock", "/var/run/crio/crio.sock",
    "/run/docker.sock", "/var/run/docker.sock",
})
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "gke-system"}


def normalize_kubernetes_runtime_socket_pod(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if not isinstance(record, Mapping):
        return None
    if "protoPayload" in record:
        from peaso.attack_detection.kubernetes_pod_next import _from_gke
        wrapped = _from_gke(record)
        if wrapped is None:
            return None
        record = wrapped
    if (record.get("apiVersion") != "audit.k8s.io/v1"
            or record.get("kind") != "Event" or record.get("stage") != "ResponseComplete"
            or record.get("verb") != "create"):
        return None
    uri = record.get("requestURI")
    try:
        parsed_uri = urlsplit(uri) if isinstance(uri, str) else None
    except ValueError:
        return None
    if parsed_uri is not None and any(k.lower() == "dryrun" for k, _ in
            parse_qsl(parsed_uri.query, keep_blank_values=True)):
        return None
    ref, status, response, user = (record.get(k) for k in ("objectRef", "responseStatus", "responseObject", "user"))
    if (not isinstance(ref, Mapping) or ref.get("apiGroup") not in (None, "")
            or ref.get("resource") != "pods" or ref.get("subresource") not in (None, "")
            or not isinstance(status, Mapping) or type(status.get("code")) is not int
            or status.get("code") != 201 or status.get("status") != "Success"
            or not isinstance(response, Mapping) or response.get("apiVersion") != "v1"
            or response.get("kind") != "Pod" or not isinstance(user, Mapping)):
        return None
    actor, event_id, cluster, when = user.get("username"), record.get("auditID"), record.get("cluster_id"), record.get("stageTimestamp")
    if (not isinstance(actor, str) or not actor or actor.startswith("system:")
            or not isinstance(event_id, str) or not event_id
            or not isinstance(cluster, str) or not cluster or not isinstance(when, str)):
        return None
    try:
        if datetime.fromisoformat(when.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    meta, spec = response.get("metadata"), response.get("spec")
    if not isinstance(meta, Mapping) or not isinstance(spec, Mapping):
        return None
    namespace, pod, uid = meta.get("namespace"), meta.get("name"), meta.get("uid")
    if (not isinstance(namespace, str) or not namespace or namespace in SYSTEM_NAMESPACES
            or not isinstance(pod, str) or not pod or not isinstance(uid, str) or not uid
            or ref.get("namespace") != namespace or ref.get("name") not in (None, pod)):
        return None
    if parsed_uri is not None and parsed_uri.path != f"/api/v1/namespaces/{namespace}/pods":
        return None
    os = spec.get("os")
    if isinstance(os, Mapping) and os.get("name") == "windows":
        return None
    volumes, containers = spec.get("volumes"), spec.get("containers")
    if not isinstance(volumes, list) or not isinstance(containers, list):
        return None
    socket_volumes = {}
    for volume in volumes:
        if not isinstance(volume, Mapping):
            continue
        name, host = volume.get("name"), volume.get("hostPath")
        path = host.get("path") if isinstance(host, Mapping) else None
        if (isinstance(name, str) and name and isinstance(path, str)
                and path in SOCKET_PATHS and host.get("type") == "Socket"):
            socket_volumes[name] = path
    for container in containers:
        if not isinstance(container, Mapping) or not isinstance(container.get("name"), str) or not container["name"]:
            continue
        security, mounts = container.get("securityContext"), container.get("volumeMounts")
        if not isinstance(security, Mapping) or security.get("privileged") is not True or not isinstance(mounts, list):
            continue
        for mount in mounts:
            if (not isinstance(mount, Mapping) or not isinstance(mount.get("name"), str)
                    or mount.get("name") not in socket_volumes
                    or mount.get("readOnly", False) is not False
                    or mount.get("subPath") or mount.get("subPathExpr")):
                continue
            path = mount.get("mountPath")
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            return {
                "cloud.provider": "kubernetes", "event.source": "kubernetes.audit",
                "event.name": "create", "event.outcome": "success", "event.id": event_id,
                "event.time": when, "account.id": cluster, "actor.id": actor,
                "target.id": f"{namespace}/{pod}", "target.namespace": namespace,
                "target.container": container["name"], "target.host_socket_path": socket_volumes[mount["name"]],
                "pod.privileged_runtime_socket_spec_accepted": True,
                "pod.change_effect": "admitted_spec",
            }
    return None
