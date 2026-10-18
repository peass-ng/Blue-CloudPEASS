"""Observe an admitted Pod spec combining privileged host access controls.

The response object proves only that the API server accepted this Pod object.
Scheduling, container start, host-file access, escape, and intent need separate
evidence. Node-debugging or infrastructure agents can legitimately use these
settings and require owner/context review.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit


_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "gke-system"}
_GKE_METHOD = "io.k8s.core.v1.pods.create"


def _time(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if parsed.tzinfo is not None else None


def _from_gke(record: Mapping[str, Any]) -> dict[str, Any] | None:
    payload = record.get("protoPayload")
    resource = record.get("resource")
    log_name = record.get("logName")
    labels = record.get("labels")
    if (not isinstance(payload, Mapping) or not isinstance(resource, Mapping)
            or payload.get("@type") != "type.googleapis.com/google.cloud.audit.AuditLog"
            or payload.get("serviceName") != "k8s.io" or payload.get("methodName") != _GKE_METHOD
            or resource.get("type") != "k8s_cluster"
            or not isinstance(log_name, str)
            or not log_name.endswith("/logs/cloudaudit.googleapis.com%2Factivity")
            or isinstance(labels, Mapping) and "command.gke.io/dryRun" in labels):
        return None
    status = payload.get("status")
    if status is not None:
        if not isinstance(status, Mapping):
            return None
        if "code" in status and (type(status["code"]) is not int or status["code"] != 0):
            return None
    request = payload.get("request")
    if isinstance(request, Mapping) and request.get("dryRun"):
        return None
    response = payload.get("response")
    auth = payload.get("authenticationInfo")
    resource_labels = resource.get("labels")
    if (not isinstance(response, Mapping) or not isinstance(auth, Mapping)
            or not isinstance(resource_labels, Mapping)
            or not isinstance(resource_labels.get("location"), str) or not resource_labels["location"]
            or not isinstance(resource_labels.get("cluster_name"), str) or not resource_labels["cluster_name"]):
        return None
    metadata = response.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    cluster = (log_name.split("/logs/", 1)[0]
               + f"/locations/{resource_labels['location']}/clusters/{resource_labels['cluster_name']}")
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete",
        "verb": "create", "auditID": record.get("insertId"), "stageTimestamp": record.get("timestamp"),
        "cluster_id": cluster, "user": {"username": auth.get("principalEmail")},
        "objectRef": {"apiGroup": "", "resource": "pods", "name": metadata.get("name"),
                      "namespace": metadata.get("namespace")},
        "responseStatus": {"code": 201, "status": "Success"}, "responseObject": response,
    }


def _host_root_mount(spec: Mapping[str, Any]) -> tuple[str, str] | None:
    volumes = spec.get("volumes")
    containers = spec.get("containers")
    if not isinstance(volumes, list) or not isinstance(containers, list):
        return None
    root_volumes = {volume.get("name") for volume in volumes if isinstance(volume, Mapping)
                    and isinstance(volume.get("name"), str) and volume["name"]
                    and isinstance(volume.get("hostPath"), Mapping)
                    and volume["hostPath"].get("path") == "/"
                    and volume["hostPath"].get("type") in (None, "", "Directory", "DirectoryOrCreate")}
    if not root_volumes:
        return None
    for container in containers:
        if not isinstance(container, Mapping) or not isinstance(container.get("name"), str) or not container["name"]:
            continue
        security = container.get("securityContext")
        mounts = container.get("volumeMounts")
        if not isinstance(security, Mapping) or security.get("privileged") is not True or not isinstance(mounts, list):
            continue
        for mount in mounts:
            if (isinstance(mount, Mapping) and mount.get("name") in root_volumes
                    and isinstance(mount.get("mountPath"), str) and mount["mountPath"].startswith("/")
                    and mount.get("readOnly", False) is False
                    and not mount.get("subPath") and not mount.get("subPathExpr")):
                return container["name"], mount["mountPath"]
    return None


def normalize_kubernetes_privileged_host_pod(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return only a successful Pod create response with the exact risky spec."""
    if "protoPayload" in record:
        record = _from_gke(record)
        if record is None:
            return None
    if (record.get("apiVersion") != "audit.k8s.io/v1" or record.get("kind") != "Event"
            or record.get("stage") != "ResponseComplete" or record.get("verb") != "create"):
        return None
    uri = record.get("requestURI")
    if isinstance(uri, str) and any(key.lower() == "dryrun" for key, _ in
            parse_qsl(urlsplit(uri).query, keep_blank_values=True)):
        return None
    ref = record.get("objectRef")
    status = record.get("responseStatus")
    response = record.get("responseObject")
    user = record.get("user")
    if (not isinstance(ref, Mapping) or ref.get("apiGroup") not in (None, "")
            or ref.get("resource") != "pods"
            or not isinstance(status, Mapping) or type(status.get("code")) is not int
            or status["code"] != 201 or status.get("status") != "Success"
            or not isinstance(response, Mapping) or response.get("apiVersion") != "v1"
            or response.get("kind") != "Pod" or not isinstance(user, Mapping)):
        return None
    actor = user.get("username")
    event_id = record.get("auditID")
    cluster = record.get("cluster_id")
    if (not isinstance(actor, str) or not actor
            or not isinstance(event_id, str) or not event_id
            or not isinstance(cluster, str) or not cluster
            or _time(record.get("stageTimestamp")) is None):
        return None
    metadata = response.get("metadata")
    spec = response.get("spec")
    if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping):
        return None
    pod = metadata.get("name")
    namespace = metadata.get("namespace")
    if (not isinstance(pod, str) or not pod
            or not isinstance(metadata.get("uid"), str) or not metadata["uid"]
            or not isinstance(namespace, str) or not namespace or namespace in _SYSTEM_NAMESPACES
            or ref.get("namespace") != namespace or ref.get("name") not in (None, pod)
            or spec.get("hostPID") is not True):
        return None
    os = spec.get("os")
    if isinstance(os, Mapping) and os.get("name") == "windows":
        return None
    host_mount = _host_root_mount(spec)
    if host_mount is None:
        return None
    container, mount_path = host_mount
    return {
        "cloud.provider": "kubernetes", "event.source": "kubernetes.audit",
        "event.name": "create", "event.outcome": "success",
        "event.id": event_id, "event.time": record["stageTimestamp"],
        "account.id": cluster, "actor.id": actor,
        "target.id": f"{namespace}/{pod}", "target.namespace": namespace,
        "target.container": container, "target.host_mount_path": mount_path,
        "pod.host_pid": True, "pod.privileged": True,
        "pod.writable_host_root_mount": True,
        "pod.privileged_host_pod_created": True,
        "pod.change_effect": "admitted_spec",
    }
