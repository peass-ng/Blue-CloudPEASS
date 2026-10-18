"""Observe an accepted privileged ephemeral-container subresource update.

This does not prove a new container was added, started, reached another
process, or escaped the node. Authorized debugging can produce this event.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .gke_scope import project_scope


_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "gke-system"}
_GKE_METHOD = "io.k8s.core.v1.pods.ephemeralcontainers.update"
_SA_ACTOR = re.compile(r"system:serviceaccount:([a-z0-9](?:[-a-z0-9]*[a-z0-9])?):([a-z0-9](?:[-.a-z0-9]*[a-z0-9])?)\Z")


def _time(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if parsed.tzinfo is not None else None


def _gke_native(record: Mapping[str, Any]) -> dict[str, Any] | None:
    payload = record.get("protoPayload")
    resource = record.get("resource")
    log_name = record.get("logName")
    labels = record.get("labels")
    resource_labels = resource.get("labels") if isinstance(resource, Mapping) else None
    scope = project_scope(log_name, resource_labels)
    if (not isinstance(payload, Mapping) or not isinstance(resource, Mapping)
            or payload.get("@type") != "type.googleapis.com/google.cloud.audit.AuditLog"
            or payload.get("serviceName") != "k8s.io" or payload.get("methodName") != _GKE_METHOD
            or resource.get("type") != "k8s_cluster"
            or not isinstance(log_name, str)
            or scope is None
            or isinstance(labels, Mapping) and "command.gke.io/dryRun" in labels):
        return None
    status = payload.get("status")
    if status is not None:
        if not isinstance(status, Mapping):
            return None
        if "code" in status and (type(status["code"]) is not int or status["code"] != 0):
            return None
    request = payload.get("request")
    response = payload.get("response")
    auth = payload.get("authenticationInfo")
    if (not isinstance(request, Mapping) or request.get("dryRun")
            or not isinstance(response, Mapping) or not isinstance(auth, Mapping)
            or not isinstance(resource_labels, Mapping)
            or not isinstance(resource_labels.get("location"), str) or not resource_labels["location"]
            or not isinstance(resource_labels.get("cluster_name"), str) or not resource_labels["cluster_name"]):
        return None
    metadata = response.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    cluster = (scope + f"/locations/{resource_labels['location']}"
               + f"/clusters/{resource_labels['cluster_name']}")
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete", "verb": "update",
        "auditID": record.get("insertId"), "stageTimestamp": record.get("timestamp"),
        "cluster_id": cluster, "user": {"username": auth.get("principalEmail")},
        "objectRef": {"apiGroup": "", "resource": "pods", "subresource": "ephemeralcontainers",
                      "name": metadata.get("name"), "namespace": metadata.get("namespace")},
        "responseStatus": {"code": 200, "status": "Success"},
        "requestObject": request, "responseObject": response,
    }


def _privileged_ephemeral_request(request: Mapping[str, Any], response: Mapping[str, Any]) -> str | None:
    req_spec = request.get("spec")
    res_spec = response.get("spec")
    if not isinstance(req_spec, Mapping) or not isinstance(res_spec, Mapping):
        return None
    requested = req_spec.get("ephemeralContainers")
    returned = res_spec.get("ephemeralContainers")
    containers = res_spec.get("containers")
    if (not isinstance(requested, list) or not isinstance(returned, list)
            or not isinstance(containers, list)):
        return None
    regular_names = {item.get("name") for item in containers if isinstance(item, Mapping)
                     and isinstance(item.get("name"), str) and item["name"]}
    for candidate in requested:
        if not isinstance(candidate, Mapping):
            continue
        name = candidate.get("name")
        target = candidate.get("targetContainerName")
        security = candidate.get("securityContext")
        if (not isinstance(name, str) or not name or not isinstance(target, str)
                or not target or target not in regular_names
                or not isinstance(security, Mapping) or security.get("privileged") is not True):
            continue
        # Ambiguous duplicate names cannot establish which container was
        # accepted. Exact request/response agreement is required.
        req_same = [item for item in requested if isinstance(item, Mapping) and item.get("name") == name]
        res_same = [item for item in returned if isinstance(item, Mapping) and item.get("name") == name]
        if len(req_same) != 1 or len(res_same) != 1:
            continue
        returned_security = res_same[0].get("securityContext")
        if (res_same[0].get("targetContainerName") == target
                and isinstance(returned_security, Mapping)
                and returned_security.get("privileged") is True):
            return name
    return None


def normalize_kubernetes_privileged_ephemeral_update(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a completed update with matching requested and returned Pod spec."""
    if "protoPayload" in record:
        record = _gke_native(record)
        if record is None:
            return None
    if (record.get("apiVersion") != "audit.k8s.io/v1" or record.get("kind") != "Event"
            or record.get("stage") != "ResponseComplete" or record.get("verb") != "update"):
        return None
    uri = record.get("requestURI")
    if isinstance(uri, str) and any(key.lower() == "dryrun" for key, _ in
            parse_qsl(urlsplit(uri).query, keep_blank_values=True)):
        return None
    ref = record.get("objectRef")
    status = record.get("responseStatus")
    request = record.get("requestObject")
    response = record.get("responseObject")
    user = record.get("user")
    if (not isinstance(ref, Mapping) or ref.get("apiGroup") not in (None, "")
            or ref.get("resource") != "pods" or ref.get("subresource") != "ephemeralcontainers"
            or not isinstance(status, Mapping) or type(status.get("code")) is not int
            or status["code"] != 200 or status.get("status") != "Success"
            or not isinstance(request, Mapping) or request.get("apiVersion") != "v1"
            or request.get("kind") != "Pod"
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
    if actor.startswith("system:"):
        match = _SA_ACTOR.fullmatch(actor)
        if match is None or match.group(1) in _SYSTEM_NAMESPACES:
            return None
    req_meta = request.get("metadata")
    res_meta = response.get("metadata")
    if not isinstance(req_meta, Mapping) or not isinstance(res_meta, Mapping):
        return None
    pod = res_meta.get("name")
    namespace = res_meta.get("namespace")
    uid = res_meta.get("uid")
    if (not isinstance(pod, str) or not pod
            or not isinstance(namespace, str) or not namespace or namespace in _SYSTEM_NAMESPACES
            or not isinstance(uid, str) or not uid
            or req_meta.get("name") != pod or req_meta.get("namespace") != namespace
            or req_meta.get("uid") not in (None, uid)
            or ref.get("name") != pod or ref.get("namespace") != namespace):
        return None
    res_spec = response.get("spec")
    if not isinstance(res_spec, Mapping):
        return None
    os = res_spec.get("os")
    if isinstance(os, Mapping) and os.get("name") == "windows":
        return None
    ephemeral_name = _privileged_ephemeral_request(request, response)
    if ephemeral_name is None:
        return None
    return {
        "cloud.provider": "kubernetes", "event.source": "kubernetes.audit",
        "event.name": "update", "event.outcome": "success",
        "event.id": event_id, "event.time": record["stageTimestamp"],
        "account.id": cluster, "actor.id": actor,
        "target.id": f"{namespace}/{pod}", "target.namespace": namespace,
        "target.ephemeral_container": ephemeral_name,
        "pod.privileged_ephemeral_update_observed": True,
        "pod.change_effect": "accepted_state",
    }
