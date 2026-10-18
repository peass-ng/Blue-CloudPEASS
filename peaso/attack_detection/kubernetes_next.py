"""Normalize a completed cluster-admin binding creation for a high-risk subject.

The returned object proves the binding was created at the audit event time.
It does not prove the subject lacked these permissions before, still has them,
or that the actor had malicious intent.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .gke_scope import project_scope, successful_status


_GROUPS = {"system:authenticated", "system:unauthenticated"}
_GKE_METHOD = "io.k8s.authorization.rbac.v1.clusterrolebindings.create"
_NAMESPACE = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?")
_SERVICE_ACCOUNT = re.compile(r"[a-z0-9](?:[-.a-z0-9]*[a-z0-9])?")


def _service_account_actor(value: str) -> bool:
    parts = value.split(":")
    return (len(parts) == 4 and parts[:2] == ["system", "serviceaccount"]
            and len(parts[2]) <= 63 and len(parts[3]) <= 253
            and _NAMESPACE.fullmatch(parts[2]) is not None
            and _SERVICE_ACCOUNT.fullmatch(parts[3]) is not None)


def _timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if parsed.tzinfo is not None else None


def _gke_native_event(record: Mapping[str, Any]) -> dict[str, Any] | None:
    payload = record.get("protoPayload")
    resource = record.get("resource")
    log_name = record.get("logName")
    labels = record.get("labels")
    resource_labels = resource.get("labels") if isinstance(resource, Mapping) else None
    scope = project_scope(log_name, resource_labels)
    if (not isinstance(payload, Mapping) or not isinstance(resource, Mapping)
            or payload.get("@type") != "type.googleapis.com/google.cloud.audit.AuditLog"
            or payload.get("serviceName") != "k8s.io"
            or payload.get("methodName") != _GKE_METHOD
            or resource.get("type") != "k8s_cluster"
            or scope is None
            or isinstance(labels, Mapping) and "command.gke.io/dryRun" in labels):
        return None
    if not successful_status(payload):
        return None
    request = payload.get("request")
    if isinstance(request, Mapping) and request.get("dryRun"):
        return None
    response = payload.get("response")
    auth = payload.get("authenticationInfo")
    if (not isinstance(response, Mapping) or not isinstance(auth, Mapping)
            or not isinstance(resource_labels, Mapping)
            or not isinstance(resource_labels.get("location"), str) or not resource_labels["location"]
            or not isinstance(resource_labels.get("cluster_name"), str) or not resource_labels["cluster_name"]):
        return None
    metadata = response.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    scope += f"/locations/{resource_labels['location']}/clusters/{resource_labels['cluster_name']}"
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete", "verb": "create",
        "auditID": record.get("insertId"), "stageTimestamp": record.get("timestamp"),
        "cluster_id": scope, "user": {"username": auth.get("principalEmail")},
        "objectRef": {"apiGroup": "rbac.authorization.k8s.io", "resource": "clusterrolebindings",
                      "name": metadata.get("name")},
        "responseStatus": {"code": 201, "status": "Success"}, "responseObject": response,
    }


def normalize_kubernetes_cluster_admin_grant(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return only a completed, returned cluster-wide grant to self or all users."""
    if "protoPayload" in record:
        record = _gke_native_event(record)
        if record is None:
            return None
    if (record.get("apiVersion") != "audit.k8s.io/v1" or record.get("kind") != "Event"
            or record.get("stage") != "ResponseComplete" or record.get("verb") != "create"):
        return None
    request_uri = record.get("requestURI")
    try:
        parsed_uri = urlsplit(request_uri) if isinstance(request_uri, str) else None
    except ValueError:
        return None
    if parsed_uri is not None and any(key.lower() == "dryrun" for key, _ in
            parse_qsl(parsed_uri.query, keep_blank_values=True)):
        return None
    ref = record.get("objectRef")
    status = record.get("responseStatus")
    response = record.get("responseObject")
    actor = record.get("user")
    if (not isinstance(ref, Mapping) or ref.get("apiGroup") != "rbac.authorization.k8s.io"
            or ref.get("resource") != "clusterrolebindings"
            or ref.get("namespace") not in (None, "")
            or not isinstance(status, Mapping) or type(status.get("code")) is not int
            or status["code"] != 201 or status.get("status") != "Success"
            or not isinstance(response, Mapping)
            or response.get("apiVersion") != "rbac.authorization.k8s.io/v1"
            or response.get("kind") != "ClusterRoleBinding"
            or not isinstance(actor, Mapping)):
        return None
    actor_name = actor.get("username")
    if (not isinstance(actor_name, str) or not actor_name
            or not isinstance(record.get("auditID"), str) or not record["auditID"]
            or _timestamp(record.get("stageTimestamp")) is None
            or not isinstance(record.get("cluster_id"), str) or not record["cluster_id"]):
        return None
    metadata = response.get("metadata")
    role_ref = response.get("roleRef")
    subjects = response.get("subjects")
    if (not isinstance(metadata, Mapping) or not isinstance(role_ref, Mapping)
            or not isinstance(subjects, list) or not subjects
            or not isinstance(metadata.get("name"), str) or not metadata["name"]
            or not isinstance(metadata.get("uid"), str) or not metadata["uid"]
            or metadata.get("namespace") not in (None, "")
            or ref.get("name") not in (None, metadata["name"])
            or role_ref.get("apiGroup") != "rbac.authorization.k8s.io"
            or role_ref.get("kind") != "ClusterRole" or role_ref.get("name") != "cluster-admin"):
        return None
    human_actor = not actor_name.startswith("system:")
    service_account_actor = _service_account_actor(actor_name)
    selected = next((subject for subject in subjects if isinstance(subject, Mapping)
                     and subject.get("apiGroup") == "rbac.authorization.k8s.io"
                     and ((human_actor and subject.get("kind") == "User"
                           and subject.get("name") == actor_name)
                          or ((human_actor or service_account_actor)
                              and subject.get("kind") == "Group"
                              and subject.get("name") in _GROUPS))), None)
    if selected is None:
        return None
    subject_kind = selected["kind"]
    subject_name = selected["name"]
    return {
        "cloud.provider": "kubernetes", "event.source": "kubernetes.audit",
        "event.name": "create", "event.outcome": "success",
        "event.id": record["auditID"], "event.time": record["stageTimestamp"],
        "account.id": record["cluster_id"], "actor.id": actor_name,
        "target.id": metadata["name"], "target.principal": subject_name,
        "rbac.role": "cluster-admin", "rbac.subject_kind": subject_kind,
        "rbac.subject_name": subject_name,
        "rbac.cluster_admin_binding_created": True,
        "rbac.self_user_grant": subject_kind == "User",
        "rbac.broad_group_grant": subject_kind == "Group",
        "rbac.change_effect": "created_binding",
    }
