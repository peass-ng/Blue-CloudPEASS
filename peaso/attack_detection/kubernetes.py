"""Normalize completed Kubernetes RBAC changes with returned object evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}
RBAC_CREATE_METHODS = {
    "io.k8s.authorization.rbac.v1.clusterrolebindings.create": ("clusterrolebindings", "ClusterRoleBinding"),
    "io.k8s.authorization.rbac.v1.rolebindings.create": ("rolebindings", "RoleBinding"),
}


def normalize_kubernetes_audit(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if "protoPayload" in record:
        payload = record.get("protoPayload")
        resource = record.get("resource")
        labels = record.get("labels")
        if not isinstance(payload, Mapping) or not isinstance(resource, Mapping):
            return None
        if payload.get("@type") != "type.googleapis.com/google.cloud.audit.AuditLog" or payload.get("serviceName") != "k8s.io":
            return None
        binding = RBAC_CREATE_METHODS.get(payload.get("methodName"))
        if binding is None or resource.get("type") != "k8s_cluster":
            return None
        log_name = record.get("logName")
        if not isinstance(log_name, str) or not log_name.endswith("/logs/cloudaudit.googleapis.com%2Factivity"):
            return None
        if isinstance(labels, Mapping) and "command.gke.io/dryRun" in labels:
            return None
        status = payload.get("status")
        if isinstance(status, Mapping) and status.get("code") not in (None, 0):
            return None
        response = payload.get("response")
        if not isinstance(response, Mapping) or response.get("kind") != binding[1]:
            return None
        metadata = response.get("metadata")
        metadata = metadata if isinstance(metadata, Mapping) else {}
        auth = payload.get("authenticationInfo")
        auth = auth if isinstance(auth, Mapping) else {}
        resource_labels = resource.get("labels")
        resource_labels = resource_labels if isinstance(resource_labels, Mapping) else {}
        scope = log_name.split("/logs/", 1)[0]
        if resource_labels.get("location") and resource_labels.get("cluster_name"):
            scope += f"/locations/{resource_labels['location']}/clusters/{resource_labels['cluster_name']}"
        record = {
            "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete", "verb": "create",
            "auditID": record.get("insertId"), "stageTimestamp": record.get("timestamp"),
            "cluster_id": scope,
            "user": {"username": auth.get("principalEmail")},
            "objectRef": {"apiGroup": "rbac.authorization.k8s.io", "resource": binding[0],
                          "name": metadata.get("name"), "namespace": metadata.get("namespace")},
            "responseStatus": {"code": 201, "status": "Success"}, "responseObject": response,
        }
    if record.get("apiVersion") != "audit.k8s.io/v1" or record.get("kind") != "Event":
        return None
    if record.get("stage") != "ResponseComplete" or record.get("verb") != "create":
        return None
    request_uri = record.get("requestURI")
    if isinstance(request_uri, str) and "dryRun=" in request_uri:
        return None
    object_ref = record.get("objectRef")
    object_ref = object_ref if isinstance(object_ref, Mapping) else {}
    resource_name = object_ref.get("resource")
    if object_ref.get("apiGroup") != "rbac.authorization.k8s.io" or resource_name not in {"clusterrolebindings", "rolebindings"}:
        return None
    status = record.get("responseStatus")
    status = status if isinstance(status, Mapping) else {}
    if status.get("code") != 201 or status.get("status") != "Success":
        return None
    response = record.get("responseObject")
    expected_kind = "RoleBinding" if resource_name == "rolebindings" else "ClusterRoleBinding"
    if not isinstance(response, Mapping) or response.get("kind") != expected_kind:
        return None
    role = response.get("roleRef")
    role = role if isinstance(role, Mapping) else {}
    if role.get("apiGroup") != "rbac.authorization.k8s.io" or role.get("kind") != "ClusterRole" or role.get("name") != "cluster-admin":
        return None
    metadata = response.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    binding_name = metadata.get("name")
    if not isinstance(binding_name, str) or not binding_name:
        return None
    if object_ref.get("name") not in (None, binding_name):
        return None
    namespace = metadata.get("namespace")
    if resource_name == "rolebindings":
        if not isinstance(namespace, str) or not namespace or namespace in SYSTEM_NAMESPACES:
            return None
        if object_ref.get("namespace") != namespace:
            return None
    subjects = response.get("subjects")
    if not isinstance(subjects, list):
        return None
    actor = record.get("user")
    actor = actor if isinstance(actor, Mapping) else {}
    actor_name = actor.get("username")
    privileged_subject = next((s for s in subjects if isinstance(s, Mapping)
        and s.get("kind") == "ServiceAccount" and isinstance(s.get("name"), str) and s.get("name")
        and isinstance(s.get("namespace"), str) and s.get("namespace") not in SYSTEM_NAMESPACES
        and (resource_name == "clusterrolebindings" or
             (s.get("namespace") == namespace and actor_name == f"system:serviceaccount:{namespace}:{s['name']}"))), None)
    if privileged_subject is None:
        return None
    return {
        "cloud.provider": "kubernetes",
        "event.name": "create",
        "event.source": "kubernetes.audit",
        "event.outcome": "success",
        "event.id": record.get("auditID"),
        "event.time": record.get("stageTimestamp"),
        "account.id": record.get("cluster_id"),
        "actor.id": actor.get("username"),
        "target.id": binding_name,
        "target.principal": f"system:serviceaccount:{privileged_subject['namespace']}:{privileged_subject['name']}",
        "rbac.role": "cluster-admin",
        "rbac.non_system_service_account": True,
        "rbac.self_namespace_service_account": resource_name == "rolebindings",
    }
