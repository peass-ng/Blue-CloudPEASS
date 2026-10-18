"""Normalize completed Kubernetes RBAC changes with returned object evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlsplit


SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}
RBAC_WRITE_METHODS = {
    f"io.k8s.authorization.rbac.v1.{resource}.{verb}": (resource, kind, verb)
    for resource, kind in (("clusterrolebindings", "ClusterRoleBinding"),
                           ("rolebindings", "RoleBinding"))
    for verb in ("create", "update", "patch")
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
        binding = RBAC_WRITE_METHODS.get(payload.get("methodName"))
        if binding is None or resource.get("type") != "k8s_cluster":
            return None
        log_name = record.get("logName")
        if not isinstance(log_name, str) or not log_name.endswith("/logs/cloudaudit.googleapis.com%2Factivity"):
            return None
        if isinstance(labels, Mapping) and "command.gke.io/dryRun" in labels:
            return None
        status = payload.get("status")
        if "status" in payload and not isinstance(status, Mapping):
            return None
        code = status.get("code") if isinstance(status, Mapping) else None
        if isinstance(status, Mapping) and "code" in status and (type(code) is not int or code != 0):
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
            "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete", "verb": binding[2],
            "auditID": record.get("insertId"), "stageTimestamp": record.get("timestamp"),
            "cluster_id": scope,
            "user": {"username": auth.get("principalEmail")},
            "objectRef": {"apiGroup": "rbac.authorization.k8s.io", "resource": binding[0],
                          "name": metadata.get("name"), "namespace": metadata.get("namespace")},
            "responseStatus": {"code": 201 if binding[2] == "create" else 200, "status": "Success"},
            "responseObject": response,
        }
    if record.get("apiVersion") != "audit.k8s.io/v1" or record.get("kind") != "Event":
        return None
    verb = record.get("verb")
    if record.get("stage") != "ResponseComplete" or verb not in {"create", "update", "patch"}:
        return None
    request_uri = record.get("requestURI")
    if isinstance(request_uri, str) and any(key.lower() == "dryrun" for key, _ in parse_qsl(urlsplit(request_uri).query, keep_blank_values=True)):
        return None
    object_ref = record.get("objectRef")
    object_ref = object_ref if isinstance(object_ref, Mapping) else {}
    resource_name = object_ref.get("resource")
    if object_ref.get("apiGroup") != "rbac.authorization.k8s.io" or resource_name not in {"clusterrolebindings", "rolebindings"}:
        return None
    status = record.get("responseStatus")
    status = status if isinstance(status, Mapping) else {}
    # A 201 on a PUT/PATCH can mean the resource was created. Keep update
    # coverage to completed updates of an existing binding with 200 OK.
    allowed_codes = {201} if verb == "create" else {200}
    if status.get("code") not in allowed_codes or status.get("status") != "Success":
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
    if verb in {"update", "patch"} and object_ref.get("name") != binding_name:
        return None
    if verb == "create" and object_ref.get("name") not in (None, binding_name):
        return None
    namespace = metadata.get("namespace")
    if resource_name == "rolebindings":
        if not isinstance(namespace, str) or not namespace or namespace in SYSTEM_NAMESPACES:
            return None
        if object_ref.get("namespace") != namespace:
            return None
    elif namespace not in (None, "") or object_ref.get("namespace") not in (None, ""):
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
        "event.name": verb,
        "event.source": "kubernetes.audit",
        "event.outcome": "success",
        "event.id": record.get("auditID"),
        "event.time": record.get("stageTimestamp"),
        "account.id": record.get("cluster_id"),
        "actor.id": actor.get("username"),
        "target.id": binding_name,
        "target.principal": f"system:serviceaccount:{privileged_subject['namespace']}:{privileged_subject['name']}",
        "rbac.role": "cluster-admin",
        "rbac.observed_cluster_admin_binding": True,
        "rbac.change_effect": "observed_state",
        "rbac.non_system_service_account": True,
        "rbac.self_namespace_service_account": resource_name == "rolebindings",
    }
