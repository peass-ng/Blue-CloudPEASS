"""Cache-only candidate: accepted ClusterRole exposing Secret reads to `view`.

This observes an admitted role object, not controller reconciliation, effective
access, a Secret read, or malicious intent. No Secret body is returned.
"""
from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import parse_qsl, urlsplit

from peaso.attack_detection.gke_scope import project_scope, successful_status
from peaso.attack_detection.kubernetes_pod_next import _time


METHOD = "io.k8s.authorization.rbac.v1.clusterroles.create"
LABEL = "rbac.authorization.k8s.io/aggregate-to-view"


def _gke(row):
    payload, resource = row.get("protoPayload"), row.get("resource")
    resource_labels = resource.get("labels") if isinstance(resource, Mapping) else None
    scope = project_scope(row.get("logName"), resource_labels)
    labels = row.get("labels")
    if (not isinstance(payload, Mapping) or not isinstance(resource, Mapping)
            or payload.get("@type") != "type.googleapis.com/google.cloud.audit.AuditLog"
            or payload.get("serviceName") != "k8s.io" or payload.get("methodName") != METHOD
            or resource.get("type") != "k8s_cluster" or scope is None
            or not successful_status(payload)
            or (labels is not None and not isinstance(labels, Mapping))
            or isinstance(labels, Mapping) and "command.gke.io/dryRun" in labels):
        return None
    request, response, auth = payload.get("request"), payload.get("response"), payload.get("authenticationInfo")
    if (not isinstance(request, Mapping) or "dryRun" in request
            or not isinstance(response, Mapping) or not isinstance(auth, Mapping)
            or not isinstance(resource_labels, Mapping)
            or not isinstance(resource_labels.get("location"), str) or not resource_labels["location"]
            or "/" in resource_labels["location"]
            or not isinstance(resource_labels.get("cluster_name"), str) or not resource_labels["cluster_name"]
            or "/" in resource_labels["cluster_name"]):
        return None
    meta, request_meta = response.get("metadata"), request.get("metadata")
    if (not isinstance(meta, Mapping) or not isinstance(request_meta, Mapping)
            or request_meta.get("name") not in (None, meta.get("name"))):
        return None
    cluster = scope + "/locations/" + resource_labels["location"] + "/clusters/" + resource_labels["cluster_name"]
    return {"apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete", "verb": "create",
            "auditID": row.get("insertId"), "stageTimestamp": row.get("timestamp"), "cluster_id": cluster,
            "user": {"username": auth.get("principalEmail")},
            "objectRef": {"apiGroup": "rbac.authorization.k8s.io", "resource": "clusterroles", "name": meta.get("name")},
            "responseStatus": {"code": 201, "status": "Success"}, "responseObject": response}


def normalize_aggregate_view_secret_read(row):
    if not isinstance(row, Mapping):
        return None
    wrapped = "protoPayload" in row
    if wrapped:
        row = _gke(row)
        if row is None:
            return None
    if (row.get("apiVersion") != "audit.k8s.io/v1" or row.get("kind") != "Event"
            or row.get("stage") != "ResponseComplete" or row.get("verb") != "create"):
        return None
    uri = row.get("requestURI")
    if not wrapped and not isinstance(uri, str):
        return None
    try:
        parsed = urlsplit(uri) if isinstance(uri, str) else None
    except ValueError:
        return None
    if parsed is not None and (parsed.path != "/apis/rbac.authorization.k8s.io/v1/clusterroles"
                               or any(k.lower() == "dryrun" for k, _ in parse_qsl(parsed.query, keep_blank_values=True))):
        return None
    ref, status, response, user = (row.get(k) for k in ("objectRef", "responseStatus", "responseObject", "user"))
    if (not isinstance(ref, Mapping) or ref.get("apiGroup") != "rbac.authorization.k8s.io"
            or ref.get("resource") != "clusterroles" or ref.get("namespace") not in (None, "")
            or ref.get("subresource") not in (None, "")
            or not isinstance(status, Mapping) or type(status.get("code")) is not int or status["code"] != 201
            or status.get("status") != "Success" or not isinstance(response, Mapping)
            or response.get("apiVersion") != "rbac.authorization.k8s.io/v1"
            or response.get("kind") != "ClusterRole" or not isinstance(user, Mapping)):
        return None
    actor, event_id, cluster, when = user.get("username"), row.get("auditID"), row.get("cluster_id"), row.get("stageTimestamp")
    if (not isinstance(actor, str) or not actor or actor.startswith("system:")
            or not isinstance(event_id, str) or not event_id
            or not isinstance(cluster, str) or not cluster or _time(when) is None):
        return None
    meta, rules = response.get("metadata"), response.get("rules")
    if not isinstance(meta, Mapping) or not isinstance(rules, list):
        return None
    name, uid, labels = meta.get("name"), meta.get("uid"), meta.get("labels")
    if (not isinstance(name, str) or not name or not isinstance(uid, str) or not uid
            or name == "view" or meta.get("namespace") not in (None, "")
            or ref.get("name") not in (None, name)
            or not isinstance(labels, Mapping) or labels.get(LABEL) != "true"):
        return None
    # Require a direct, namespace-wide Secret read rule. An explicitly named
    # Secret or a different API group is a different, narrower observation.
    matched = False
    for rule in rules:
        if not isinstance(rule, Mapping):
            continue
        groups, resources, verbs = rule.get("apiGroups"), rule.get("resources"), rule.get("verbs")
        if (isinstance(groups, list) and "" in groups
                and isinstance(resources, list) and "secrets" in resources
                and isinstance(verbs, list) and any(verb in verbs for verb in ("get", "list", "watch"))
                and not rule.get("resourceNames") and not rule.get("nonResourceURLs")):
            matched = True
            break
    if not matched:
        return None
    return {"cloud.provider": "kubernetes", "event.source": "kubernetes.audit", "event.name": "create",
            "event.outcome": "success", "event.id": event_id, "event.time": when,
            "account.id": cluster, "actor.id": actor, "target.id": name,
            "rbac.aggregate_to_view_secret_read_role_accepted": True,
            "rbac.change_effect": "admitted_role_spec"}
