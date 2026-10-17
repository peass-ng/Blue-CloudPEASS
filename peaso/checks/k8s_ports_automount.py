"""Canonical Pod automount implementation for the registry owner's replacement.

No second equivalent registry ID is created. Registry adoption must retain
k8s.pod.restrict_token_automount and declare pod/serviceaccount dependencies.
"""
from . import result, unknown
from .facts import get, optional, guard, list_of_objects, Unavailable

CANONICAL_ID = "k8s.pod.restrict_token_automount"
DEPENDENCIES = ("pod", "serviceaccount")
TITLE = "Pod disables automatic token mounting through Pod or ServiceAccount metadata"


def evaluate_token_automount(item, index):
    try:
        spec = get(item, "spec", dict)
        value = optional(spec, "automountServiceAccountToken", None, (bool, type(None)))
        if value is not None:
            return result(value, automount_service_account_token=value, configured_at="pod",
                semantics="Explicit Pod metadata takes precedence over ServiceAccount; no token or effective access is read")
        namespace = get(item, "metadata.namespace", str)
        name = optional(spec, "serviceAccountName", "default", str) or "default"
        cluster = optional(item, "provenance", {}, dict).get("cluster_id") or index.get("context", {}).get("metadata", {}).get("cluster_id")
        if not isinstance(cluster, str) or not cluster:
            return unknown("Pod cluster identity needed for the ServiceAccount metadata join")
        context_cluster = index.get("context", {}).get("metadata", {}).get("cluster_id")
        if context_cluster is not None and context_cluster != cluster:
            return unknown("Pod cluster does not match the snapshot context")
        collections = list_of_objects(index.get("collections", {}).get("serviceaccount", []))
        selected = [row for row in collections if row.get("scope") in ("*", namespace)]
        if not selected or any(row.get("status") not in ("collected", "empty") for row in selected):
            return unknown("ServiceAccount metadata inventory missing, denied or incomplete for this namespace")
        matches = []
        for resource in list_of_objects(index.get("serviceaccount", [])):
            account = get(resource, "data", dict)
            meta = get(account, "metadata", dict)
            if meta.get("namespace") != namespace or meta.get("name") != name:
                continue
            if get(account, "provenance.cluster_id", str) == cluster:
                matches.append(account)
        if len(matches) != 1:
            return unknown("ServiceAccount relation missing or ambiguous for exact cluster/namespace/name")
        inherited = optional(matches[0], "automountServiceAccountToken", None, (bool, type(None)))
        effective = True if inherited is None else inherited
        return result(effective, automount_service_account_token=effective,
            configured_at="serviceaccount" if inherited is not None else "documented_kubernetes_default",
            service_account=name, namespace=namespace, semantics="Pod/ServiceAccount automount precedence and documented default true; no Secret value or token contents")
    except Unavailable as exc:
        return unknown(str(exc))
    except (ValueError, TypeError, KeyError, AttributeError):
        return unknown("malformed Pod/ServiceAccount automount metadata")
