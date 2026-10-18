"""Reviewed, source-bound Kubernetes pivots that inventory metadata cannot prove.

The collection contains attestations, never Secret data or private keys. Every
target is named from an exact accepted principal or an exact permission gain.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import re

from . import Node, inventory_status, items
from .credential_evidence import exact_text, https_endpoint


COLLECTION = "k8s_verified_pivot_evidence"
ARGO = "k8s-rbac-secrets-read-argocd-cluster-credential"
GOOGLE_KEY = "k8s-cloud-pivot-secret-static-gcp-sa-key"
GKE_GRANT = "k8s-gke-authenticated-user-rolebinding-self-grant"
KIAM = "k8s-cloud-kiam-kube2iam-annotation"
TECHNIQUES = frozenset((ARGO, GOOGLE_KEY, GKE_GRANT, KIAM))
KINDS = {ARGO: "k8s_remote_cluster", GOOGLE_KEY: "cloud_identity",
         GKE_GRANT: "k8s_verified_authority", KIAM: "cloud_identity"}
GOOGLE_EMAIL = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.iam\.gserviceaccount\.com$")
AWS_ROLE = re.compile(r"^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/\-]+$")


def _fresh(snapshot, record):
    def parse(value):
        if not isinstance(value, str):
            raise ValueError("missing timestamp")
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("timezone required")
        return stamp
    try:
        captured = parse(snapshot.get("created_at"))
        observed = parse(record.get("EvidenceObservedAt"))
        return observed <= captured and 0 <= (captured - observed).total_seconds() <= 900
    except (TypeError, ValueError, OverflowError):
        return False


def _permission(record, provider):
    permission = record.get("NewPermission")
    return (isinstance(permission, dict) and set(permission) == {"Provider", "Action", "Resource"}
            and permission.get("Provider") == provider
            and all(exact_text(permission.get(key)) for key in ("Action", "Resource"))
            and record.get("SourcePreviouslyDenied") is True
            and record.get("TargetPermissionAllowed") is True)


def _identity(record):
    technique = record.get("TechniqueId")
    if technique == ARGO:
        return (record.get("RemoteClusterId"), record.get("CredentialSubjectId"))
    if technique == GOOGLE_KEY:
        return (record.get("GoogleServiceAccountEmail"), record.get("GoogleKeyId"))
    if technique == GKE_GRANT:
        permission = record.get("NewPermission") or {}
        return (record.get("AuthenticatedSubject"), record.get("BindingNamespace"),
                permission.get("Action"), permission.get("Resource"))
    if technique == KIAM:
        return (record.get("RoleArn"), record.get("PodUID"))
    return ()


def _base(record, cluster, snapshot):
    if (not isinstance(record, dict) or record.get("TechniqueId") not in TECHNIQUES
            or record.get("Status") != "verified" or record.get("ClusterId") != cluster
            or not exact_text(record.get("SourceId"))
            or not exact_text(record.get("EvidenceRef")) or not _fresh(snapshot, record)
            or not all(exact_text(value) for value in _identity(record))):
        return False
    technique = record["TechniqueId"]
    if technique in (ARGO, GOOGLE_KEY):
        return (all(exact_text(record.get(key)) for key in
                    ("SecretNamespace", "SecretName", "SecretUID", "SecretResourceVersion"))
                and record.get("SecretReadAction") in ("get", "list", "watch")
                and record.get("SecretReadAccepted") is True
                and record.get("CredentialUsable") is True
                and _permission(record, "k8s" if technique == ARGO else "gcp"))
    if technique == GKE_GRANT:
        permission = record.get("NewPermission") or {}
        return (all(exact_text(record.get(key)) for key in
                    ("BindingNamespace", "BindingName", "BindingUID", "BindingResourceVersion",
                     "AuthenticatedSubject", "ObservedWhoamiSubject"))
                and record.get("ObservedWhoamiSubject") == record.get("AuthenticatedSubject")
                and record.get("BindingSubject") == record.get("AuthenticatedSubject")
                and record.get("BindingRoleKind") == "ClusterRole"
                and record.get("BindingRoleName") == "view"
                and record.get("BindingAction") in ("create", "patch", "update")
                and record.get("BindingAccepted") is True
                and record.get("GoogleCredentialControlledBySource") is True
                and permission.get("Action") == "get" and permission.get("Resource") == "pods"
                and _permission(record, "k8s"))
    return (all(exact_text(record.get(key)) for key in
                ("PodNamespace", "PodName", "PodUID", "PodResourceVersion", "RoleArn",
                 "ProxyNamespace", "ProxyPodName", "ProxyPodUID", "ProxyPodResourceVersion"))
            and bool(AWS_ROLE.fullmatch(record["RoleArn"]))
            and record.get("ProxyMode") in ("kiam", "kube2iam")
            and record.get("PodCreateAccepted") is True
            and record.get("PodRunning") is True
            and record.get("ProxyRunning") is True
            and record.get("NamespacePolicyAllowsRole") is True
            and record.get("RoleTrustAccepted") is True
            and record.get("StsCredentialDelivered") is True
            and record.get("CredentialIssuerRoleArn") == record["RoleArn"]
            and _permission(record, "aws"))


def _target_id(record):
    material = "\x00".join([record["TechniqueId"], record["ClusterId"],
                          *map(str, _identity(record))])
    return f"k8s:verified-pivot:{record['TechniqueId']}:{sha256(material.encode()).hexdigest()[:24]}"


def load(model):
    """Build exact targets only from a complete collected reviewed record."""
    status = inventory_status(model.snapshot, COLLECTION)
    unique_collections = {scope for scope, state in status.items()
                          if state == "collected" and sum(
                              c.get("type") == COLLECTION and c.get("scope") == scope
                              for c in model.snapshot.get("collections", ())) == 1}
    records = {}
    nodes = {}
    for cluster, record in items(model.snapshot, COLLECTION):
        if cluster not in unique_collections or not _base(record, cluster, model.snapshot):
            continue
        target_id = _target_id(record)
        technique = record["TechniqueId"]
        attrs = {"cluster": cluster, "technique": technique, "variant": "verified_pivot"}
        if technique in (ARGO, GOOGLE_KEY):
            attrs.update({"namespace": record["SecretNamespace"], "name": record["SecretName"]})
        elif technique == GKE_GRANT:
            attrs.update({"namespace": record["BindingNamespace"], "name": record["BindingRoleName"]})
        else:
            attrs.update({"namespace": record["PodNamespace"], "name": record["PodName"],
                          "external_id": record["RoleArn"]})
        label = {ARGO: f"{record.get('CredentialSubjectId')} in {record.get('RemoteClusterId')}",
                 GOOGLE_KEY: str(record.get("GoogleServiceAccountEmail")),
                 GKE_GRANT: f"{record.get('AuthenticatedSubject')}: get pods in {record.get('BindingNamespace')}",
                 KIAM: str(record.get("RoleArn"))}[technique]
        nodes[target_id] = Node(target_id, KINDS[technique], "k8s", cluster, label,
                                attrs=attrs, entity=technique == GKE_GRANT)
        records.setdefault((technique, record["SourceId"], target_id), []).append(record)
    return nodes, records


def _secret(model, record):
    cluster = record["ClusterId"]
    key = cluster, record["SecretNamespace"], record["SecretName"]
    if (model.secret_uids.get(key) != [record["SecretUID"]]
            or model.secret_versions.get(key) != [record["SecretResourceVersion"]]):
        return False
    matches = [(typ, labels) for c, ns, name, typ, labels, _ in model.secrets
               if (c, ns, name) == key]
    if len(matches) != 1:
        return False
    if record["TechniqueId"] == ARGO:
        return matches[0][1].get("argocd.argoproj.io/secret-type") == "cluster"
    return matches[0][0] != "kubernetes.io/service-account-token"


def _record_matches(model, record, source, target):
    from .k8s import _kube2iam_permits

    if (record.get("SourceId") != source.id or source.attrs.get("cluster") != record["ClusterId"]
            or target.kind != KINDS[record["TechniqueId"]]
            or target.attrs.get("cluster") != record["ClusterId"]):
        return False
    technique = record["TechniqueId"]
    if technique in (ARGO, GOOGLE_KEY):
        if not _secret(model, record):
            return False
        action = record["SecretReadAction"]
        grant = model.check(source, {"verb": action, "resource": "secrets",
                                     "namespace": record["SecretNamespace"]},
                            (record["SecretNamespace"], record["SecretName"], None))
        if grant is None or grant.confidence == "unknown":
            return False
        if technique == ARGO:
            return (record.get("RemoteClusterId") != record["ClusterId"]
                    and https_endpoint(record.get("RemoteServer"))
                    and record.get("CredentialKind") in ("k8s_bearer_token", "k8s_client_certificate")
                    and record.get("RemoteAuthenticationAccepted") is True)
        return (bool(GOOGLE_EMAIL.fullmatch(record["GoogleServiceAccountEmail"]))
                and record.get("CredentialKind") == "gcp_service_account_json_key"
                and record.get("GoogleTokenSubject") == record["GoogleServiceAccountEmail"]
                and record.get("GoogleTokenAccepted") is True
                and record.get("GoogleKeyActive") is True)
    if technique == GKE_GRANT:
        if source.kind != "k8s_user" or source.attrs.get("user") != record["AuthenticatedSubject"]:
            return False
        ns = record["BindingNamespace"]
        bindings = [item for _, item in items(model.snapshot, "rolebinding")
                    if item.get("provenance", {}).get("cluster_id") == record["ClusterId"]
                    and (item.get("metadata") or {}).get("namespace") == ns
                    and (item.get("metadata") or {}).get("name") == record["BindingName"]]
        if len(bindings) != 1:
            return False
        binding = bindings[0]
        meta = binding.get("metadata") or {}
        role_ref = binding.get("roleRef") or {}
        if (meta.get("uid") != record["BindingUID"]
                or meta.get("resourceVersion") != record["BindingResourceVersion"]
                or role_ref.get("kind") != "ClusterRole" or role_ref.get("name") != "view"
                or {"kind": "User", "name": record["AuthenticatedSubject"]} not in (binding.get("subjects") or [])):
            return False
        write = model.check(source, {"verb": record["BindingAction"], "resource": "rolebindings",
                                     "api_group": "rbac.authorization.k8s.io", "namespace": ns},
                            (ns, record["BindingName"], None))
        bind = model.check(source, {"verb": "bind", "resource": "clusterroles",
                                    "api_group": "rbac.authorization.k8s.io", "namespace": "*"},
                           (None, "view", None))
        after = model.check(source, {"verb": "get", "resource": "pods", "namespace": ns},
                            (ns, None, None))
        return bool(write and bind and after and all(
            grant.confidence != "unknown" for grant in (write, bind, after)))
    ns = record["PodNamespace"]
    pods = [item for _, item in items(model.snapshot, "pod")
            if item.get("provenance", {}).get("cluster_id") == record["ClusterId"]
            and (item.get("metadata") or {}).get("namespace") == ns
            and (item.get("metadata") or {}).get("name") == record["PodName"]]
    if len(pods) != 1:
        return False
    pod = pods[0]
    meta = pod.get("metadata") or {}
    if (meta.get("uid") != record["PodUID"]
            or meta.get("resourceVersion") != record["PodResourceVersion"]
            or (meta.get("annotations") or {}).get("iam.amazonaws.com/role") != record["RoleArn"]
            or (pod.get("status") or {}).get("phase") != "Running"):
        return False
    proxies = [item for _, item in items(model.snapshot, "pod")
               if item.get("provenance", {}).get("cluster_id") == record["ClusterId"]
               and (item.get("metadata") or {}).get("namespace") == record["ProxyNamespace"]
               and (item.get("metadata") or {}).get("name") == record["ProxyPodName"]]
    if len(proxies) != 1:
        return False
    proxy = proxies[0]
    proxy_meta = proxy.get("metadata") or {}
    if (proxy_meta.get("uid") != record["ProxyPodUID"]
            or proxy_meta.get("resourceVersion") != record["ProxyPodResourceVersion"]
            or (proxy.get("status") or {}).get("phase") != "Running"):
        return False
    rules = model.ns_annotations.get(record["ClusterId"], {}).get(ns)
    if not rules or _kube2iam_permits([rules], record["RoleArn"], record["RoleArn"].rsplit("/", 1)[-1]) is not True:
        return False
    grant = model.check(source, {"verb": "create", "resource": "pods", "namespace": ns},
                        (ns, record["PodName"], None))
    return bool(grant and grant.confidence != "unknown")


def select(model, technique, candidates, source, pivot=None):
    if source is None:
        return {}
    out = {}
    for target_id, target in candidates.items():
        records = model.verified_pivot_records.get((technique, source.id, target_id), ())
        if (technique == GKE_GRANT and not any(
                p.get("pivot.namespace") == target.attrs.get("namespace") for p in (pivot or ()))):
            continue
        if len(records) == 1 and _record_matches(model, records[0], source, target):
            out[target_id] = ("conditional", "reviewed_exact_principal_or_permission_gain")
    return out
