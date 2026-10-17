"""Validate metadata-only proofs of scoped credentials, without storing secrets.

These attestations supplement inventory and effective permission checks. A valid
proof authorizes only the named subject, audience and rights, never the subject's
unrestricted cloud identity.
"""
from datetime import datetime
from urllib.parse import urlsplit


def exact_text(value):
    return isinstance(value, str) and bool(value.strip()) and value == value.strip() and not any(
        char in value for char in ("*", "?", "\n", "\r", "\x00"))


def fresh_credential(snapshot, fact, *, kinds, conditions):
    if not isinstance(fact, dict):
        return False
    if (fact.get("Status") != "verified" or fact.get("VerifiedPreconditions") is not True
            or fact.get("CredentialUsable") is not True or fact.get("RevocationChecked") is not True
            or not isinstance(fact.get("CredentialKind"), str)
            or fact.get("CredentialKind") not in kinds
            or not all(exact_text(fact.get(key)) for key in
                       ("EvidenceRef", "CredentialSubjectId", "CredentialScope", "CredentialAudience"))):
        return False
    verified = fact.get("VerifiedConditionIds")
    if not isinstance(verified, list) or any(not isinstance(item, str) for item in verified):
        return False
    if sorted(verified) != sorted(conditions):
        return False
    rights = fact.get("EffectiveRights")
    if (not isinstance(rights, list) or not rights or any(not exact_text(right) for right in rights)
            or len(rights) != len(set(rights))):
        return False

    def instant(value):
        if not isinstance(value, str):
            raise ValueError("missing timestamp")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp needs timezone")
        return parsed

    try:
        captured = instant(snapshot.get("created_at"))
        observed = instant(fact.get("EvidenceObservedAt"))
        expiry = instant(fact.get("CredentialExpiresAt"))
        return observed <= captured < expiry and (captured - observed).total_seconds() <= 900
    except (TypeError, ValueError, OverflowError):
        return False


def https_endpoint(value):
    if not exact_text(value):
        return False
    try:
        parts = urlsplit(value)
        return (parts.scheme == "https" and bool(parts.hostname) and not parts.username
                and not parts.password and not parts.query and not parts.fragment
                and parts.port != 0)
    except ValueError:
        return False


ARGOCD_MOUNT = "k8s-workloads-pods-mount-argocd-cluster-credential"
ARGOCD_CONDITIONS = ("same_namespace_and_admitted_pod", "usable_remote_cluster_credential")
LEGACY_SA_TOKEN = "k8s-rbac-secrets-read-legacy-sa-token"
LEGACY_SA_CONDITIONS = ("legacy_sa_token_secret_exists", "get_requires_secret_name")
CREATED_SA_TOKEN = "k8s-rbac-secrets-create-sa-token-secret"
CREATED_SA_CONDITIONS = ("admission_blocks_sa_token_secret",)
SCOPED_IDS = frozenset({ARGOCD_MOUNT,
    "azure-audit-microsoftstoragestorageaccountslocalusersregeneratepasswordaction",
    "azure-audit-microsoftstoragestorageaccountslocaluserswrite-microsoftstoragestorageac"})


def argocd_credential(model, fact, source, target):
    """Bind a current Secret UID, admitted workload and accepted remote subject."""
    attrs = target.attrs
    cluster, namespace, name = (attrs.get(key) for key in ("cluster", "namespace", "name"))
    for kind in ("secret_metadata", "k8s_privesc_challenge_evidence"):
        scopes = {cluster} if kind == "k8s_privesc_challenge_evidence" else {cluster, "*", namespace, f"{cluster}/{namespace}"}
        reads = [c for c in model.snapshot.get("collections", []) if c.get("type") == kind and c.get("scope") in scopes]
        if len(reads) != 1 or reads[0].get("status") != "collected":
            return False
    captured_cluster = model.snapshot.get("metadata", {}).get("cluster_id")
    if (captured_cluster is not None and captured_cluster != cluster):
        return False
    if (source.attrs.get("cluster") != cluster
            or fact.get("TechniqueId") != ARGOCD_MOUNT or fact.get("SourceId") != source.id
            or fact.get("TargetKind") != "k8s_remote_cluster" or fact.get("TargetId") != target.id
            or fact.get("TargetScope") != cluster or fact.get("SecretNamespace") != namespace
            or fact.get("SecretName") != name
            or not exact_text(fact.get("SecretUID"))
            or model.secret_uids.get((cluster, namespace, name)) != [fact["SecretUID"]]
            or not exact_text(fact.get("SecretResourceVersion"))
            or model.secret_versions.get((cluster, namespace, name)) != [fact["SecretResourceVersion"]]
            or fact.get("WorkloadNamespace") != namespace
            or fact.get("WorkloadAdmitted") is not True or fact.get("SecretMountVerified") is not True
            or not exact_text(fact.get("RemoteClusterId")) or fact["RemoteClusterId"] == cluster
            or not https_endpoint(fact.get("RemoteServer"))
            or not exact_text(fact.get("RemoteAcceptedAudience"))
            or fact.get("CredentialAudience") != fact["RemoteAcceptedAudience"]
            or fact.get("CredentialScope") != fact["RemoteClusterId"]
            or fact.get("RemoteAuthorizationVerified") is not True):
        return False
    resources = {"pods": "", "deployments": "apps", "daemonsets": "apps", "statefulsets": "apps",
                 "replicasets": "apps", "replicationcontrollers": "", "jobs": "batch", "cronjobs": "batch"}
    resource = fact.get("WorkloadResource")
    if not isinstance(resource, str) or resource not in resources or fact.get("WorkloadApiGroup") != resources[resource]:
        return False
    grant = model.check(source, {"verb": "create", "resource": resource,
                                 "api_group": resources[resource], "namespace": namespace},
                        (namespace, None, None))
    if grant is None or grant.confidence == "unknown":
        return False
    return fresh_credential(model.snapshot, fact,
                            kinds={"k8s_bearer_token", "k8s_client_certificate"},
                            conditions=ARGOCD_CONDITIONS)


def legacy_sa_token_credential(model, fact, source, target, *, created=False):
    """Require an exact readable Secret and a freshly accepted token for this SA."""
    if target.kind != "k8s_service_account" or not target.attrs.get("inventoried"):
        return False
    cluster, namespace, sa_name = (target.attrs.get(key) for key in ("cluster", "namespace", "name"))
    name = fact.get("SecretName")
    if not exact_text(name):
        return False
    for kind in ("secret_metadata", "k8s_privesc_challenge_evidence"):
        scopes = {cluster} if kind == "k8s_privesc_challenge_evidence" else {cluster, "*", namespace, f"{cluster}/{namespace}"}
        reads = [c for c in model.snapshot.get("collections", []) if c.get("type") == kind and c.get("scope") in scopes]
        if len(reads) != 1 or reads[0].get("status") != "collected":
            return False
    matches = [(typ, annotations) for c, ns, secret_name, typ, _labels, annotations in model.secrets
               if (c, ns, secret_name) == (cluster, namespace, name)]
    if (len(matches) != 1 or matches[0][0] != "kubernetes.io/service-account-token"
            or matches[0][1].get("kubernetes.io/service-account.name") != sa_name
            or model.secret_uids.get((cluster, namespace, name)) != [fact.get("SecretUID")]
            or model.secret_versions.get((cluster, namespace, name)) != [fact.get("SecretResourceVersion")]
            or not exact_text(fact.get("SecretUID"))
            or not exact_text(fact.get("SecretResourceVersion"))):
        return False
    action = fact.get("SecretReadAction")
    if action not in ("get", "list", "watch"):
        return False
    grant = model.check(source, {"verb": action, "resource": "secrets", "namespace": namespace},
                        (namespace, name, None))
    if created:
        create = model.check(source, {"verb": "create", "resource": "secrets", "namespace": namespace},
                             (namespace, name, None))
        if (create is None or create.confidence == "unknown"
                or fact.get("SecretCreateAccepted") is not True
                or fact.get("TokenControllerPopulated") is not True):
            return False
    technique = CREATED_SA_TOKEN if created else LEGACY_SA_TOKEN
    if (grant is None or grant.confidence == "unknown"
            or fact.get("TechniqueId") != technique or fact.get("SourceId") != source.id
            or fact.get("TargetKind") != "k8s_service_account" or fact.get("TargetId") != target.id
            or fact.get("TargetScope") != cluster or fact.get("SecretNamespace") != namespace
            or fact.get("SecretReadAccepted") is not True or fact.get("ApiServerTokenAccepted") is not True
            or fact.get("CredentialSubjectId") != target.attrs.get("user")
            or fact.get("CredentialScope") != cluster
            or fact.get("CredentialAudience") != fact.get("ApiServerAcceptedAudience")
            or fact.get("SourcePreviouslyDenied") is not True
            or not exact_text(fact.get("NewEffectivePermission"))
            or fact.get("NewEffectivePermission") not in (fact.get("EffectiveRights") or ())):
        return False
    return fresh_credential(model.snapshot, fact, kinds={"k8s_bearer_token"},
                            conditions=CREATED_SA_CONDITIONS if created else LEGACY_SA_CONDITIONS)
