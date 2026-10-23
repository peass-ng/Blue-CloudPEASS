"""Fail-closed, reviewed pivots into named non-IAM principals.

The cloud API action only exposes or changes a credential. It is not an edge
until a complete review proves the exact external subject, usable credential,
successful authentication, and newly allowed target-plane action.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from urllib.parse import urlsplit

from . import Node, inventory_status, items

COLLECTION = "gcp_external_principal_evidence"
AGENT_REGISTRY_TECHNIQUE = "gcp-agentregistry-service-redirect-exact-external-principal"
FIREBASE_SIGNING_TECHNIQUES = {
    "gcp-firebase-signblob-exact-custom-token-user",
    "gcp-firebase-signjwt-exact-custom-token-user",
}
FIREBASE_CUSTOM_TOKEN_AUDIENCE = (
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
)


def _exact(value):
    return (isinstance(value, str) and bool(value.strip()) and value == value.strip()
            and not any(char in value for char in ("*", "?", "\n", "\r", "\x00")))


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("missing timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("naive timestamp")
    return parsed


def _valid(record, scope, snapshot):
    if not isinstance(record, dict) or not scope.startswith("projects/"):
        return False
    fields = ("TechniqueId", "SourceId", "ActionResource", "AccessPermission",
              "TargetPlane", "TargetServiceResource", "TargetPrincipalId",
              "CredentialRef", "GainedPermission", "EvidenceRef",
              "PriorTestedPermission", "AfterTestedPermission",
              "PriorTestedResource", "AfterTestedResource")
    if any(not _exact(record.get(field)) for field in fields):
        return False
    if record.get("TargetScope") != scope:
        return False
    if record["ActionResource"] != scope and not record["ActionResource"].startswith(scope + "/"):
        return False
    target_resource = record["TargetServiceResource"]
    try:
        external = urlsplit(target_resource)
        external_ok = (external.scheme == "https" and external.hostname and external.path
                       and not external.username and not external.password
                       and not external.query and not external.fragment and external.port != 0)
    except ValueError:
        external_ok = False
    if (not target_resource.startswith(scope + "/")
            and not external_ok):
        return False
    if not (record["PriorTestedPermission"] == record["GainedPermission"]
            == record["AfterTestedPermission"]):
        return False
    if not (record["PriorTestedResource"] == record["TargetServiceResource"]
            == record["AfterTestedResource"]):
        return False
    try:
        captured = _instant(snapshot.get("created_at"))
        observed = _instant(record.get("EvidenceObservedAt"))
        expiry = _instant(record.get("CredentialExpiresAt"))
        prior = _instant(record.get("PriorAccessCheckedAt"))
        action = _instant(record.get("ActionObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        fresh = (prior < action <= after <= observed <= captured < expiry
                 and (captured - prior).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        fresh = False
    if record.get("TechniqueId") == AGENT_REGISTRY_TECHNIQUE:
        if not fresh:
            return False
        if not _valid_agent_registry(record, scope, prior, action, after, observed):
            return False
    if record.get("TechniqueId") in FIREBASE_SIGNING_TECHNIQUES:
        if not _valid_firebase_custom_token(record, scope):
            return False
    return (fresh and record.get("Status") == "verified"
            and all(record.get(key) is True for key in (
                "ActionSucceeded", "PriorSourceAccessDenied", "CredentialUsable",
                "CredentialFreshnessVerified", "AfterAuthenticationSucceeded",
                "AfterTargetPermissionAllowed"))
            and record.get("ObservedPrincipalId") == record["TargetPrincipalId"])


def _valid_firebase_custom_token(record, scope):
    """Bind the signed custom token and accepted exchange to one SA and UID."""
    prefix = scope + "/serviceAccounts/"
    resource = record["ActionResource"]
    if not resource.startswith(prefix):
        return False
    signer = resource[len(prefix):]
    project = scope.split("/", 1)[1]
    tenant = record.get("ExchangeTenantId")
    if tenant is None:
        account_resource = f"{scope}/accounts/{record['TargetPrincipalId']}"
        tenant_matches = record.get("SignedTokenTenantId") is None
    else:
        if not _exact(tenant) or "/" in tenant:
            return False
        account_resource = f"{scope}/tenants/{tenant}/accounts/{record['TargetPrincipalId']}"
        tenant_matches = record.get("SignedTokenTenantId") == tenant
    if (not re.fullmatch(r"[^/@\s]+@[^/@\s]+\.gserviceaccount\.com", signer)
            or record["TargetServiceResource"] != account_resource
            or not tenant_matches
            or not 1 <= len(record["TargetPrincipalId"]) <= 128):
        return False
    return (record.get("SignedTokenAlgorithm") == "RS256"
            and record.get("SignedTokenIssuer") == signer
            and record.get("SignedTokenSubject") == signer
            and record.get("SignedTokenAudience") == FIREBASE_CUSTOM_TOKEN_AUDIENCE
            and record.get("SignedTokenUid") == record["TargetPrincipalId"]
            and record.get("ExchangeProjectId") == project
            and record.get("ExchangeUid") == record["TargetPrincipalId"]
            and record.get("ExchangeAccepted") is True)


def _valid_agent_registry(record, scope, prior, action, after, observed):
    """Tie the received credential to one changed Service and unchanged Binding."""
    fields = ("QuotaProject", "ServiceProjectedUrnBefore", "ServiceProjectedUrnAfter",
              "BindingResource", "BindingTargetUrn", "BindingAuthProvider",
              "ServiceUrlBefore", "ServiceUrlAfter", "CaptureEndpointUrl",
              "VictimPrincipalId", "CredentialKind", "CredentialHeaderName",
              "VictimInvocationObservedAt", "CredentialCapturedAt")
    if any(not _exact(record.get(field)) for field in fields):
        return False
    service = record["ActionResource"]
    if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/services/[^/]+", service)
            or not service.startswith(scope + "/")
            or not re.fullmatch(r"projects/[^/]+", record["QuotaProject"])
            or not re.fullmatch(r"projects/[^/]+/locations/[^/]+/bindings/[^/]+", record["BindingResource"])
            or not record["BindingResource"].startswith(scope + "/")
            or not re.fullmatch(r"projects/[^/]+/locations/[^/]+/authProviders/[^/]+", record["BindingAuthProvider"])
            or record["VictimPrincipalId"] == record["SourceId"]
            or record["CredentialKind"] not in ("api_key", "oauth_access_token")
            or record["ServiceProjectedUrnBefore"] != record["ServiceProjectedUrnAfter"]
            or record["BindingTargetUrn"] != record["ServiceProjectedUrnAfter"]
            or record["ServiceUrlBefore"] == record["ServiceUrlAfter"]
            or record["ServiceUrlAfter"] != record["CaptureEndpointUrl"]):
        return False
    for field in ("ServiceUrlBefore", "ServiceUrlAfter"):
        try:
            url = urlsplit(record[field])
            if (url.scheme != "https" or not url.hostname or url.username or url.password
                    or url.port == 0 or url.fragment):
                return False
        except ValueError:
            return False
    if any(record.get(field) is not True for field in (
            "BindingPresentBefore", "BindingPresentAfter", "ServiceUpdatedOnlyInterfaces",
            "VictimRuntimeAuthorizedToRetrieve", "VictimUsedBindingAwareRuntime",
            "CredentialCapturedAtControlledEndpoint")):
        return False
    try:
        invoked = _instant(record["VictimInvocationObservedAt"])
        credential = _instant(record["CredentialCapturedAt"])
        return prior < action < invoked <= credential <= after <= observed
    except (TypeError, ValueError, OverflowError):
        return False


def _node_id(record):
    fields = ("TechniqueId", "SourceId", "TargetPlane", "TargetServiceResource", "TargetPrincipalId")
    digest = hashlib.sha256("\x00".join(record[field] for field in fields).encode()).hexdigest()[:20]
    return f"gcp_external_principal:{record['TargetPlane']}:{digest}"


def load(model):
    """Only a unique record in a complete project collection creates a node."""
    status = inventory_status(model.snapshot, COLLECTION)
    grouped = {}
    poisoned = set()
    for collection_scope, record in items(model.snapshot, COLLECTION):
        scope = model._norm_scope(collection_scope)
        if not isinstance(record, dict):
            continue
        technique, source = record.get("TechniqueId"), record.get("SourceId")
        if not _exact(technique) or not _exact(source):
            continue
        owner = (technique, source, scope)
        if not all(_exact(record.get(key)) for key in (
                "ActionResource", "AccessPermission", "TargetPlane", "TargetServiceResource")):
            poisoned.add(owner)
            continue
        key = (record["TechniqueId"], record["SourceId"], scope,
               record["ActionResource"], record["AccessPermission"], record["TargetPlane"],
               record["TargetServiceResource"])
        grouped.setdefault(key, []).append((collection_scope, record))
    nodes, records = {}, {}
    for (technique, source, scope, _, _, _, _), matches in grouped.items():
        if (technique, source, scope) in poisoned:
            continue
        if len(matches) != 1 or status.get(matches[0][0]) != "collected":
            continue
        record = matches[0][1]
        if not _valid(record, scope, model.snapshot):
            poisoned.add((technique, source, scope))
            continue
        ident = _node_id(record)
        if record["ActionResource"] != scope:
            model.parents.setdefault(record["ActionResource"], scope)
        nodes[ident] = Node(ident, "gcp_external_principal", "gcp", scope,
                            f"{record['TargetPrincipalId']} on {record['TargetServiceResource']}",
                            attrs={"scope": scope, "resource": record["ActionResource"],
                                   "external_plane": record["TargetPlane"],
                                   "external_principal": record["TargetPrincipalId"],
                                   "external_resource": record["TargetServiceResource"],
                                   "quota_project": record.get("QuotaProject")})
        records[ident] = record
    if poisoned:
        for ident, record in list(records.items()):
            if (record["TechniqueId"], record["SourceId"], record["TargetScope"]) in poisoned:
                records.pop(ident)
                nodes.pop(ident)
    return nodes, records


def select(model, candidates, source):
    if source is None:
        return {}
    entry = model.current_entry or {}
    if (entry.get("target") or {}).get("outcome") != "credentials":
        return {}
    def actions(value):
        if isinstance(value, dict):
            if isinstance(value.get("action"), str):
                yield value["action"].lower()
            for nested in value.values():
                yield from actions(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from actions(nested)
    required = set(actions(entry.get("requires") or {}))
    out = {}
    for ident, node in candidates.items():
        record = model.external_principal_records.get(ident)
        if (record is None or record["TechniqueId"] != entry.get("id")
                or record["SourceId"] != source.id
                or record["AccessPermission"].lower() not in required
                or node.attrs.get("resource") != record["ActionResource"]):
            continue
        authority = model.check(source, {"action": record["AccessPermission"]}, record["ActionResource"])
        if authority is not None and authority.confidence != "unknown":
            out[ident] = ("conditional", "reviewed_external_principal_gain")
    return out
