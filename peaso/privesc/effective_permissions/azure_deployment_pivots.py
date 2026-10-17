"""Typed proof for Azure source-control changes that actually reach an identity.

Changing a source binding is only a potential future deployment. An edge to the
Container App's managed identity requires evidence of a successful attacker-code
deployment and token use on the exact app whose binding the source changed.
"""
from __future__ import annotations


CONTRACT = frozenset({"azure-containerapp-sourcecontrols-write"})
_ACTION = "microsoft.app/containerapps/sourcecontrols/write"
_TYPE = "microsoft.app/containerapps"


def valid(model, technique, fact, source_id, target_id, target_scope):
    if technique not in CONTRACT or not isinstance(fact, dict):
        return False
    host = fact.get("ActionResourceId")
    if not isinstance(host, str) or not host.startswith("/subscriptions/") or "*" in host or "?" in host:
        return False
    if not all(fact.get(key) is True for key in (
        "VerifiedPreconditions", "ActionAuthorizedVerified", "SourceBindingChanged",
        "AttackerControlledSourceVerified", "BuildSucceeded", "RevisionDeployed",
        "ManagedIdentityTokenObtained", "PriorIdentityAccessDenied",
    )):
        return False
    if not all(isinstance(fact.get(key), str) and fact[key].strip() for key in (
        "EvidenceRef", "ActionAuthorizationEvidenceRef", "SourceBindingEvidenceRef",
        "BuildEvidenceRef", "DeploymentEvidenceRef", "TokenEvidenceRef",
        "PriorAccessEvidenceRef", "DeploymentRevisionId",
    )):
        return False
    if (fact.get("TechniqueId") != technique or fact.get("Status") != "verified"
            or fact.get("EffectType") != "source_control_deployment_identity"
            or fact.get("SourceId") != source_id
            or fact.get("TargetKind") != "azure_managed_identity"
            or fact.get("TargetId") != target_id
            or fact.get("TargetScope", "").casefold() != host.casefold()
            or target_scope.casefold() != host.casefold()
            or fact.get("ManagedIdentityPrincipalId") != target_id
            or fact.get("SourceAction", "").casefold() != _ACTION):
        return False
    resource = model.resources.get(host.casefold())
    identity = model.principals.get(target_id)
    return (resource is not None and resource.get("type") == _TYPE
            and identity is not None and identity.kind == "azure_managed_identity"
            and host.casefold() in identity.attrs.get("hosts", ()))
