"""Proof that an ADF data-plane token actually reached one managed identity."""
from __future__ import annotations

CONTRACT = frozenset({"azure-datafactory-dataplane-access-token"})
_ACTION = "microsoft.datafactory/factories/getdataplaneaccess/action"
_TYPE = "microsoft.datafactory/factories"


def _exact(value):
    return (isinstance(value, str) and bool(value.strip()) and value == value.strip()
            and not any(char in value for char in ("*", "?", "\n", "\r", "\x00")))


def valid(model, technique, fact, source_id, target_id, target_scope):
    if technique not in CONTRACT or not isinstance(fact, dict):
        return False
    host = fact.get("ActionResourceId")
    if not _exact(host) or not host.casefold().startswith("/subscriptions/"):
        return False
    if any(not _exact(fact.get(key)) for key in (
            "EvidenceRef", "ActionAuthorizationEvidenceRef", "TokenEvidenceRef",
            "PipelineEvidenceRef", "ExecutionEvidenceRef", "IdentityTokenEvidenceRef",
            "PriorAccessEvidenceRef", "GrantedDataPlanePermission", "ExecutablePipelineId")):
        return False
    if not all(fact.get(key) is True for key in (
            "VerifiedPreconditions", "ActionAuthorizedVerified", "DataPlaneTokenUsable",
            "TokenAuthorizesPipelineRun", "RunnablePipelineVerified", "PipelineRunSucceeded",
            "ManagedIdentityTokenObtained", "PriorIdentityAccessDenied")):
        return False
    if (fact.get("TechniqueId") != technique or fact.get("Status") != "verified"
            or fact.get("SourceId") != source_id
            or fact.get("TargetKind") != "azure_managed_identity"
            or fact.get("TargetId") != target_id
            or fact.get("IdentityPrincipalId") != target_id
            or fact.get("TargetScope", "").casefold() != host.casefold()
            or target_scope.casefold() != host.casefold()
            or fact.get("SourceAction", "").casefold() != _ACTION):
        return False
    if not fact["ExecutablePipelineId"].casefold().startswith(host.casefold() + "/pipelines/"):
        return False
    resource = model.resources.get(host.casefold())
    identity = model.principals.get(target_id)
    if (resource is None or resource.get("type") != _TYPE or identity is None
            or identity.kind != "azure_managed_identity"
            or host.casefold() not in identity.attrs.get("hosts", ())):
        return False
    if fact.get("IdentityType") == "user_assigned":
        return (identity.attrs.get("mi_type") == "user_assigned"
                and fact.get("IdentityCredentialBindingVerified") is True
                and _exact(fact.get("FactoryCredentialId"))
                and fact["FactoryCredentialId"].casefold().startswith(host.casefold() + "/credentials/")
                and _exact(fact.get("IdentityCredentialEvidenceRef")))
    return fact.get("IdentityType") == "system_assigned" and identity.attrs.get("mi_type") == "system_assigned"
