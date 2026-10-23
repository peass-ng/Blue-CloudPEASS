"""A Data Factory data-plane token reaches an MI only after an exact runnable join."""
from __future__ import annotations

import copy

from peaso.privesc.schema import load_catalog
from peaso.privesc.versioned_catalog import _verified_previous_current
from peaso.privesc.effective_permissions.azure import AzureModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az

TECHNIQUE = "azure-datafactory-dataplane-access-token"
ACTION = "Microsoft.DataFactory/factories/getDataPlaneAccess/action"
FACTORY = f"{RG}/providers/Microsoft.DataFactory/factories/finance"
IDENTITY = "mi-finance"


def _case():
    # This contract is retained only for regression of the archived evaluator.
    # Its active automatic technique was retired because these facts require
    # successful token use and pipeline execution outside passive collection.
    assert TECHNIQUE not in {e["id"] for e in load_catalog()["entries"]}
    entry = _verified_previous_current()[TECHNIQUE]
    fact = {
        "TechniqueId": TECHNIQUE, "SourceId": "u-alice", "TargetKind": "azure_managed_identity",
        "TargetId": IDENTITY, "TargetScope": FACTORY, "Status": "verified",
        "VerifiedPreconditions": True, "EvidenceRef": "review-1", "ActionResourceId": FACTORY,
        "SourceAction": ACTION, "IdentityPrincipalId": IDENTITY, "IdentityType": "system_assigned",
        "ActionAuthorizedVerified": True, "DataPlaneTokenUsable": True,
        "TokenAuthorizesPipelineRun": True, "RunnablePipelineVerified": True,
        "PipelineRunSucceeded": True, "ManagedIdentityTokenObtained": True,
        "PriorIdentityAccessDenied": True, "GrantedDataPlanePermission": "pipeline.run",
        "ExecutablePipelineId": FACTORY + "/pipelines/export", "ActionAuthorizationEvidenceRef": "rbac-1",
        "TokenEvidenceRef": "token-review-1", "PipelineEvidenceRef": "pipeline-1",
        "ExecutionEvidenceRef": "run-1", "IdentityTokenEvidenceRef": "mi-token-1",
        "PriorAccessEvidenceRef": "prior-denial-1",
    }
    factory = {"id": FACTORY, "type": "Microsoft.DataFactory/factories", "name": "finance",
               "identity": {"type": "SystemAssigned", "principalId": IDENTITY}}
    snap = az(assignments=[("u-alice", "User", FACTORY, ROLE_ID)],
              roles={ROLE_ID: ([ACTION], [])}, graph=[factory],
              extra=[("azure_privesc_challenge_evidence", FACTORY, [fact])])
    return entry, snap


def _paths(entry, snap):
    return {target_id: grant.confidence for reach in Evaluator(AzureModel(snap), [entry]).run()
            if reach.source.id == "u-alice" for target_id, grant in reach.targets.items()
            if not target_id.startswith(("unknown:", "unresolved:"))}


def test_retired_token_pipeline_path_stays_inactive_even_with_supplied_fact():
    entry, snap = _case()
    assert _paths(entry, snap) == {}
    for key, value in (
        ("TokenAuthorizesPipelineRun", False), ("PipelineRunSucceeded", False),
        ("ManagedIdentityTokenObtained", False), ("IdentityPrincipalId", "mi-other"),
        ("ExecutablePipelineId", ""), ("TokenEvidenceRef", ""),
        ("IdentityType", "user_assigned"),
    ):
        bad = copy.deepcopy(snap)
        next(c for c in bad["collections"] if c["type"] == "azure_privesc_challenge_evidence")["items"][0][key] = value
        assert _paths(entry, bad) == {}, key
    no_action = copy.deepcopy(snap)
    next(c for c in no_action["collections"] if c["type"] == "role_definition")["items"][0]["properties"]["permissions"] = [
        {"actions": ["Microsoft.DataFactory/factories/read"], "dataActions": []}]
    assert _paths(entry, no_action) == {}


def test_retired_user_assigned_identity_path_stays_inactive():
    entry, snap = _case()
    uami = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/finance-mi"
    graph = next(c for c in snap["collections"] if c["type"] == "resource_graph")["items"]
    graph[0]["identity"] = {"type": "UserAssigned", "userAssignedIdentities": {
        uami: {"principalId": IDENTITY, "clientId": "client-finance"}}}
    graph.append({"id": uami, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                  "name": "finance-mi", "properties": {"principalId": IDENTITY,
                                                       "clientId": "client-finance"}})
    fact = next(c for c in snap["collections"] if c["type"] == "azure_privesc_challenge_evidence")["items"][0]
    fact.update(IdentityType="user_assigned", IdentityCredentialBindingVerified=True,
                FactoryCredentialId=FACTORY + "/credentials/finance-mi",
                IdentityCredentialEvidenceRef="credential-binding-1")
    assert _paths(entry, snap) == {}
