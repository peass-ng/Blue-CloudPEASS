"""A Container App source-control edit reaches an MI only after exact deployment proof."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import load_catalog
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az


TECHNIQUE = "azure-containerapp-sourcecontrols-write"
ACTION = "Microsoft.App/containerApps/sourcecontrols/write"
APP = f"{RG}/providers/Microsoft.App/containerApps/payments"
IDENTITY = "mi-payments"


def _case():
    entry = next(e for e in load_catalog()["entries"] if e["id"] == TECHNIQUE)
    fact = {
        "TechniqueId": TECHNIQUE, "SourceId": "u-alice", "TargetKind": "azure_managed_identity",
        "TargetId": IDENTITY, "TargetScope": APP, "Status": "verified",
        "VerifiedPreconditions": True, "EvidenceRef": "deployment-review-1",
        "EffectType": "source_control_deployment_identity", "ActionResourceId": APP,
        "SourceAction": ACTION, "ManagedIdentityPrincipalId": IDENTITY,
        "ActionAuthorizedVerified": True, "SourceBindingChanged": True,
        "AttackerControlledSourceVerified": True, "BuildSucceeded": True,
        "RevisionDeployed": True, "ManagedIdentityTokenObtained": True,
        "PriorIdentityAccessDenied": True, "DeploymentRevisionId": "payments--revision-7",
        "ActionAuthorizationEvidenceRef": "role-and-scope-1",
        "SourceBindingEvidenceRef": "source-binding-change-1",
        "BuildEvidenceRef": "workflow-run-1", "DeploymentEvidenceRef": "revision-7",
        "TokenEvidenceRef": "managed-identity-token-1", "PriorAccessEvidenceRef": "prior-denial-1",
    }
    app = {"id": APP, "type": "Microsoft.App/containerApps", "name": "payments",
           "identity": {"type": "SystemAssigned", "principalId": IDENTITY}}
    snap = az(assignments=[("u-alice", "User", APP, ROLE_ID)],
              roles={ROLE_ID: ([ACTION], [])}, graph=[app],
              extra=[("azure_privesc_challenge_evidence", APP, [fact])])
    return entry, snap


def test_containerapp_source_control_requires_exact_completed_deployment():
    entry, snap = _case()
    assert reached(privesc.analyze(snap, entries=[entry]), "u-alice", TECHNIQUE) == {
        IDENTITY: "conditional"}

    for field, value in (
        ("BuildSucceeded", False), ("ManagedIdentityTokenObtained", False),
        ("PriorIdentityAccessDenied", False), ("TokenEvidenceRef", ""),
        ("ManagedIdentityPrincipalId", "another-mi"),
        ("ActionResourceId", f"{RG}/providers/Microsoft.App/containerApps/other"),
    ):
        bad = copy.deepcopy(snap)
        next(c for c in bad["collections"] if c["type"] == "azure_privesc_challenge_evidence")["items"][0][field] = value
        assert all(c == "unknown" for c in reached(privesc.analyze(bad, entries=[entry]), "u-alice", TECHNIQUE).values()), field

    no_action = copy.deepcopy(snap)
    next(c for c in no_action["collections"] if c["type"] == "role_definition")["items"][0]["properties"]["permissions"] = [
        {"actions": ["Microsoft.App/containerApps/read"], "dataActions": []}]
    assert not any(c in ("conditional", "derived") for c in
                   reached(privesc.analyze(no_action, entries=[entry]), "u-alice", TECHNIQUE).values())


def test_review_flags_without_typed_deployment_proof_do_not_create_edge():
    entry, snap = _case()
    fact = next(c for c in snap["collections"] if c["type"] == "azure_privesc_challenge_evidence")["items"][0]
    for field in ("EffectType", "BuildSucceeded", "TokenEvidenceRef"):
        fact.pop(field)
    assert all(c == "unknown" for c in reached(privesc.analyze(snap, entries=[entry]), "u-alice", TECHNIQUE).values())
