"""Appliance credential exports need a measured external permission gain."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_azure_external_principal import proof
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-arc-resource-bridge-credential-export"
APPLIANCE = f"{RG}/providers/Microsoft.ResourceConnector/appliances/bridge"
OTHER = f"{RG}/providers/Microsoft.ResourceConnector/appliances/other"
CUSTOMER = "Microsoft.ResourceConnector/appliances/listKeys/action"
PARTNER = "Microsoft.ResourceConnector/appliances/listClusterUserCredential/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _fact(action):
    service = "https://bridge.example.local/api"
    return {**proof(), "TechniqueId": TID, "ActionResource": APPLIANCE,
            "AccessPermission": action, "TargetPlane": "arc_bridge_appliance",
            "TargetServiceResource": service, "TargetPrincipalId": "bridge-user",
            "ObservedPrincipalId": "bridge-user", "AccessArtifactKind": "credential",
            "GainedPermission": "get pods", "PriorTestedPermission": "get pods",
            "AfterTestedPermission": "get pods", "PriorTestedResource": service,
            "AfterTestedResource": service,
            "TargetServiceBindingEvidenceRef": "bridge-to-api-1",
            "TargetSubjectBindingEvidenceRef": "export-to-bridge-user-1"}


def _run(action=CUSTOMER, facts=None, *, grant=APPLIANCE, include_unknown=False):
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: ([action], [])},
              graph=[{"id": APPLIANCE, "type": "Microsoft.ResourceConnector/appliances",
                      "name": "bridge"}],
              extra=[("azure_external_principal_evidence", SUB,
                      [_fact(action)] if facts is None else facts, "collected")])
    snap["created_at"] = "2026-10-16T11:05:00Z"
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def _paths(result):
    return {target: confidence for target, confidence in reached(result, "u-alice", TID).items()
            if not target.startswith(("unknown:", "unresolved:"))}


def test_both_export_actions_need_exact_reviewed_authority():
    assert validate_entry(ENTRY)[0] == []
    for action in (CUSTOMER, PARTNER):
        result = _paths(_run(action))
        assert len(result) == 1
        assert next(iter(result)).startswith("azure_external_principal:")
        assert set(result.values()) == {"conditional"}


def test_permission_alone_and_wrong_appliance_do_not_create_admin_path():
    assert _paths(_run(facts=[])) == {}
    assert _paths(_run(grant=OTHER)) == {}
    bad = _fact(CUSTOMER)
    bad["ActionResource"] = OTHER
    assert _paths(_run(facts=[bad])) == {}


def test_unusable_or_unbound_credential_does_not_create_path():
    for field, value in (("AccessArtifactUsable", False),
                         ("AfterAuthenticationSucceeded", False),
                         ("AfterTargetPermissionAllowed", False),
                         ("TargetServiceBindingVerified", False),
                         ("ObservedPrincipalId", "different"),
                         ("PriorSourceAccessDenied", False),
                         ("EvidenceExpiresAt", "2026-10-16T11:04:00Z")):
        bad = _fact(CUSTOMER)
        bad[field] = value
        assert _paths(_run(facts=[bad])) == {}, field
