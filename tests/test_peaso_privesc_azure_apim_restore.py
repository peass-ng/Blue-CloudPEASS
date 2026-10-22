"""Restoring a backup must prove the exact controlled policy and receiving identity."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


SERVICE = f"{RG}/providers/Microsoft.ApiManagement/service/api1"
OTHER = f"{RG}/providers/Microsoft.ApiManagement/service/other"
TARGET = "mi-api1"
ACTION = "Microsoft.ApiManagement/service/restore/action"
ENTRY = next(entry for entry in yaml.safe_load(
    (Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/azure/api_management.yaml").read_text())
    if entry["id"] == "azure-apim-restore-backup-managed-identity-token")


def _fact():
    return {"TechniqueId": ENTRY["id"], "SourceId": "u-alice",
            "TargetKind": "azure_managed_identity", "TargetId": TARGET, "TargetScope": SUB,
            "RestoreServiceResource": SERVICE, "BackupSourceServiceResource": OTHER,
            "BackupStorageAccount": "apimbackups", "BackupContainer": "restorable",
            "BackupName": "approved.apimbackup", "BackupAccessType": "AccessKey",
            "PolicyIdentitySelector": "system", "Status": "verified",
            "VerifiedPreconditions": True, "BackupProducedByApim": True,
            "BackupPolicyControlled": True, "BackupStorageAccessVerified": True,
            "TargetTierCompatible": True, "TargetRestoreSupported": True,
            "BackupEvidenceRef": "apim-backup-operation-1", "PolicyEvidenceRef": "backup-policy-1",
            "EvidenceRef": "reviewed-backup-and-restore-input-1",
            "BackupCreatedAt": "2026-10-10T11:00:00Z",
            "EvidenceObservedAt": "2026-10-21T11:55:00Z"}


def _case(facts=None, *, action=ACTION, role_scope=SERVICE, evidence_status="collected"):
    service = {"id": SERVICE, "name": "api1", "type": "Microsoft.ApiManagement/service",
               "identity": {"type": "SystemAssigned", "principalId": TARGET}}
    snap = az(assignments=[("u-alice", "User", role_scope, ROLE_ID)],
              roles={ROLE_ID: ([action], [])}, graph=[service],
              extra=[("azure_privesc_challenge_evidence", SUB,
                      [_fact()] if facts is None else facts, evidence_status)])
    snap["created_at"] = "2026-10-21T12:00:00Z"
    return snap


def _paths(snap):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", ENTRY["id"])


def test_valid_apim_backup_and_restore_action_reaches_exact_identity_conditionally():
    assert validate_entry(ENTRY)[0] == []
    assert _paths(_case()) == {TARGET: "conditional"}


@pytest.mark.parametrize("field,value", [
    ("BackupProducedByApim", False), ("BackupPolicyControlled", False),
    ("BackupStorageAccessVerified", False), ("TargetTierCompatible", False),
    ("TargetRestoreSupported", False), ("PolicyIdentitySelector", "other-client"),
    ("TargetId", "mi-other"), ("RestoreServiceResource", OTHER),
    ("BackupSourceServiceResource", ""), ("BackupAccessType", "Unknown"),
    ("BackupName", ""), ("PolicyEvidenceRef", ""), ("EvidenceRef", ""),
    ("BackupCreatedAt", "2026-09-01T00:00:00Z"),
    ("EvidenceObservedAt", "2026-10-19T00:00:00Z"),
    ("Status", "unverified"),
])
def test_unproven_or_expired_backup_does_not_name_identity(field, value):
    fact = _fact()
    fact[field] = value
    assert TARGET not in _paths(_case([fact])), (field, value)


def test_duplicate_partial_or_missing_evidence_does_not_name_identity():
    fact = _fact()
    for snap in (_case([]), _case([fact, copy.deepcopy(fact)]),
                 _case([fact], evidence_status="partial")):
        assert TARGET not in _paths(snap)


def test_restore_permission_must_cover_same_service_as_backup_evidence():
    assert TARGET not in _paths(_case(role_scope=OTHER))
    assert TARGET not in _paths(_case(action="Microsoft.ApiManagement/service/backup/action"))


def test_user_assigned_identity_policy_must_name_its_exact_client_id():
    uami = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
    target = "mi-worker"
    client = "44444444-4444-4444-4444-444444444444"
    service = {"id": SERVICE, "name": "api1", "type": "Microsoft.ApiManagement/service",
               "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                   uami: {"principalId": target}}}}
    identity = {"id": uami, "name": "worker", "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {"principalId": target, "clientId": client}}
    fact = dict(_fact(), TargetId=target, PolicyIdentitySelector=client)
    snap = _case([fact])
    next(c for c in snap["collections"] if c["type"] == "resource_graph")["items"] = [identity, service]
    assert _paths(snap) == {target: "conditional"}
    fact["PolicyIdentitySelector"] = "55555555-5555-5555-5555-555555555555"
    assert target not in _paths(snap)
