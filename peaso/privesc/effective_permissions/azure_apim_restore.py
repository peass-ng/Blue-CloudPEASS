"""Reviewed proof for restoring an APIM backup that contains an identity-using policy."""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from . import inventory_status, items

TECHNIQUE = "azure-apim-restore-backup-managed-identity-token"
COLLECTION = "azure_privesc_challenge_evidence"
SERVICE = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.apimanagement/service/[^/]+", re.I)


def _instant(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _valid(model, record, source, target, host, scope):
    if not isinstance(record, dict):
        return False
    if (record.get("TechniqueId") != TECHNIQUE or record.get("SourceId") != source.id
            or record.get("TargetKind") != "azure_managed_identity"
            or record.get("TargetId") != target.id
            or str(record.get("TargetScope", "")).casefold() != scope
            or str(record.get("RestoreServiceResource", "")).casefold() != host
            or str(record.get("BackupSourceServiceResource", "")).casefold() == ""
            or SERVICE.fullmatch(str(record.get("BackupSourceServiceResource", ""))) is None):
        return False
    if target.attrs.get("mi_type") == "system_assigned":
        if record.get("PolicyIdentitySelector") != "system":
            return False
    elif target.attrs.get("mi_type") == "user_assigned":
        client_id = target.attrs.get("client_id")
        if not isinstance(client_id, str) or record.get("PolicyIdentitySelector", "").casefold() != client_id.casefold():
            return False
    else:
        return False
    if any(not isinstance(record.get(key), str) or not record[key].strip() for key in
           ("BackupStorageAccount", "BackupContainer", "BackupName",
            "BackupEvidenceRef", "PolicyEvidenceRef", "EvidenceRef")):
        return False
    if (record.get("BackupAccessType") not in
            ("AccessKey", "SystemAssignedManagedIdentity", "UserAssignedManagedIdentity")
            or any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", record[key]) is None for key in
                   ("BackupStorageAccount", "BackupContainer", "BackupName"))):
        return False
    if not all(record.get(key) is True for key in
               ("VerifiedPreconditions", "BackupProducedByApim", "BackupPolicyControlled",
                "BackupStorageAccessVerified", "TargetTierCompatible", "TargetRestoreSupported")):
        return False
    if record.get("Status") != "verified":
        return False
    created = _instant(record.get("BackupCreatedAt"))
    observed = _instant(record.get("EvidenceObservedAt"))
    captured = _instant(model.snapshot.get("created_at"))
    return bool(created and observed and captured and created <= observed <= captured
                and captured - created < timedelta(days=30)
                and captured - observed <= timedelta(days=1))


def select(model, candidates, source):
    if source is None:
        return {}
    statuses = inventory_status(model.snapshot, COLLECTION)
    records = {}
    for scope, record in items(model.snapshot, COLLECTION):
        if not isinstance(record, dict) or record.get("TechniqueId") != TECHNIQUE:
            continue
        key = (record.get("SourceId"), record.get("TargetId"),
               str(record.get("RestoreServiceResource", "")).casefold(), str(scope).casefold())
        records.setdefault(key, []).append(record)
    out = {}
    for ident, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        scope = target.scope.casefold()
        if statuses.get(target.scope) != "collected" and statuses.get(scope) != "collected":
            continue
        for host in target.attrs.get("hosts") or ():
            if (model.resources.get(host, {}).get("type") != "microsoft.apimanagement/service"
                    or SERVICE.fullmatch(host) is None):
                continue
            matches = records.get((source.id, ident, host, scope), ())
            if len(matches) == 1 and _valid(model, matches[0], source, target, host, scope):
                grant = model.check(source, {"action": "Microsoft.ApiManagement/service/restore/action"}, host)
                if grant is not None and grant.confidence != "unknown":
                    out[ident] = ("conditional", "reviewed_restorable_apim_backup_for_identity")
    return out
