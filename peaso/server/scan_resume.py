"""Conservative eligibility and connector identity checks for same-row scan resume."""
from __future__ import annotations

import json

from peaso.storage.sqlite import StoreError, TERMINAL
from peaso.storage.artifacts import job_prefix


_SECRET_FIELDS = {
    "aws": {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"},
    "gcp": {"token", "subject_token"},
    "azure": {"token", "arm_token", "graph_token", "vault_token", "storage_token",
              "logs_token", "databricks_account_token", "client_secret",
              "certificate_data", "client_certificate", "certificate_password",
              "federated_token"},
    "k8s": {"token", "client_cert_data", "client_key_data"},
}
_RECOVERABLE = {"credentials_expired", "failed", "timed_out", "cancelled"}


def resume_stage(row):
    """Return the work that remains, only for an incomplete live terminal row."""
    if row.get("status") not in _RECOVERABLE or row.get("status") not in TERMINAL:
        return None
    try:
        frozen = json.loads(row["connector"])
    except (KeyError, TypeError, ValueError):
        return None
    if frozen.get("data", {}).get("input_mode", "live") != "live":
        return None
    if (row.get("status") == "credentials_expired" or row.get("error_stage") == "collector"
            or row.get("status") == "cancelled" and row.get("resume_phase") == "collector"):
        # A checkpoint batch proves its published facts but lacks the complete
        # native scope/metadata plan needed to skip settled work safely.
        return "collector" if row.get("snapshot") else None
    if row.get("snapshot"):
        return "analyzer"
    return None


def _boundary(auth, provider):
    if not isinstance(auth, dict):
        raise StoreError(422, "Connector authentication is invalid")
    value = {key: item for key, item in auth.items()
             if key not in _SECRET_FIELDS[provider]}
    if provider == "gcp" and "sa_json" in value:
        try:
            service_account = value["sa_json"]
            service_account = json.loads(service_account) if isinstance(service_account, str) else service_account
            if not isinstance(service_account, dict):
                raise ValueError
            value["sa_json"] = {key: item for key, item in service_account.items()
                                if key not in {"private_key", "private_key_id"}}
        except (TypeError, ValueError):
            raise StoreError(422, "Connector authentication is invalid") from None
    return value


def compatible_connector(row, latest, cipher):
    """Use fresh credentials without changing the frozen provider/target/selection."""
    if latest["id"] != row["connector_id"] or latest["tenant"] != row["tenant"]:
        raise StoreError(409, "The original connector is unavailable")
    prior = json.loads(row["connector"])
    current = json.loads(latest["data"])
    old_data = prior["data"]
    provider = old_data.get("provider")
    if (provider not in _SECRET_FIELDS or current.get("provider") != provider
            or current.get("scopes") != old_data.get("scopes")
            or current.get("input_mode", "live") != "live"):
        raise StoreError(409, "Connector target or scope changed; start a new scan")
    old_private = cipher.decrypt(prior["auth"])
    new_private = cipher.decrypt(latest["auth"])
    if (old_private.get("options") != new_private.get("options")
            or _boundary(old_private.get("auth"), provider)
               != _boundary(new_private.get("auth"), provider)):
        raise StoreError(409, "Connector options or identity changed; start a new scan")
    return {"data": current, "auth": latest["auth"]}


def recoverable_sources(row, store, artifacts):
    """Prove saved objects belong to this scan before resetting its queue state."""
    from peaso.snapshot import validate
    stage = resume_stage(row)
    if stage is None:
        raise StoreError(409, "This scan has no recoverable work")
    prefix = job_prefix(row["tenant"], row["id"])
    provider = json.loads(row["connector"])["data"]["provider"]
    if stage == "analyzer":
        references = [row["snapshot"]]
    else:
        entries = store.checkpoint_collections(row["tenant"], row["id"])
        references = ([row["snapshot"]] if row.get("snapshot") else []) + [entry["reference"] for entry in entries]
        if not references or any(type(entry.get("sequence")) is not int
                              or not 0 < entry["sequence"] <= row["checkpoint_sequence"]
                              for entry in entries):
            raise StoreError(409, "Saved scan batches are unavailable")
    if not references or any(not isinstance(ref, str) or not ref.startswith(prefix)
                             for ref in references):
        raise StoreError(409, "Saved scan results are unavailable")
    try:
        for reference in dict.fromkeys(references):
            snapshot = validate(artifacts.get(row["tenant"], reference))
            if snapshot["provider"] != provider or not snapshot["collections"]:
                raise ValueError("Saved scan provider mismatch")
    except (KeyError, OSError, TypeError, ValueError):
        raise StoreError(409, "Saved scan results are unavailable") from None
    return stage
