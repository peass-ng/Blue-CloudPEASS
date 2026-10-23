"""Conservative eligibility and connector identity checks for same-row scan resume."""
from __future__ import annotations

import json
import re
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from peaso.storage.sqlite import StoreError, TERMINAL
from peaso.storage.artifacts import check_reference, job_prefix


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


def collector_source(row):
    """Prefer a sealed final snapshot; admit a fenced cumulative checkpoint."""
    if row.get("snapshot"):
        return row["snapshot"]
    sequence = row.get("checkpoint_sequence")
    published = row.get("partial_report_sequence")
    if (type(sequence) is int and type(published) is int and 0 < published <= sequence
            and row.get("partial_snapshot") and row.get("partial_report")):
        return row["partial_snapshot"]
    return None


def resume_stage(row):
    """Return the work that remains, only for an incomplete live terminal row."""
    row = dict(row)
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
        return "collector" if collector_source(row) else None
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


def recoverable_sources(row, store, artifacts, *, metadata_only=False):
    """Prove saved objects belong to this scan before resetting its queue state."""
    from peaso.snapshot import digest, validate
    stage = resume_stage(row)
    if stage is None:
        raise StoreError(409, "This scan has no recoverable work")
    prefix = job_prefix(row["tenant"], row["id"])
    provider = json.loads(row["connector"])["data"]["provider"]
    partial = stage == "collector" and not row.get("snapshot")
    if stage == "analyzer":
        references = [row["snapshot"]]
    else:
        entries = store.checkpoint_collections(row["tenant"], row["id"])
        references = [collector_source(row)] + ([row["partial_report"]] if partial else []) + [
            entry["reference"] for entry in entries]
        if not references or any(type(entry.get("sequence")) is not int
                              or not 0 < entry["sequence"] <= row["checkpoint_sequence"]
                              for entry in entries):
            raise StoreError(409, "Saved scan batches are unavailable")
        if partial and (not entries or max(entry["sequence"] for entry in entries)
                        != row["checkpoint_sequence"]):
            raise StoreError(409, "Saved scan batches are unavailable")
    if not references or any(not isinstance(ref, str) or not ref.startswith(prefix)
                             for ref in references):
        raise StoreError(409, "Saved scan results are unavailable")
    if partial and metadata_only:
        # The HTTP route checks durable row metadata and object existence,
        # while the collector child validates every byte before native work.
        # HEAD/stat reads stay small even for a 150 MB cumulative snapshot.
        try:
            for reference in references:
                check_reference(row["tenant"], reference)
            # Check only the cumulative publication here. Batch presence and
            # complete content are verified in the claimed collector, so API
            # latency does not grow with the number of acknowledged batches.
            publication_refs = [row["partial_snapshot"], row["partial_report"]]
            with ThreadPoolExecutor(max_workers=2) as pool:
                sizes = list(pool.map(lambda ref: artifacts.size(row["tenant"], ref), publication_refs))
            if any(type(size) is not int or size <= 0 for size in sizes):
                raise ValueError("Empty saved artifact")
        except Exception:
            raise StoreError(409, "Saved scan results are unavailable") from None
        return stage
    try:
        if not partial:
            for reference in dict.fromkeys(references):
                snapshot = validate(artifacts.get(row["tenant"], reference))
                if snapshot["provider"] != provider or not snapshot["collections"]:
                    raise ValueError("Saved scan provider mismatch")
        if partial:
            saved = validate(artifacts.get(row["tenant"], row["partial_snapshot"]))
            if saved["provider"] != provider or not saved["collections"]:
                raise ValueError("Saved scan provider mismatch")
            metadata = saved.get("metadata") or {}
            incremental = metadata.get("incremental") or {}
            frozen = json.loads(row["connector"])["data"]
            scopes = frozen.get("scopes")
            plan = incremental.get("scope_plan")
            if (metadata.get("intentional_partial") is not True
                    or incremental.get("phase") != "collecting"
                    or incremental.get("sequence") != row["partial_report_sequence"]
                    or incremental.get("completed_collections") != len(saved["collections"])
                    or not isinstance(scopes, list) or not scopes
                    or metadata.get("requested_scopes") != scopes):
                raise ValueError("Saved checkpoint plan mismatch")
            if provider == "aws":
                # An explicit regional target is its own complete boundary.
                # Wildcard discovery needs the native plan persisted after
                # on_scope_plan; observed rows alone cannot prove absent work.
                explicit = ("*" not in scopes and all(
                    isinstance(scope, str) and re.fullmatch(
                        r"[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", scope)
                    for scope in scopes))
                if plan is None:
                    globals_allowed = {scope.split("/", 1)[0] + "/global" for scope in scopes}
                    if not explicit or any(row["scope"] not in scopes and row["scope"] not in globals_allowed
                                           for row in saved["collections"]):
                        raise ValueError("Saved checkpoint scope plan unavailable")
                elif (not isinstance(plan, list) or not plan
                      or len(set(plan)) != len(plan)
                      or any(not isinstance(scope, str) or not re.fullmatch(
                          r"[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", scope)
                          for scope in plan)
                      or (explicit and not set(scopes) <= set(plan))):
                    raise ValueError("Saved checkpoint scope plan mismatch")
                else:
                    globals_allowed = {scope.split("/", 1)[0] + "/global" for scope in plan}
                    if any(row["scope"] not in plan and row["scope"] not in globals_allowed
                           for row in saved["collections"]):
                        raise ValueError("Saved checkpoint scope plan mismatch")
            report = artifacts.get(row["tenant"], row["partial_report"])
            publication = (report.get("summary", report).get("publication")
                           if isinstance(report, dict) else None)
            if (not isinstance(publication, dict)
                    or publication.get("state") != "partial"
                    or publication.get("phase") != "collecting"
                    or publication.get("sequence") != row["partial_report_sequence"]):
                raise ValueError("Saved checkpoint publication mismatch")
            observed = {(envelope["type"], envelope["scope"]): digest(envelope)
                        for envelope in saved["collections"]}
            # A cumulative AWS checkpoint can exceed 150 MB. Release it before
            # downloading bounded batches, and retain only envelope digests.
            del saved
            at_publication = {}
            def check_batch(entry, batch):
                if batch["provider"] != provider or not batch["collections"]:
                    raise ValueError("Saved batch provider mismatch")
                mark = (batch.get("metadata") or {}).get("incremental") or {}
                if (mark.get("sequence") != entry["sequence"] or mark.get("phase") != "collecting"
                        or batch.get("metadata", {}).get("requested_scopes") != scopes):
                    raise ValueError("Saved checkpoint sequence mismatch")
                batch_plan = mark.get("scope_plan")
                if provider == "aws" and batch_plan is not None and (
                        not isinstance(batch_plan, list)
                        or batch_plan != (plan if plan is not None else scopes)):
                    raise ValueError("Saved checkpoint scope plan changed")
                if entry["kind"] == "__checkpoint_batch__":
                    revisions = mark.get("batch_revisions")
                    if (entry["scope"] != str(entry["sequence"])
                            or not isinstance(revisions, list)
                            or len(revisions) != len(batch["collections"])):
                        raise ValueError("Saved checkpoint batch mismatch")
                elif (len(batch["collections"]) != 1
                      or batch["collections"][0]["type"] != entry["kind"]
                      or batch["collections"][0]["scope"] != entry["scope"]):
                    raise ValueError("Saved checkpoint envelope mismatch")
                else:
                    revisions = [mark.get("data_revision", entry["sequence"])]
                for revision, envelope in zip(revisions, batch["collections"]):
                    if type(revision) is not int or not 0 <= revision <= entry["sequence"]:
                        raise ValueError("Saved checkpoint revision mismatch")
                    if entry["sequence"] <= row["partial_report_sequence"]:
                        key = (envelope["type"], envelope["scope"])
                        value = digest(envelope)
                        previous = at_publication.get(key, (-1, None))
                        if revision == previous[0] and value != previous[1]:
                            raise ValueError("Conflicting checkpoint revision")
                        if revision > previous[0]:
                            at_publication[key] = (revision, value)
            # S3 round trips dominate hosted validation. At most four batch
            # bodies are in flight so large native envelopes stay memory bound.
            with ThreadPoolExecutor(max_workers=min(4, len(entries))) as pool:
                source = iter(entries)
                pending = {}
                for _ in range(min(4, len(entries))):
                    entry = next(source)
                    pending[pool.submit(artifacts.get, row["tenant"], entry["reference"])] = entry
                while pending:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        entry = pending.pop(future)
                        check_batch(entry, validate(future.result()))
                        following = next(source, None)
                        if following is not None:
                            pending[pool.submit(artifacts.get, row["tenant"], following["reference"])] = following
            expected = {key: value for key, (_, value) in at_publication.items()}
            if not expected or expected != observed:
                raise ValueError("Saved cumulative checkpoint mismatch")
    except (KeyError, OSError, TypeError, ValueError):
        raise StoreError(409, "Saved scan results are unavailable") from None
    return stage


def validate_resume_proof(proof, artifacts, tenant, ident, connector, checkpoint_refs):
    """Verify a CAS-claimed collector's immutable checkpoint before any read."""
    if not isinstance(proof, dict) or not isinstance(proof.get("row"), dict):
        raise ValueError("Resume proof is unavailable")
    row, entries = proof["row"], proof.get("entries")
    if (row.get("tenant") != tenant or row.get("id") != ident
            or row.get("resume_phase") != "collector" or row.get("snapshot")
            or not isinstance(entries, list)
            or [entry.get("reference") for entry in entries] != checkpoint_refs):
        raise ValueError("Resume proof does not match the claimed scan")
    data = json.loads(row["connector"])["data"]
    if (data.get("provider") != connector.get("provider")
            or data.get("scopes") != connector.get("scopes")):
        raise ValueError("Resume proof target changed")

    class SavedRows:
        @staticmethod
        def checkpoint_collections(expected_tenant, expected_id):
            if expected_tenant != tenant or expected_id != ident:
                raise ValueError("Resume proof owner changed")
            return entries

    terminal = dict(row, status="failed", error_stage="collector")
    if recoverable_sources(terminal, SavedRows(), artifacts) != "collector":
        raise ValueError("Resume proof is incomplete")
