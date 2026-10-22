"""Durable collection and analysis with optional post-scan AI and fenced jobs."""
import argparse
import hashlib
import json
import logging
import multiprocessing
import os
import re
import signal
import threading
import time
import traceback
from pathlib import Path
from fastapi import HTTPException
from peaso.auth import Authenticator, CredentialCipher, redact
from peaso.auth.secrets import credential_values
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts, S3Artifacts
from peaso.storage.runtime import stores, WorkflowDispatcher

LOGGER = logging.getLogger(__name__)


def _verify_aws_credentials(connector):
    """Reject an expired selected session before scheduling native inventory."""
    if (connector.get("provider") != "aws" or
            connector.get("input_mode") in {"offline_snapshot", "demo"}):
        return
    from botocore.config import Config
    from peaso.collectors.aws import _session
    try:
        region = (connector.get("options", {}).get("regions") or ["us-east-1"])[0]
        session, _ = _session(connector.get("auth", {}), region)
        session.client("sts", config=Config(connect_timeout=5, read_timeout=10,
            retries={"max_attempts": 1})).get_caller_identity()
    except Exception:
        # Provider exceptions can contain request/credential details. Keep this
        # early failure within the existing sanitized credential error path.
        raise PermissionError("AWS connector authentication failed before collection") from None


class _SynchronizedPipe:
    """Serialize child progress and background checkpoint frames on one pipe."""
    def __init__(self, connection):
        self.connection = connection
        self.lock = threading.Lock()

    def send(self, value):
        with self.lock:
            self.connection.send(value)

    def recv(self):
        return self.connection.recv()

    def close(self):
        self.connection.close()


def _restore_secret_capture(sink, artifacts, tenant, scan_id):
    """Carry encrypted prior witnesses into a reclaimed collector attempt."""
    from peaso.secret_evidence import (SCHEMA, MAX_BYTES, MAX_LOCATIONS, MAX_VALUES,
                                       private_reference, _lock as private_evidence_lock)
    document = artifacts.get(tenant, private_reference(tenant, scan_id))
    if (not isinstance(document, dict) or document.get("schema") != SCHEMA
            or document.get("tenant") != tenant or document.get("scan_id") != scan_id
            or not isinstance(document.get("records"), dict)
            or len(document["records"]) > MAX_VALUES or not isinstance(document.get("index"), str)):
        raise ValueError("Private checkpoint evidence boundary mismatch")
    index = sink.cipher.decrypt(document["index"])
    related = index.get("related") if isinstance(index, dict) else None
    if not isinstance(related, dict):
        raise ValueError("Private checkpoint index malformed")
    count, size = 0, 0
    for fingerprint, sealed in document["records"].items():
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or not isinstance(sealed, str):
            raise ValueError("Private checkpoint record malformed")
        row = sink.cipher.decrypt(sealed)
        if not isinstance(row, dict) or not isinstance(row.get("value"), str) or not isinstance(row.get("locations"), list):
            raise ValueError("Private checkpoint record malformed")
        count += len(row["locations"])
        size += len(sealed) + len(fingerprint)
    if count > MAX_LOCATIONS or size > MAX_BYTES:
        raise ValueError("Private checkpoint evidence budget exceeded")
    with private_evidence_lock:
        sink.records = dict(document["records"])
        sink.related = {key: set(value) for key, value in related.items()
                        if isinstance(key, str) and isinstance(value, list)
                        and all(isinstance(item, str) for item in value)}
        sink.locations, sink.bytes = count, size
        sink.related_count = sum(len(value) for value in sink.related.values())
        sink.incomplete = bool(document.get("incomplete"))


def _reusable_stages(artifacts, tenant, sections, stage_results):
    """Accept only stage artifacts bound to a complete final data revision."""
    reused = {}
    for stage, result in (stage_results or {}).items():
        if stage not in {"network", "hardening", "exposure"} or not isinstance(result, dict):
            continue
        section = sections.get(stage)
        if (not isinstance(section, dict) or section.get("status") != "complete"
                or section.get("data_revision") != result.get("data_revision")):
            continue
        try:
            artifact = artifacts.get(tenant, result["result_ref"])
        except (KeyError, ValueError, OSError):
            continue
        if (isinstance(artifact, dict) and artifact.get("stage") == stage
                and artifact.get("data_revision") == result.get("data_revision")
                and isinstance(artifact.get("result"), dict)):
            reused[stage] = artifact["result"]
    return reused


def _cached_ai_access_reference(artifacts, tenant, ident, bound, cache, identity_dir):
    """Keep one sealed reference per exact bound access set in this scan process."""
    marker = hashlib.sha256(json.dumps(bound, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    key = (tenant, ident, marker)
    reference = cache.get(key)
    if reference is None:
        from peaso.ai.crypto import AICipher
        reference = artifacts.put(tenant, ident, "ai-access", {"sealed":
            AICipher(identity_dir).encrypt({"entries": bound})})
        cache[key] = reference
    return reference

_ROLE_ARN = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}\Z")
_TARGET_MESSAGES = {
    "external_id_not_required_by_trust": "trust policy does not require External ID; add the sts:ExternalId condition shown in onboarding.",
    "external_id_trust_unverified": "the role's External ID boundary could not be verified; require an exact workspace External ID and retry.",
    "platform_owned_account": "this platform account cannot be a customer scan target.",
    "role_target_limit": "the hosted scan limit of 50 role targets was reached.",
}


def _curated_target_reasons(snapshot, connector):
    """Build bounded public reasons from known codes and configured role ARNs only."""
    if connector.get("provider") != "aws" or not connector.get("options", {}).get("hosted"):
        return []
    auth = connector.get("auth", {})
    roles = [auth.get("role_arn"), *auth.get("assume_roles", [])]
    configured = set()
    for entry in roles:
        arn = entry.get("role_arn") if isinstance(entry, dict) else entry
        if isinstance(arn, str) and _ROLE_ARN.fullmatch(arn):
            configured.add(arn)
    metadata = snapshot.get("metadata", {})
    if not isinstance(metadata, dict):
        return []
    errors = metadata.get("authentication_errors", [])
    if not isinstance(errors, list):
        return []
    reasons = []
    for entry in errors[:50]:
        if not isinstance(entry, dict) or not isinstance(entry.get("error"), dict):
            continue
        code, account = entry["error"].get("code"), entry.get("account")
        if not isinstance(code, str) or code not in _TARGET_MESSAGES or not isinstance(account, str):
            continue
        arn = entry.get("role_arn")
        if not isinstance(arn, str) or arn not in configured or arn.split(":")[4] != account:
            continue
        reasons.append({"code": code, "role_arn": arn,
                        "message": f"Role {arn} was refused: {_TARGET_MESSAGES[code]}"})
    return reasons


def _safe_failure_details(exc):
    """Diagnose application failures without logging exception values or locals."""
    root = Path(__file__).resolve().parent
    allowed = {"ValueError", "TypeError", "KeyError", "IndexError", "AttributeError", "ImportError",
               "ModuleNotFoundError", "PermissionError", "TimeoutError", "RuntimeError", "AssertionError"}
    name = type(exc).__name__
    details = {"exception_type": name if name in allowed else "provider_error", "source": "unavailable"}
    for frame in reversed(traceback.extract_tb(exc.__traceback__)):
        try:
            relative = Path(frame.filename).resolve().relative_to(root)
        except ValueError:
            continue
        if relative.suffix == ".py" and all(part.replace("_", "").replace(".", "").isalnum() for part in relative.parts):
            details["source"] = "peaso/" + relative.as_posix() + ":" + str(frame.lineno)
            break
    return details


def _process(role, request, connection):
    connection = _SynchronizedPipe(connection)
    # Provider exceptions and third-party libraries must never log credentials.
    with open(os.devnull, "w") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    failure_reasons = []
    def stop_child(*_):
        raise SystemExit()
    signal.signal(signal.SIGTERM, stop_child)
    try:
        config = request.pop("artifact_config")
        artifacts = FileArtifacts(Path(config["root"])) if config["mode"] == "file" else S3Artifacts(config["bucket"], kms_key=config.get("kms_key"))
        tenant, ident = request["tenant_id"], request["scan_id"]
        from peaso.storage.report_reuse import ReusableReportArtifacts
        publication_artifacts = ReusableReportArtifacts(artifacts, tenant, ident)
        if role == "collector":
            _verify_aws_credentials(request.get("connector", {}))
            from peaso.engine import collect_snapshot
            from peaso.snapshot import seal
            connector = request.get("connector", {})
            if (role == "collector" and connector.get("provider") == "gcp"
                    and connector.get("auth", {}).get("method") == "platform-service-account"):
                from peaso.gcp_platform import load_service_account
                connector["auth"]["sa_json"] = load_service_account(Settings().gcp_platform_sa_secret_arn)
            from peaso.ai import access as ai_access
            if request.get("ai_enabled", True):
                # A shared collector identity can read other customers' projects.
                # Assigned scope labels do not downscope its bearer token.
                shared_identity = (connector.get("provider") == "gcp" and
                                   connector.get("auth", {}).get("method") == "platform-service-account")
                ai_access.begin(allow_live=not shared_identity)
            from peaso.secret_evidence import capture, checks_for_request
            evidence_cipher = CredentialCipher(Path(request.get('ai_context', {}).get('identity_dir') or Settings().identity_dir))
            with capture(evidence_cipher, tenant=tenant, scan_id=ident, options=connector.get('options'),
                         selected_checks=checks_for_request(request)) as secret_capture:
                from peaso.incremental import CheckpointSession
                from peaso.secret_evidence import _lock as private_evidence_lock, without_private_values
                if request.get("checkpoint_refs"):
                    _restore_secret_capture(secret_capture, artifacts, tenant, ident)

                ai_access_cache = {}

                def public_checkpoint(raw):
                    public = seal(redact(secret_capture.public_snapshot(raw),
                                         tuple(credential_values(connector.get("auth", {})))))
                    if request.get("ai_enabled", True):
                        try:
                            entries = ai_access.peek()
                            bound = ai_access.bind_targets(entries, public) if entries else []
                            if bound:
                                reference = _cached_ai_access_reference(artifacts, tenant, ident,
                                    bound, ai_access_cache, Path(request.get('ai_context', {}).get('identity_dir') or Settings().identity_dir))
                                public.setdefault("metadata", {})["ai_access_reference"] = reference
                        except Exception:
                            public.setdefault("metadata", {})["ai_access_status"] = "unavailable"
                    return seal(public)

                checkpoint_lock = threading.Lock()

                def checkpoint(snapshot, report, sequence):
                    # Commit private evidence before the supervisor can expose
                    # any public checkpoint from this native read. The entire
                    # handoff is serialized so an older publisher cannot
                    # overwrite the latest encrypted private document.
                    with checkpoint_lock:
                        with private_evidence_lock:
                            document = secret_capture.document()
                        artifacts.put_secret_evidence(tenant, ident, document)
                        snapshot_ref = artifacts.put(tenant, ident, "snapshot", snapshot)
                        if report is not None:
                            from peaso.storage.reports import publish_report
                            report_ref = publish_report(publication_artifacts, tenant, ident,
                                                        without_private_values(redact_report(report)), snapshot)
                        else:
                            report_ref = None
                        batch = (report is None and 'batch_revisions' in
                                 snapshot.get('metadata', {}).get('incremental', {}))
                        envelope = snapshot["collections"][0] if report is None and not batch else None
                        connection.send(("__checkpoint__", {"sequence": sequence, "stage": "collector",
                            "snapshot_ref": snapshot_ref, "report_ref": report_ref,
                            "kind": '__checkpoint_batch__' if batch else envelope["type"] if envelope else None,
                            "scope": str(sequence) if batch else envelope["scope"] if envelope else None}))
                        if connection.recv() != ("__checkpoint_ack__", sequence, True):
                            raise RuntimeError("checkpoint lease or publication rejected")

                checkpoint_session = CheckpointSession(request, checkpoint, public_checkpoint)
                restored = [artifacts.get(tenant, reference) for reference in
                    dict.fromkeys(request.get("checkpoint_refs", ()))]
                checkpoint_session.restore(restored, int(request.get("checkpoint_sequence", 0)))
                request["_collection_callback"] = checkpoint_session.on_collection
                request["_scope_plan_callback"] = checkpoint_session.on_scope_plan
                try:
                    from peaso.worker_progress import stream_progress
                    with stream_progress(connection):
                        snapshot = collect_snapshot(request)
                    checkpoint_session.finish_collection()
                    snapshot.setdefault("metadata", {})["sections"] = checkpoint_session.sections()
                finally:
                    checkpoint_session.close()
                    request.pop("_collection_callback", None)
                    request.pop("_scope_plan_callback", None)
                    ai_credentials = ai_access.finish()
            # Separate encrypted per-scan object; no reference or value enters
            # the native snapshot, public report, supervisor pipe or AI context.
            snapshot = secret_capture.public_snapshot(snapshot)
            artifacts.put_secret_evidence(tenant, ident, secret_capture.document())
            if request.get("ai_enabled", True) and ai_credentials:
                try:
                    ai_credentials = ai_access.bind_targets(ai_credentials, snapshot)
                    access_reference = _cached_ai_access_reference(artifacts, tenant, ident,
                        ai_credentials, ai_access_cache, Path(request.get("ai_context", {}).get("identity_dir") or Settings().identity_dir))
                    snapshot.setdefault("metadata", {})["ai_access_reference"] = access_reference
                except Exception:
                    snapshot.setdefault("metadata", {})["ai_access_status"] = "unavailable"
            del ai_credentials
            from peaso.snapshot import nothing_readable
            if nothing_readable(snapshot):
                # Every read failed (expired/wrong credentials): fail the scan instead of publishing an empty assessment.
                failure_reasons = _curated_target_reasons(snapshot, request["connector"])
                raise PermissionError("no collection was readable with the connector credentials")
            snapshot.setdefault("metadata", {})["input_mode"] = request["connector"].get("input_mode", "live")
            value = seal(redact(snapshot, tuple(credential_values(request["connector"].get("auth", {})))))
            reference = artifacts.put(tenant, ident, "snapshot", value)
        else:
            from peaso.engine import evaluate_snapshot
            selectors = request["selectors"]
            snapshot = artifacts.get(tenant, request["snapshot_ref"])
            related, sources = [], {}
            for entry in request.get("related", []):
                try:
                    item = artifacts.get(tenant, entry["snapshot_ref"])
                except Exception:  # noqa: BLE001 - an expired/removed sibling snapshot only means no join
                    continue
                related.append(item)
                sources[item.get("snapshot_id")] = {"scan_id": entry["scan_id"], "connector_id": entry["connector_id"]}
            report = evaluate_snapshot(snapshot, categories=selectors.get("categories") or None,
                           checks=selectors.get("checks") or None, frameworks=selectors.get("frameworks") or None,
                           include_not_applicable=bool(selectors.get("include_not_applicable", False)),
                           related_snapshots=related)
            for row in report.get("related_snapshots", []):
                row.update(sources.get(row["snapshot_id"], {}))
            value = redact_report(report)
            value["input_mode"] = snapshot.get("metadata", {}).get("input_mode", "live")
            from peaso.storage.cost import runtime_estimate
            value["runtime"] = runtime_estimate(request["timeline"])
            from peaso.storage.reports import publish_report
            native_sequence = int(request.get("checkpoint_sequence", 0)) + 1
            sections = snapshot.get("metadata", {}).get("sections", {})
            sections = sections if isinstance(sections, dict) else {}
            native_value = dict(value, publication={"state": "partial", "phase": "analyzing",
                                                    "sequence": native_sequence, "sections": sections})
            native_reference = publish_report(publication_artifacts, tenant, ident, native_value, snapshot)
            connection.send(("__checkpoint__", {"sequence": native_sequence,
                "stage": "analyzer_native", "snapshot_ref": request["snapshot_ref"],
                "report_ref": native_reference, "kind": None, "scope": None}))
            if connection.recv() != ("__checkpoint_ack__", native_sequence, True):
                raise RuntimeError("native analysis checkpoint rejected")
            from peaso.ai.pipeline import review_scan
            reused_stages = _reusable_stages(artifacts, tenant, sections, request.get("stage_results"))
            value["ai"] = review_scan(value, snapshot, selectors, tenant=tenant, artifacts=artifacts,
                                      deadline=request.get("deadline"), context=request.get("ai_context"),
                                      reused_stages=reused_stages)
            from peaso.ai.network import with_findings
            value = with_findings(value, value["ai"].get("network", {}).get("findings", []))
            value["publication"] = {"state": "final", "phase": "completed", "sequence": native_sequence,
                                    "sections": sections}
            reference = publish_report(publication_artifacts, tenant, ident, value, snapshot)
        # Large evidence/report objects never cross the supervisor process pipe.
        connection.send((True, reference))
    except BaseException as exc:
        if isinstance(exc, (ValueError, TypeError, KeyError)):
            code = "invalid_input"
        elif isinstance(exc, ImportError):
            code = "dependency_unavailable"
        elif isinstance(exc, PermissionError):
            # OS errors name the inaccessible local artifact in filename. A
            # provider authorization failure has no local filename; never
            # include either the path or provider message in public details.
            code = "dependency_unavailable" if exc.filename else "credential_access_denied"
        elif isinstance(exc, TimeoutError):
            code = "collector_timeout"
        else:
            code = "provider_error"
        connection.send((False, code, _safe_failure_details(exc), failure_reasons))
    finally:
        connection.close()


def redact_report(report):
    """redact() a report. check_frameworks / check_meta are keyed by public catalog check ids (e.g.
    "...client_secret"), so only their values are redacted, never the id keys: a secret-shaped id
    must not turn its per-check entry into "[REDACTED]"."""
    per_check = {key: report[key] for key in ("check_frameworks", "check_meta") if isinstance(report.get(key), dict)}
    value = redact({key: item for key, item in report.items() if key not in per_check})
    for key, mapping in per_check.items():
        value[key] = {check_id: redact(item) for check_id, item in mapping.items()}
    return value


# Scan group = same tenant: an analyzer run joins the latest collected snapshot of each other connector whose
# provider the privesc model joins with this one (K8s <-> clouds), so a GKE/EKS/AKS cluster scan and a scan of
# its cloud account/project show the cross-provider paths. Bounded in count and age (RAM, stale facts).
RELATED_PROVIDERS = {"k8s": {"aws", "gcp", "azure"}, "aws": {"k8s"}, "gcp": {"k8s"}, "azure": {"k8s"}}
RELATED_MAX_SNAPSHOTS = 8
RELATED_MAX_AGE_SECONDS = 8 * 86400  # a weekly schedule plus a day of slack


def related_snapshot_refs(store, job):
    """[{scan_id, connector_id, provider, snapshot_ref}] for the analyzer job's scan group (newest per connector)."""
    tenant = job["tenant"]
    provider = json.loads(job["connector"])["data"].get("provider")
    wanted = RELATED_PROVIDERS.get(provider, set())
    out, seen = [], {job["connector_id"]}
    if not wanted:
        return out
    for public in store.jobs(tenant):  # newest first
        if len(out) >= RELATED_MAX_SNAPSHOTS:
            break
        if public["id"] == job["id"] or public.get("connector_id") in seen or public["status"] not in {"collected", "analyzing", "completed"}:
            continue
        row = store.job(tenant, public["id"])
        if not row.get("snapshot") or abs(float(job["created"]) - float(row["created"])) > RELATED_MAX_AGE_SECONDS:
            continue
        other = json.loads(row["connector"])["data"].get("provider")
        if other not in wanted:
            continue
        seen.add(row["connector_id"])
        out.append({"scan_id": row["id"], "connector_id": row["connector_id"], "provider": other, "snapshot_ref": row["snapshot"]})
    return out


class Worker:
    def __init__(self, role, settings=None, *, store=None, artifacts=None, authenticator=None):
        self.settings = settings or Settings()
        self.role = role
        if store is None or artifacts is None:
            runtime_store, runtime_artifacts = stores(self.settings)
            store, artifacts = store or runtime_store, artifacts or runtime_artifacts
        self.store, self.artifacts = store, artifacts
        self.cipher = CredentialCipher(self.settings.identity_dir) if role == "collector" else None
        self.authenticator = authenticator or (Authenticator(self.settings) if role == "collector" else None)
        if isinstance(self.authenticator, Authenticator):
            self.authenticator.store = self.store
        self.stopping = threading.Event()

    def schedule_tick(self, now=None):
        if self.role != "collector":
            return []
        results = []
        for row in self.store.due_schedules(now):
            try:
                selectors = json.loads(row['data'])
                if selectors.get('ai_enabled', True):
                    from peaso.ai.auth import require_local_codex
                    require_local_codex(self.settings, self.store, selectors.get('ai_user_id', row['tenant']))
                paid = self.authenticator.is_paid(row["tenant"])
            except HTTPException as exc:
                if exc.status_code == 401:
                    self.store.pause_schedule(row["tenant"], row["id"])
                # An outage leaves the occurrence due for a later retry.
                continue
            result = self.store.trigger_schedule(row, 10 if paid else 1, self.settings.scan_timeout, now)
            if result:
                results.append(result)
                WorkflowDispatcher().dispatch(row["tenant"], result)
        return results

    def run_once(self, tenant=None, ident=None):
        job = self.store.claim(self.role, self.settings.lease_seconds, tenant=tenant, ident=ident)
        if not job:
            return False
        process, parent, child = None, None, None
        try:
            selectors = json.loads(job["data"])
            if selectors.get('ai_enabled', True):
                from peaso.ai.providers import review_disabled
                if review_disabled(self.store, selectors.get('ai_user_id', job['tenant'])):
                    selectors['ai_enabled'] = False
            if self.role == "collector":
                encrypted = json.loads(job["connector"])
                private = self.cipher.decrypt(encrypted["auth"])
                connector = dict(encrypted["data"], auth=private["auth"], options=private["options"])
                if self.settings.auth_mode == "cognito":
                    from peaso.server.validation import validate_connector
                    validate_connector(connector["provider"], connector["auth"], connector["options"], self.settings,
                                       server_external_id=True, scopes=connector.get("scopes", []))
                    connector["options"] = dict(connector["options"], hosted=True)
                    if connector["provider"] == "aws" and connector["auth"].get("method") == "assume_role":
                        connector["auth"]["method"] = "access_keys" if connector["auth"].get("aws_access_key_id") else "task_role"
                elif connector["provider"] == "aws" and connector["auth"].get("method") == "assume_role":
                    connector["auth"]["method"] = "profile" if connector["auth"].get("profile") else "access_keys" if connector["auth"].get("aws_access_key_id") else "default"
                request = dict(selectors, connector=connector)
            else:
                request = {"snapshot_ref": job["snapshot"], "selectors": selectors,
                           "related": related_snapshot_refs(self.store, job),
                           "stage_results": self.store.stage_results(job["tenant"], job["id"])}
            request["checkpoint_sequence"] = int(job.get("checkpoint_sequence") or 0)
            if self.role == "collector":
                request["checkpoint_refs"] = [row["reference"] for row in sorted(
                    self.store.checkpoint_collections(job["tenant"], job["id"]),
                    key=lambda row: row["sequence"])]
            request.update(tenant_id=job["tenant"], scan_id=job["id"], deadline=job["deadline"], artifact_config={"mode": "file", "root": str(self.artifacts.root)} if isinstance(self.artifacts, FileArtifacts) else {"mode": "s3", "bucket": self.artifacts.bucket, "kms_key": self.artifacts.kms_key})
            request["ai_context"] = {"state_dir": str(self.settings.state_dir), "identity_dir": str(self.settings.identity_dir)}
            request["timeline"] = self.store.public_job(job)["timeline"]
            context = multiprocessing.get_context("spawn")
            parent, child = context.Pipe(duplex=True)
            process = context.Process(target=_process, args=(self.role, request, child), daemon=True)
            process.start()
            child.close()
            next_heartbeat = 0
            result = None
            while not self.stopping.is_set():
                now = time.time()
                if now >= job["deadline"]:
                    self.store.expire_job(job["tenant"], job["id"], now)
                    return True
                if now >= next_heartbeat:
                    if not self.store.heartbeat(job["id"], job["owner"], self.settings.lease_seconds):
                        return True
                    next_heartbeat = now + max(0.2, self.settings.lease_seconds / 3)
                # Cancellation is checked independently of the heartbeat interval.
                if self.store.job(job["tenant"], job["id"])["status"] not in {"collecting", "analyzing"}:
                    return True
                if parent.poll(0.2):
                    try:
                        result = parent.recv()
                        if isinstance(result, tuple) and len(result) == 2 and result[0] == "__progress__":
                            from peaso.worker_progress import record_progress
                            record_progress(self.store, job, result[1], LOGGER)
                            result = None
                            continue
                        if isinstance(result, tuple) and len(result) == 2 and result[0] == "__checkpoint__":
                            event = result[1]
                            accepted = self.store.record_checkpoint(job["tenant"], job["id"], job["owner"],
                                event["sequence"], event["snapshot_ref"], kind=event.get("kind"),
                                scope=event.get("scope"), report_ref=event.get("report_ref"),
                                stage=event.get("stage", "collector"))
                            parent.send(("__checkpoint_ack__", event["sequence"], bool(accepted)))
                            if not accepted:
                                return True
                            result = None
                            continue
                    except EOFError:
                        # A killed child cannot report a result. SIGKILL alone
                        # does not establish OOM; persist a safe interruption.
                        result = None
                    break
                if not process.is_alive():
                    break
            if self.stopping.is_set():
                # Leave lease to expire; restart can safely reclaim the job.
                return True
            if result and result[0]:
                kind = "snapshot" if self.role == "collector" else "report"
                self.store.finish(job["id"], job["owner"], "collected" if kind == "snapshot" else "completed", result[1])
            else:
                if result and len(result) > 2:
                    LOGGER.warning("Scan worker failed: code=%s type=%s source=%s", result[1],
                                   result[2]["exception_type"], result[2]["source"])
                self.store.finish(job["id"], job["owner"], "failed", error_code=result[1] if result else "worker_interrupted",
                                  failure_reasons=result[3] if result and len(result) > 3 else None)
            return True
        except Exception as exc:
            details = _safe_failure_details(exc)
            LOGGER.warning("Scan worker failed: code=artifact_error type=%s source=%s", details["exception_type"], details["source"])
            self.store.finish(job["id"], job["owner"], "failed", error_code="artifact_error")
            return True
        finally:
            if process is not None:
                if process.is_alive():
                    process.terminate()
                process.join(timeout=2)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=2)
            if parent is not None:
                parent.close()
            if child is not None:
                child.close()

    def run(self):
        def schedule_loop():
            while not self.stopping.is_set():
                try:
                    self.schedule_tick()
                except Exception:
                    # A transient scheduler failure is retried without logging credentials.
                    pass
                self.stopping.wait(30)
        scheduler = threading.Thread(target=schedule_loop, name='scan-scheduler', daemon=True) if self.role == 'collector' else None
        if scheduler:
            scheduler.start()
        try:
            while not self.stopping.is_set():
                try:
                    if not self.run_once():
                        self.stopping.wait(1)
                except Exception:
                    # Do not serialize exceptions: SDK errors can embed auth material.
                    self.stopping.wait(2)
        finally:
            self.stopping.set()
            if scheduler:
                scheduler.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("collector", "analyzer"))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--ai-smoke", action="store_true", help="Run the isolated live AI deployment acceptance check")
    parser.add_argument("--progressive", action="store_true", help="Watch one scan's completed sections while collection continues")
    parser.add_argument("--tenant-id")
    parser.add_argument("--scan-id")
    args = parser.parse_args()
    if bool(args.tenant_id) != bool(args.scan_id):
        parser.error("--tenant-id and --scan-id must be supplied together")
    if args.ai_smoke:
        if args.role != "analyzer" or args.once or args.tenant_id or args.scan_id or args.progressive:
            parser.error("--ai-smoke requires the analyzer role without scan selectors")
        from .ai.smoke import main as ai_smoke
        ai_smoke()
        return
    # Only this application's sanitized supervisor messages are enabled.
    # Provider/third-party child stdout and stderr remain suppressed.
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    worker = Worker(args.role)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: worker.stopping.set())
    if args.progressive:
        if args.role != "analyzer" or not args.tenant_id or not args.scan_id:
            parser.error("--progressive requires analyzer role and one tenant/scan selector")
        from .progressive_analyzer import run_progressive
        if run_progressive(worker, args.tenant_id, args.scan_id) != "completed":
            raise SystemExit(1)
        return
    if args.once:
        worker.run_once(args.tenant_id, args.scan_id)
    else:
        worker.run()


if __name__ == "__main__":
    main()
