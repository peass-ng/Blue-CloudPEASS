"""Durable collection and analysis with optional post-scan AI and fenced jobs."""
import argparse
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
        if role == "collector":
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
                try:
                    snapshot = collect_snapshot(request)
                finally:
                    ai_credentials = ai_access.finish()
            # Separate encrypted per-scan object; no reference or value enters
            # the native snapshot, public report, supervisor pipe or AI context.
            snapshot = secret_capture.public_snapshot(snapshot)
            artifacts.put_secret_evidence(tenant, ident, secret_capture.document())
            if request.get("ai_enabled", True) and ai_credentials:
                try:
                    ai_credentials = ai_access.bind_targets(ai_credentials, snapshot)
                    from peaso.ai.crypto import AICipher
                    access_reference = artifacts.put(tenant, ident, "ai-access", {"sealed": AICipher(Path(request.get("ai_context", {}).get("identity_dir") or Settings().identity_dir)).encrypt({"entries": ai_credentials})})
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
            from peaso.ai.pipeline import review_scan
            value["ai"] = review_scan(value, snapshot, selectors, tenant=tenant, artifacts=artifacts, deadline=request.get("deadline"), context=request.get("ai_context"))
            from peaso.ai.network import with_findings
            value = with_findings(value, value["ai"].get("network", {}).get("findings", []))
            from peaso.storage.reports import publish_report
            reference = publish_report(artifacts, tenant, ident, value, snapshot)
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
                request = {"snapshot_ref": job["snapshot"], "selectors": selectors, "related": related_snapshot_refs(self.store, job)}
            request.update(tenant_id=job["tenant"], scan_id=job["id"], deadline=job["deadline"], artifact_config={"mode": "file", "root": str(self.artifacts.root)} if isinstance(self.artifacts, FileArtifacts) else {"mode": "s3", "bucket": self.artifacts.bucket, "kms_key": self.artifacts.kms_key})
            request["ai_context"] = {"state_dir": str(self.settings.state_dir), "identity_dir": str(self.settings.identity_dir)}
            request["timeline"] = self.store.public_job(job)["timeline"]
            context = multiprocessing.get_context("spawn")
            parent, child = context.Pipe(duplex=False)
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
    parser.add_argument("--tenant-id")
    parser.add_argument("--scan-id")
    args = parser.parse_args()
    if bool(args.tenant_id) != bool(args.scan_id):
        parser.error("--tenant-id and --scan-id must be supplied together")
    if args.ai_smoke:
        if args.role != "analyzer" or args.once or args.tenant_id or args.scan_id:
            parser.error("--ai-smoke requires the analyzer role without scan selectors")
        from .ai.smoke import main as ai_smoke
        ai_smoke()
        return
    worker = Worker(args.role)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: worker.stopping.set())
    if args.once:
        worker.run_once(args.tenant_id, args.scan_id)
    else:
        worker.run()


if __name__ == "__main__":
    main()
