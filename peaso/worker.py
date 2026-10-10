"""Durable collector/scheduler and offline analyzer with fenced, cancellable jobs."""
import argparse
import json
import multiprocessing
import os
import signal
import threading
import time
from pathlib import Path
from fastapi import HTTPException
from peaso.auth import Authenticator, CredentialCipher, redact
from peaso.auth.secrets import credential_values
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts, S3Artifacts
from peaso.storage.runtime import stores, WorkflowDispatcher


def _process(role, request, connection):
    # Provider exceptions and third-party libraries must never log credentials.
    with open(os.devnull, "w") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    try:
        config = request.pop("artifact_config")
        artifacts = FileArtifacts(Path(config["root"])) if config["mode"] == "file" else S3Artifacts(config["bucket"], kms_key=config.get("kms_key"))
        tenant, ident = request["tenant_id"], request["scan_id"]
        if role == "collector":
            from peaso.engine import collect_snapshot
            from peaso.snapshot import seal
            snapshot = collect_snapshot(request)
            snapshot.setdefault("metadata", {})["input_mode"] = request["connector"].get("input_mode", "live")
            value = seal(redact(snapshot, tuple(credential_values(request["connector"].get("auth", {})))))
            reference = artifacts.put(tenant, ident, "snapshot", value)
        else:
            from peaso.engine import evaluate_snapshot
            selectors = request["selectors"]
            snapshot = artifacts.get(tenant, request["snapshot_ref"])
            value = redact(evaluate_snapshot(snapshot, categories=selectors.get("categories") or None,
                           checks=selectors.get("checks") or None, frameworks=selectors.get("frameworks") or None))
            value["input_mode"] = snapshot.get("metadata", {}).get("input_mode", "live")
            from peaso.storage.cost import runtime_estimate
            value["runtime"] = runtime_estimate(request["timeline"])
            from peaso.storage.reports import publish_report
            reference = publish_report(artifacts, tenant, ident, value, snapshot)
        # Large evidence/report objects never cross the supervisor process pipe.
        connection.send((True, reference))
    except BaseException as exc:
        code = "invalid_input" if isinstance(exc, (ValueError, TypeError, KeyError)) else "dependency_unavailable" if isinstance(exc, ImportError) else "credential_access_denied" if isinstance(exc, PermissionError) else "collector_timeout" if isinstance(exc, TimeoutError) else "provider_error"
        connection.send((False, code))
    finally:
        connection.close()


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
                    validate_connector(connector["provider"], connector["auth"], connector["options"], self.settings, server_external_id=True)
                    connector["options"] = dict(connector["options"], hosted=True)
                    if connector["provider"] == "aws" and connector["auth"].get("method") == "assume_role":
                        connector["auth"]["method"] = "access_keys" if connector["auth"].get("aws_access_key_id") else "task_role"
                elif connector["provider"] == "aws" and connector["auth"].get("method") == "assume_role":
                    connector["auth"]["method"] = "profile" if connector["auth"].get("profile") else "access_keys" if connector["auth"].get("aws_access_key_id") else "default"
                if connector["provider"] == "k8s":
                    aliases = {"inline": "kubeconfig", "client-cert": "cert"}
                    connector["auth"]["method"] = aliases.get(connector["auth"].get("method"), connector["auth"].get("method", "auto"))
                request = dict(selectors, connector=connector)
            else:
                request = {"snapshot_ref": job["snapshot"], "selectors": selectors}
            request.update(tenant_id=job["tenant"], scan_id=job["id"], artifact_config={"mode": "file", "root": str(self.artifacts.root)} if isinstance(self.artifacts, FileArtifacts) else {"mode": "s3", "bucket": self.artifacts.bucket, "kms_key": self.artifacts.kms_key})
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
                    self.store.expire(now)
                    return True
                if now >= next_heartbeat:
                    if not self.store.heartbeat(job["id"], job["owner"], self.settings.lease_seconds):
                        return True
                    next_heartbeat = now + max(0.2, self.settings.lease_seconds / 3)
                # Cancellation is checked independently of the heartbeat interval.
                if self.store.job(job["tenant"], job["id"])["status"] not in {"collecting", "analyzing"}:
                    return True
                if parent.poll(0.2):
                    result = parent.recv()
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
                self.store.finish(job["id"], job["owner"], "failed", error_code=result[1] if result else "worker_interrupted")
            return True
        except Exception:
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
        while not self.stopping.is_set():
            try:
                self.schedule_tick()
                if not self.run_once():
                    self.stopping.wait(1)
            except Exception:
                # Do not serialize exceptions: SDK errors can embed auth material.
                self.stopping.wait(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("collector", "analyzer"))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--tenant-id")
    parser.add_argument("--scan-id")
    args = parser.parse_args()
    if bool(args.tenant_id) != bool(args.scan_id):
        parser.error("--tenant-id and --scan-id must be supplied together")
    worker = Worker(args.role)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: worker.stopping.set())
    if args.once:
        worker.run_once(args.tenant_id, args.scan_id)
    else:
        worker.run()


if __name__ == "__main__":
    main()
