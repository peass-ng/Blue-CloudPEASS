"""Isolated Compose acceptance: read-only AWS, weekly scheduler, UI, owned cleanup.

Credentials stay in process memory and the encrypted disposable Compose volume.
The weekly rescan uses the production scheduler with an explicit next-week clock;
it does not change quota records, paid entitlements, or production resources.
"""
from __future__ import annotations

from peaso import deployment
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import traceback
import uuid

import boto3
import httpx

ROOT = Path(__file__).resolve().parents[2]
INVENTORIES = ["aws_account", "iam_user", "iam_group", "iam_role", "iam_policy",
               "iam_account_summary", "instance", "vpc", "subnet", "security_group",
               "network_acl", "route_table", "internet_gateway", "network_interface"]
COPY_INPUTS = ("pyproject.toml", "peaso", "bluepeass", "scripts", "risk_rules", "frontend",
               "infra/aws/sdk-constraints.txt")
CONTEXT_FILES = ("Dockerfile.peaso", "docker-compose.yml", ".dockerignore")
IGNORED_DIRS = {".git", ".venv", "node_modules", "dist", "evidence", ".cache",
                ".benchmarks", ".aws", ".azure", ".kube", ".peaso",
                "__pycache__", ".pytest_cache"}
IGNORED_SUFFIXES = {".pyc", ".yaml", ".yml", ".png", ".csv", ".log",
                    ".pem", ".key", ".zip"}


def source_manifest(root=ROOT):
    """Hash the Docker COPY inputs without reading excluded secrets or build output."""
    paths = [root / name for name in CONTEXT_FILES]
    for path in paths:
        if not path.is_file():
            raise RuntimeError("Missing Docker build context file: " + path.name)
    for name in COPY_INPUTS:
        entry = root / name
        if not entry.exists():
            raise RuntimeError("Missing Docker COPY input: " + name)
        if entry.is_file():
            paths.append(entry)
            continue
        for current, directories, files in os.walk(entry):
            for directory in directories:
                if (Path(current) / directory).is_symlink():
                    raise RuntimeError("Build input contains a directory symlink: " + str(Path(current, directory).relative_to(root)))
            directories[:] = sorted(item for item in directories if item not in IGNORED_DIRS)
            paths.extend(Path(current) / item for item in files)
    digest = hashlib.sha256()
    count = 0
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise RuntimeError("Build input contains a symlink: " + relative)
        if not path.is_file() or (path.name.startswith(".env") and path.name != ".env.example") or path.name.startswith("untitled") or ".tfstate" in path.name:
            continue
        if path.suffix in IGNORED_SUFFIXES and not relative.startswith(("peaso/", "risk_rules/", "frontend/src/", "frontend/public/")):
            continue
        if path.suffix == ".json" and relative not in {"frontend/package.json", "frontend/package-lock.json", "frontend/tsconfig.json", "bluepeass/hardening_catalog.json"} and not relative.startswith(("peaso/", "risk_rules/", "frontend/src/", "frontend/public/")):
            continue
        digest.update(relative.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest() + b"\n")
        count += 1
    return {"sha256": digest.hexdigest(), "files": count}


class Acceptance:
    def __init__(self, directory, profile, region):
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.token = secrets.token_urlsafe(32)
        self.secret_values = [self.token]
        self.profile, self.region = profile, region
        self.project = "peaso-api-qa-" + uuid.uuid4().hex[:12]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.env = dict(os.environ, PEASO_LOCAL_TOKEN=self.token,
                        PEASO_PORT=str(self.port), PEASO_ALLOWED_ORIGINS=self.origin,
                        COMPOSE_PARALLEL_LIMIT="1")
        self.compose = ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"), "-p", self.project]
        self.summary = {"project": self.project, "origin": self.origin,
                        "started_at": datetime.now(timezone.utc).isoformat(),
                        "commands": [], "gates": {}, "cleanup": "pending"}
        self.client = httpx.Client(base_url=self.origin, timeout=120,
                                   headers={"Authorization": "Bearer " + self.token})

    def save(self):
        (self.directory / "summary.json").write_text(json.dumps(self.summary, indent=2) + "\n")

    def sanitized(self, text):
        for value in self.secret_values:
            if value:
                text = text.replace(value, "[REDACTED]")
        return text

    def playwright_command(self):
        configured = self.env.get("PEASO_PLAYWRIGHT_BIN")
        if not configured:
            self.summary["playwright_binary"] = {"mode": "local npx"}
            return ["npx", "playwright"]
        binary = Path(configured)
        if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError("PEASO_PLAYWRIGHT_BIN must name an existing executable absolute file")
        resolved = binary.resolve(strict=True)
        metadata = resolved.parent / "package.json"
        if not metadata.is_file():
            raise RuntimeError("Playwright binary package metadata is missing")
        package = json.loads(metadata.read_text())
        self.summary["playwright_binary"] = {
            "mode": "explicit local binary", "path": str(binary), "resolved_path": str(resolved),
            "binary_sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
            "package_name": package.get("name"), "package_version": package.get("version"),
            "metadata_sha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
        }
        self.save()
        return [str(binary)]

    def command(self, argv, label, *, cwd=ROOT, env=None, timeout=1200):
        self.summary["commands"].append({"argv": argv, "label": label})
        self.save()
        result = subprocess.run(argv, cwd=cwd, env=env or self.env, capture_output=True,
                                text=True, timeout=timeout)
        (self.directory / (label + ".log")).write_text(self.sanitized(result.stdout + result.stderr))
        self.summary["commands"][-1]["exit_code"] = result.returncode
        self.save()
        if result.returncode:
            raise RuntimeError(label + " failed; see sanitized log")
        return result.stdout

    def request(self, method, path, *, expected=200, **kwargs):
        response = self.client.request(method, path, **kwargs)
        if response.status_code != expected:
            # Provider/credential bodies never enter the exception or transcript.
            raise RuntimeError(f"{method} {path}: HTTP {response.status_code}, expected {expected}")
        return response.json() if response.content else None

    def wait_scan(self, ident):
        deadline = time.monotonic() + 900
        history = []
        while time.monotonic() < deadline:
            row = self.request("GET", "/api/scans/" + ident)
            if not history or history[-1] != row["status"]:
                history.append(row["status"])
                print("scan " + ident + ": " + row["status"], flush=True)
            if row["status"] == "completed":
                return {"id": ident, "status": "completed", "input_mode": row["input_mode"],
                        "observed_states": history, "timeline": row.get("timeline")}
            if row["status"] in {"failed", "timed_out", "cancelled"}:
                error = row.get("error")
                timeline = row.get("timeline")
                self.summary["scan_error"] = {"id": ident, "status": row["status"],
                                              "error": self.sanitized(json.dumps(error)) if error is not None else None,
                                              "error_code": self.sanitized(row["error_code"]) if isinstance(row.get("error_code"), str) else None,
                                              "error_stage": self.sanitized(row["error_stage"]) if isinstance(row.get("error_stage"), str) else None,
                                              "timeline": [{"status": self.sanitized(event["status"]),
                                                            "at": self.sanitized(event["at"])}
                                                           for event in timeline if isinstance(event, dict)
                                                           and isinstance(event.get("status"), str)
                                                           and isinstance(event.get("at"), str)] if isinstance(timeline, list) else None}
                self.save()
                raise RuntimeError("scan ended " + row["status"])
            time.sleep(2)
        raise TimeoutError("scan did not settle")

    def report(self, ident):
        from peaso.engine import hydrate_findings
        report = self.request("GET", f"/api/scans/{ident}/report")
        assert report["input_mode"] == "live" and report["provider"] == "aws"
        assert report["resources"] and report["findings"]
        encoded = json.dumps(report)
        assert all(value not in encoded for value in self.secret_values if value)
        graphs = {}
        for kind in ["network", "iam", "privesc"]:
            graph = self.request("GET", f"/api/scans/{ident}/graphs/{kind}?max_nodes=500")
            graphs[kind] = {"nodes": len(graph.get("nodes", [])), "edges": len(graph.get("edges", []))}
            assert graphs[kind]["nodes"], kind
        findings = Counter(row["category"] for row in hydrate_findings(report)["findings"])
        assert all(findings[category] for category in ["hardening", "exposure", "least_privilege"])
        markdown = self.client.get(f"/api/scans/{ident}/report?format=markdown")
        assert markdown.status_code == 200 and report["snapshot_id"] in markdown.text
        assert all(value not in markdown.text for value in self.secret_values if value)
        return {"snapshot_id": report["snapshot_id"], "resources": len(report["resources"]),
                "findings": len(report["findings"]), "findings_by_category": dict(findings),
                "stats": report["stats"], "graphs": graphs,
                "downloads": {"json": True, "markdown": True},
                "report_sha256": hashlib.sha256(encoded.encode()).hexdigest()}

    def run(self):
        playwright = self.playwright_command()
        self.summary["docker_id"] = self.command(["docker", "info", "--format", "{{.ID}}"], "docker-identity").strip()
        assert not self.command(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + self.project], "ownership-preflight").strip()
        try:
            self.summary["source"] = {"before_build": source_manifest()}
            self.summary["images"] = {}
            self.save()
            for service in ["api", "collector", "analyzer"]:
                print("building " + service, flush=True)
                self.command(self.compose + ["build", service], "build-" + service)
                image = self.command(["docker", "image", "inspect", "--format", "{{.Id}}",
                                      self.project + "-" + service], "built-image-" + service).strip()
                assert image.startswith("sha256:")
                self.summary["images"][service] = {"built_image_id": image}
                self.save()
            self.summary["source"]["after_build"] = source_manifest()
            assert self.summary["source"]["before_build"] == self.summary["source"]["after_build"], "Docker COPY inputs changed during build"
            self.summary["gates"]["compose_build"] = True
            self.command(self.compose + ["up", "-d", "--wait", "--wait-timeout", "120"], "compose-up")
            for service in ["api", "collector", "analyzer"]:
                ident = self.command(self.compose + ["ps", "-q", service], "container-id-" + service).strip()
                assert ident
                image = self.command(["docker", "inspect", "--format", "{{.Image}}", ident], "container-image-" + service).strip()
                project_label = self.command(["docker", "inspect", "--format", '{{index .Config.Labels "com.docker.compose.project"}}', ident], "container-project-" + service).strip()
                service_label = self.command(["docker", "inspect", "--format", '{{index .Config.Labels "com.docker.compose.service"}}', ident], "container-service-" + service).strip()
                assert project_label == self.project and service_label == service
                assert image == self.summary["images"][service]["built_image_id"]
                self.summary["images"][service].update({"container_id": ident, "container_image_id": image})
                self.save()
            self.summary["gates"]["immutable_images_match_builds"] = True
            assert self.request("GET", "/api/health")["status"] == "ok"
            identity = self.request("GET", "/api/me")
            assert identity["weekly_limit"] == 1 and identity["weekly_used"] == 0
            self.summary["gates"]["local_auth_free_quota"] = True
            session = boto3.Session(profile_name=self.profile, region_name=self.region)
            account = session.client("sts").get_caller_identity()["Account"]
            credentials = session.get_credentials().get_frozen_credentials()
            auth = {"method": "access_keys", "aws_access_key_id": credentials.access_key,
                    "aws_secret_access_key": credentials.secret_key, "region_name": self.region}
            if credentials.token:
                auth["aws_session_token"] = credentials.token
            self.secret_values.extend([credentials.access_key, credentials.secret_key, credentials.token])
            connector = self.request("POST", "/api/connectors", expected=201, json={
                "name": "Compose read-only AWS acceptance", "provider": "aws", "auth": auth,
                "scopes": [account + "/" + self.region],
                "options": {"regions": [self.region], "inventories": INVENTORIES,
                            "max_pages": 20, "max_resources": 3000, "max_calls": 500,
                            "concurrency": 2, "region_concurrency": 1, "scope_concurrency": 1}})
            assert connector["input_mode"] == "live"
            self.summary["connector"] = {"id": connector["id"], "provider": "aws", "input_mode": "live",
                                         "profile": self.profile, "region": self.region, "inventories": INVENTORIES}
            scan = self.request("POST", "/api/scans", expected=201, json={"connector_id": connector["id"]})
            self.summary["manual_scan"] = self.wait_scan(scan["id"])
            self.summary["manual_report"] = self.report(scan["id"])
            self.summary["gates"]["live_aws_default_api_scan"] = True
            self.request("POST", "/api/scans", expected=429, json={"connector_id": connector["id"]})
            assert self.request("GET", "/api/me")["weekly_used"] == 1
            self.summary["gates"]["free_quota_enforced"] = True
            future = datetime.now(timezone.utc) + timedelta(days=7, minutes=1)
            schedule = self.request("POST", "/api/schedules", expected=201, json={
                "connector_id": connector["id"], "interval_hours": 168, "next_run_at": future.isoformat()})
            script = ("import json; from peaso.worker import Worker; "
                      f"rows=Worker('collector').schedule_tick(now={future.timestamp() + 1!r}); "
                      "print(json.dumps([{'id': row['id'], 'status': row['status']} for row in rows]))")
            triggered = json.loads(self.command(self.compose + ["exec", "-T", "collector", "python", "-c", script], "weekly-scheduler-clock"))
            assert len(triggered) == 1 and triggered[0]["id"] != scan["id"]
            self.summary["schedule"] = {"id": schedule["id"], "clock_mode": "production scheduler explicit next-week clock",
                                        "clock_at": future.isoformat(), "interval_hours": 168,
                                        "quota_records_modified": False, "paid_entitlement_modified": False}
            self.summary["scheduled_scan"] = self.wait_scan(triggered[0]["id"])
            self.summary["scheduled_report"] = self.report(triggered[0]["id"])
            assert self.summary["scheduled_report"]["snapshot_id"] != self.summary["manual_report"]["snapshot_id"]
            updated = self.request("GET", "/api/schedules")["items"][0]
            assert datetime.fromisoformat(updated["next_run_at"]) > future
            assert updated["last_error"] is None
            self.summary["gates"]["scheduled_weekly_rescan"] = True
            self.save()
            ui_env = dict(self.env, PEASO_UI_URL=self.origin, PEASO_COMPOSE_TOKEN=self.token,
                          PEASO_COMPOSE_EVIDENCE=str(self.directory), PEASO_COMPOSE_SCAN=triggered[0]["id"])
            self.command(playwright + ["test", "tests/compose-api.spec.ts", "--workers=1", "--reporter=line"],
                         "playwright-compose", cwd=ROOT / "frontend", env=ui_env)
            ui = json.loads((self.directory / "ui-sections.json").read_text())
            assert ui["automatically_due_schedule_quota_blocked"] is True
            self.summary["gates"]["automatically_due_schedule_quota_blocked"] = True
            self.summary["gates"]["ui_sections_screenshots"] = True
        finally:
            try:
                if self.summary.get("scan_error"):
                    self.capture_failure_diagnostics()
            finally:
                self.cleanup()
                self.client.close()
                self.save()

    def capture_failure_diagnostics(self):
        """Persist bounded, sanitized owned-project evidence before teardown."""
        receipt = {"owned_logs": False, "container_state": {}, "errors": []}
        try:
            self.command(self.compose + ["logs", "--no-color", "--tail", "80", "api", "collector", "analyzer"],
                         "failure-owned-project-logs")
            receipt["owned_logs"] = True
        except Exception as exc:
            receipt["errors"].append({"step": "owned_logs", "type": type(exc).__name__})
        for service in ("api", "collector", "analyzer"):
            ident = self.summary.get("images", {}).get(service, {}).get("container_id")
            if not ident:
                continue
            try:
                state = self.command(["docker", "inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", ident],
                                     "failure-container-state-" + service).strip().split()
                if len(state) != 2 or state[1].lower() not in {"true", "false"}:
                    raise ValueError("Malformed Docker state fields")
                receipt["container_state"][service] = {"exit_code": int(state[0]),
                                                        "oom_killed": state[1].lower() == "true"}
            except Exception as exc:
                receipt["errors"].append({"step": "container_state_" + service, "type": type(exc).__name__})
        self.summary["failure_diagnostics"] = receipt
        self.save()

    def cleanup(self):
        # Only the unique project created by this run, on the same Docker daemon.
        assert self.command(["docker", "info", "--format", "{{.ID}}"], "cleanup-docker-identity").strip() == self.summary["docker_id"]
        containers = self.command(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + self.project], "cleanup-owned-containers").split()
        for ident in containers:
            value = json.loads(subprocess.check_output(["docker", "inspect", ident], text=True))[0]
            labels = value["Config"]["Labels"]
            assert labels["com.docker.compose.project"] == self.project
            assert labels["com.docker.compose.service"] in {"api", "collector", "analyzer"}
        self.command(self.compose + ["down", "-v", "--remove-orphans"], "compose-down-volumes")
        for kind, argv in {"containers": ["docker", "ps", "-aq"], "volumes": ["docker", "volume", "ls", "-q"],
                           "networks": ["docker", "network", "ls", "-q"]}.items():
            assert not self.command(argv + ["--filter", "label=com.docker.compose.project=" + self.project], "verify-no-" + kind).strip()
        self.summary["cleanup"] = "verified_no_owned_containers_volumes_networks"
        self.summary["finished_at"] = datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--profile", default=deployment.value("test_aws_profile"))
    parser.add_argument("--region", default="eu-west-1")
    args = parser.parse_args()
    run = Acceptance(args.evidence_dir, args.profile, args.region)
    try:
        run.run()
    except Exception as exc:
        run.summary["outcome"] = "failed"
        run.summary["sanitized_error"] = {"type": type(exc).__name__, "detail": run.sanitized(str(exc)) if isinstance(exc, (AssertionError, RuntimeError, TimeoutError)) else "See sanitized command logs"}
        run.summary["sanitized_error"]["source_frames"] = [Path(frame.filename).name + ":" + str(frame.lineno) for frame in traceback.extract_tb(exc.__traceback__)]
        run.save()
        print(json.dumps({"outcome": "failed", "error": run.summary["sanitized_error"], "cleanup": run.summary["cleanup"]}))
        return 1
    run.summary["outcome"] = "succeeded"
    run.save()
    print(json.dumps({"outcome": "succeeded", "gates": run.summary["gates"], "cleanup": run.summary["cleanup"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
