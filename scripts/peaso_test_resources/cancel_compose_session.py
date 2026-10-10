"""Verify queued cancellation/schedules in a separate fresh free Compose fixture."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import signal
import time
import uuid

import httpx
from peaso.snapshot import make_snapshot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    root = Path(args.directory).resolve()
    project = "peaso-test-cancel-" + uuid.uuid4().hex[:12]
    owner = uuid.uuid4().hex
    ledger = root / "cancel-compose-ledger.json"
    row = {"provider": "docker", "account": None, "project": project, "subscription": None, "region": "local", "id": project, "name": project,
        "creation_status": "planned", "delete_operation": "docker compose exact project down --volumes", "verification": "pending", "owner_token": owner,
        "docker_id": subprocess.check_output(["docker", "info", "--format", "{{.ID}}"], text=True).strip()}
    data = {"schema_version": 1, "task_id": "task_02a312b5ac1f", "resources": [row]}
    def save():
        ledger.write_text(json.dumps(data, indent=2) + "\n")
        os.chmod(ledger, 0o600)
    def identity():
        if subprocess.check_output(["docker", "info", "--format", "{{.ID}}"], text=True).strip() != row["docker_id"]:
            raise RuntimeError("Wrong Docker daemon")
    compose_file = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    override = root / "cancel-compose-ownership.json"
    override.write_text(json.dumps({"services": {"api": {"labels": {"peaso-test-owner": owner}}}}))
    command = ["docker", "compose", "-f", str(compose_file), "-f", str(override), "-p", project]
    env = {**os.environ, "PEASO_PORT": "18002", "PEASO_ALLOWED_ORIGINS": "http://127.0.0.1:18002"}
    save()  # Before first Docker creation.
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        identity()
        if subprocess.check_output(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project], text=True).strip():
            raise RuntimeError("Project already exists")
        subprocess.run(command + ["up", "--build", "-d", "api"], env=env, check=True, capture_output=True, text=True, timeout=300)
        row["creation_status"] = "created"
        save()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                if httpx.get("http://127.0.0.1:18002/api/health", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("Isolated API not healthy")
        token = subprocess.check_output(command + ["exec", "-T", "api", "python", "-c", 'from pathlib import Path; print(Path("/var/lib/peaso/identity/local.token").read_text())'], env=env, text=True).strip()
        snapshot = make_snapshot("aws", ["peaso-test-scope"], [{"type": "bucket", "scope": "peaso-test-scope", "service": "s3", "status": "empty", "items": []}])
        with httpx.Client(base_url="http://127.0.0.1:18002", headers={"Authorization": "Bearer " + token, "Origin": "http://127.0.0.1:18002"}, timeout=30) as client:
            me = client.get("/api/me").json()
            assert me["plan"] == "free" and me["weekly_limit"] == 1 and me["weekly_used"] == 0
            connector = client.post("/api/connectors", json={"name": "peaso-test-queued-cancel", "provider": "aws", "scopes": snapshot["scopes"], "options": {"snapshot": snapshot}})
            assert connector.status_code == 201
            ident = connector.json()["id"]
            queued = client.post("/api/scans", json={"connector_id": ident})
            assert queued.status_code == 201 and queued.json()["status"] == "queued"
            scan = queued.json()["id"]
            cancelled = client.post("/api/scans/" + scan + "/cancel")
            assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
            assert client.get("/api/scans/" + scan + "/report").status_code == 409
            assert client.post("/api/scans", json={"connector_id": ident}).status_code == 429
            schedule = client.post("/api/schedules", json={"connector_id": ident, "interval_hours": 168})
            assert schedule.status_code == 201
            sid = schedule.json()["id"]
            assert client.patch("/api/schedules/" + sid, json={"enabled": False}).status_code == 200
            assert client.delete("/api/schedules/" + sid).status_code == 204
            assert client.delete("/api/connectors/" + ident).status_code == 204
            row["api_objects"] = {"connector": ident, "scan": scan, "schedule": sid}
            save()
            summary = {"queued_cancel_status": "cancelled", "incomplete_report_http": 409, "second_free_scan_http": 429,
                "schedule_create_pause_delete": True, "collector_started": False, "input_mode": "offline_snapshot", "fake_paid_entitlement": False}
            path = root / "cancel-compose-summary.json"
            path.write_text(json.dumps(summary, indent=2))
            os.chmod(path, 0o600)
            print(json.dumps(summary))
    finally:
        identity()
        containers = subprocess.check_output(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project], text=True).split()
        for cid in containers:
            actual = json.loads(subprocess.check_output(["docker", "inspect", cid], text=True))[0]
            if actual["Config"]["Labels"].get("peaso-test-owner") != owner:
                raise RuntimeError("Wrong container ownership")
        subprocess.run(command + ["down", "--volumes"], env=env, check=True, capture_output=True, text=True)
        for kind, args in [("containers", ["docker", "ps", "-aq"]), ("volumes", ["docker", "volume", "ls", "-q"]), ("networks", ["docker", "network", "ls", "-q"])]:
            if subprocess.check_output(args + ["--filter", "label=com.docker.compose.project=" + project], text=True).strip():
                raise RuntimeError("Owned " + kind + " remain")
        row.update(creation_status="deleted", verification="containers_volumes_network_not_found")
        save()
        override.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
