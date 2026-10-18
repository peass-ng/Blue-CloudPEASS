"""Finally cleanup for the uniquely named, ledger-owned QA Compose project."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def main():
    directory = Path(os.environ["PEASO_QA_PRIVATE_DIR"])
    ledger = directory / "compose-ledger.json"
    data = json.loads(ledger.read_text())
    row = data["resources"][0]
    project = row["project"]
    if data["task_id"] != "task_02a312b5ac1f" or project != "peaso-test-qa-02a312b5":
        raise RuntimeError("Wrong project ownership")
    def save():
        ledger.write_text(json.dumps(data, indent=2) + "\n")
        os.chmod(ledger, 0o600)
    def identity():
        actual = subprocess.check_output(["docker", "info", "--format", "{{.ID}}"], text=True).strip()
        if row["docker_id"] != actual:
            raise RuntimeError("Docker daemon identity mismatch")
    def stop(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        deadline = time.monotonic() + 3500
        while not (directory / "release-compose").exists() and time.monotonic() < deadline:
            time.sleep(2)
    finally:
        identity()
        containers = subprocess.check_output(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project], text=True).split()
        for ident in containers:
            item = json.loads(subprocess.check_output(["docker", "inspect", ident], text=True))[0]
            labels = item["Config"]["Labels"]
            if labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.service") not in {"api", "collector", "analyzer"}:
                raise RuntimeError("Unowned project container")
        row["container_ids"] = containers
        save()
        subprocess.run(["docker", "compose", "-p", project, "down", "--volumes", "--remove-orphans"], check=True, capture_output=True, text=True)
        remaining = subprocess.check_output(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project], text=True).strip()
        volumes = subprocess.check_output(["docker", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project=" + project], text=True).strip()
        networks = subprocess.check_output(["docker", "network", "ls", "-q", "--filter", "label=com.docker.compose.project=" + project], text=True).strip()
        if remaining or volumes or networks:
            row["verification"] = "resources_remain"
            save()
            raise RuntimeError("Compose resources remain")
        row.update(creation_status="deleted", verification="containers_volumes_network_not_found")
        save()


if __name__ == "__main__":
    main()
