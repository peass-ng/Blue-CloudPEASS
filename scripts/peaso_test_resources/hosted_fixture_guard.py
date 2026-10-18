"""Run hosted tests, retain a bounded UI review window, then clean exact test data.

Run inside assume wiki --exec. This guard never deletes infrastructure.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--ui-hold-seconds", type=int, default=120)
    args = parser.parse_args()
    if not 0 <= args.ui_hold_seconds <= 600:
        parser.error("UI review window must be 0..600 seconds")
    root = Path(args.directory).resolve()
    scripts = Path(__file__).parent.resolve()
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    users = json.loads((root / "hosted-test-identities.json").read_text())["users"]
    try:
        result = subprocess.run([sys.executable, str(scripts / "session.py"), "azure", "--ledger", str(root / "azure-resource-ledger.json"), "--",
            sys.executable, str(scripts / "hosted_acceptance.py"), "--directory", str(root)], check=True, timeout=1500,
            env={**os.environ, "PYTHONPATH": str(scripts.parents[1])})
        for recipient in ("dispatch:ctx_ad1f69544b10", "run:run_405fd85cc6f5"):
            subprocess.run(["orca", "orchestration", "send", "--from", "term_4afba68c-78df-4aaf-a8bf-0b83feb8ded8", "--to", recipient,
                "--type", "status", "--subject", "Hosted QA cloud gates passed; bounded UI inspection window",
                "--body", "Hosted summary saved privately at " + str(root / "hosted-summary.json") + "; real AWS and large Azure scans completed, free quota/isolation/cookie/download gates passed. Owned tenant data remains for " + str(args.ui_hold_seconds) + " seconds of read-only UI inspection, then exact data cleanup runs automatically. No public registration or paid subscription claim.", "--json"], check=True, capture_output=True, text=True)
        deadline = time.monotonic() + args.ui_hold_seconds
        while time.monotonic() < deadline and not (root / "release-hosted-data").exists():
            time.sleep(2)
    finally:
        ledger = root / "hosted-data-ledger.json"
        if ledger.exists():
            data = json.loads(ledger.read_text())
            for row in data["resources"]:
                user = next(u for u in users if u["sub"] == row["tenant"])
                with httpx.Client(base_url="https://cspm.hacktricks.wiki", timeout=30,
                    headers={"Authorization": "Bearer " + user["id_token"], "Origin": "https://cspm.hacktricks.wiki"}) as client:
                    for item in row["api_objects"]:
                        if item["kind"] != "scans" or not item.get("id"):
                            continue
                        response = client.get("/api/scans/" + item["id"])
                        if response.status_code == 404:
                            continue
                        if response.status_code != 200:
                            raise RuntimeError("Owned scan unavailable for cleanup")
                        if response.json()["status"] not in {"completed", "failed", "cancelled", "timed_out"}:
                            actual = client.get("/api/me")
                            if actual.status_code != 200 or actual.json()["tenant_id"] != user["sub"]:
                                raise RuntimeError("Owned subject differs before cancellation")
                            cancelled = client.post("/api/scans/" + item["id"] + "/cancel")
                            if cancelled.status_code != 200 or cancelled.json()["status"] != "cancelled":
                                raise RuntimeError("Owned active scan cancellation failed")
            # Allow fenced workers to observe cancellation before object-key sweep.
            time.sleep(5)
            subprocess.run([sys.executable, str(scripts / "hosted_data_cleanup.py"), "--directory", str(root)], check=True, timeout=300)


if __name__ == "__main__":
    main()
