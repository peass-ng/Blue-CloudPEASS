"""Announce ledger-owned role then wait for explicit release within one hour."""
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    directory = Path(os.environ["PEASO_QA_PRIVATE_DIR"])
    metadata = {"role_arn": os.environ["PEASO_TEST_ROLE_ARN"], "external_id": os.environ["PEASO_TEST_EXTERNAL_ID"]}
    path = directory / "hosted-aws-connector.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(metadata, output)
    body = ("Temporary read-only SecurityAudit role created: " + metadata["role_arn"] + ". Exact collector trust with ExternalId " + metadata["external_id"] +
            ". Private ledger audit-role-ledger.json and watchdog finally teardown active; release by creating " + str(directory / "release-audit-role") + "; deadline one hour.")
    for recipient in ("dispatch:ctx_4e2ff508fd91", "run:run_405fd85cc6f5"):
        subprocess.run(["orca", "orchestration", "send", "--from", "term_4afba68c-78df-4aaf-a8bf-0b83feb8ded8", "--to", recipient,
                        "--type", "status", "--subject", "Disposable AWS hosted audit role ready", "--body", body, "--json"], check=True, capture_output=True, text=True)
    deadline = time.monotonic() + 3500
    while not (directory / "release-audit-role").exists() and time.monotonic() < deadline:
        time.sleep(2)
    path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
