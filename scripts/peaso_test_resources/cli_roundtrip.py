"""Fresh real CLI scan followed by immutable offline JSON/Markdown verification."""
import argparse
from collections import Counter
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", choices=("aws", "azure", "gcp"))
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    root = Path(args.directory).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Freeze one build so concurrent owner edits cannot mix evaluator versions
    # between the fresh CLI scan and its offline reevaluation.
    source = Path(__file__).resolve().parents[2]
    build = root / "runtime-build"
    packages = tuple(package for package in ("peaso", "bluepeass", "scripts", "risk_rules") if (source / package).is_dir())
    def code_digest(base):
        digest = hashlib.sha256()
        for package in packages:
            for path in sorted((base / package).rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts and path.suffix in (".py", ".json", ".yaml", ".yml"):
                    digest.update(str(path.relative_to(base)).encode())
                    digest.update(path.read_bytes())
        return digest.hexdigest()
    for attempt in range(3):
        before = code_digest(source)
        for package in packages:
            shutil.copytree(source / package, build / package, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        if before == code_digest(source) == code_digest(build):
            break
    else:
        raise RuntimeError("Source changed repeatedly while freezing CLI build")
    cloud_environment = {**os.environ, "PYTHONPATH": str(build)}
    auth, scopes = {
        "aws": ({"method": "profile", "profile": "naxusai-admin"}, ["947247140022"]),
        "azure": ({"method": "az-cli", "tenant_id": "fdd066e1-ee37-49bc-b08f-d0e152119b04"}, ["cfbcdcf4-cb4f-4e4e-9f3e-a6b3b3abadfc"]),
        "gcp": ({"method": "gcloud", "account": "carlos@hacktricks-training.com"}, ["gcp-labs-ly3gvnn7"]),
    }[args.provider]
    options = {"collect_all": True, "max_calls": 500, "max_resources": 20000, "max_pages": 3, "retries": 0}
    if args.provider == "aws":
        options.update(regions=["us-east-1"], retry_attempts=1, read_timeout=10)
    request = root / "request.json"
    request.write_text(json.dumps({"connector": {"provider": args.provider, "name": "peaso-test-cli", "auth": auth, "scopes": scopes, "options": options}}))
    os.chmod(request, 0o600)
    report_path, snapshot_path, offline_path, md_path = [root / name for name in ("fresh-report.json", "snapshot.json", "offline-report.json", "report.md")]
    cli = [sys.executable, "-m", "peaso.cli"]
    start = time.perf_counter()
    subprocess.run(cli + ["scan", "--request", str(request), "--snapshot-output", str(snapshot_path), "--output", str(report_path)], env=cloud_environment, cwd=build, check=True, timeout=600)
    fresh_seconds = time.perf_counter() - start
    # An empty credential configuration proves these commands do not require login.
    environment = {**cloud_environment, "AWS_CONFIG_FILE": str(root / "absent-aws-config"), "AWS_SHARED_CREDENTIALS_FILE": str(root / "absent-aws-credentials"),
                   "CLOUDSDK_CONFIG": str(root / "absent-gcloud-config"), "AZURE_CONFIG_DIR": str(root / "absent-azure-config"), "KUBECONFIG": str(root / "absent-kubeconfig")}
    subprocess.run(cli + ["evaluate", str(snapshot_path), "--output", str(offline_path)], env=environment, cwd=build, check=True, timeout=180)
    subprocess.run(cli + ["report", str(offline_path), "--format", "markdown", "--output", str(md_path)], env=environment, cwd=build, check=True, timeout=180)
    report = json.loads(report_path.read_text())
    embedded = report.pop("snapshot")
    snapshot = json.loads(snapshot_path.read_text())
    offline = json.loads(offline_path.read_text())
    assert embedded == snapshot
    assert report == offline
    assert snapshot["snapshot_id"] in md_path.read_text()
    fixture_ids = [v for k, v in os.environ.items() if k.startswith("PEASO_TEST_") and k != "PEASO_TEST_EXTERNAL_ID"]
    native = json.dumps([c["items"] for c in snapshot["collections"]])
    summary = {"provider": args.provider, "build_sha256": before, "fresh_scan_seconds": round(fresh_seconds, 4), "snapshot_id": snapshot["snapshot_id"],
               "resources": len(report["resources"]), "findings": len(report["findings"]), "checks": report["stats"]["check_count"],
               "json_bytes": report_path.stat().st_size, "markdown_bytes": md_path.stat().st_size, "offline_exact": True,
               "fixture_presence": {value: value in native for value in fixture_ids},
               "categories": dict(Counter(f["category"] for f in report["findings"])),
               "collection_statuses": dict(Counter(c["status"] for c in snapshot["collections"])),
               "graphs": {k: {"nodes": len(v["nodes"]), "edges": len(v["edges"])} for k, v in report["graphs"].items()},
               "coverage_complete": report["stats"]["coverage_complete"]}
    path = root / "summary.json"
    path.write_text(json.dumps(summary, indent=2))
    os.chmod(path, 0o600)
    print(json.dumps(summary, indent=2))
    assert report["resources"] and report["findings"], "A real default scan must generate resources and findings"
    assert all(value in native for value in fixture_ids), "Actual CLI missed an existing disposable fixture"


if __name__ == "__main__":
    main()
