"""Collector-only full AWS evidence; evaluator/analysis imports are forbidden."""
from peaso import deployment
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.abc
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)


def child(root):
    class DenyEvaluators(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.startswith(("peaso.engine", "peaso.privesc", "peaso.analysis", "peaso.checks")):
                raise ImportError("Collector-only QA forbids evaluator/analysis modules")
    sys.meta_path.insert(0, DenyEvaluators())
    import boto3.session
    audit = []
    original = boto3.session.Session.client
    def guarded_client(session, service_name, *args, **kwargs):
        result = original(session, service_name, *args, **kwargs)
        if service_name == "iam":
            def before(**kwargs):
                identity = original(session, "sts", region_name="us-east-1").get_caller_identity()
                if identity["Account"] != deployment.value("test_aws_account_id"):
                    raise RuntimeError("Unapproved account for credential-report metadata generation")
                audit.append({"account": identity["Account"], "principal": identity["Arn"], "operation": "iam:GenerateCredentialReport",
                    "purpose": "User directive6 evidence-only account metadata", "verification": "same_session_caller_verified_before_write",
                    "at": datetime.now(timezone.utc).isoformat(), "delete_operation": "No IAM report deletion API; authorized metadata operation"})
                private(root / "account-metadata-write-audit.json", audit)
            result.meta.events.register("before-call.iam.GenerateCredentialReport", before)
        return result
    boto3.session.Session.client = guarded_client
    from peaso.collectors.aws import collect, AWS_TYPES
    from peaso.snapshot import resources, canonical
    import peaso
    if not Path(peaso.__file__).resolve().is_relative_to(root / "collector-build"):
        raise RuntimeError("Collector import escaped frozen allowed sources")
    own = boto3.session.Session(profile_name=deployment.value("test_aws_profile")).client("sts", region_name="us-east-1").get_caller_identity()
    assert own["Account"] == deployment.value("test_aws_account_id")
    started = time.perf_counter()
    snapshot = collect({"provider": "aws", "auth": {"method": "profile", "profile": deployment.value("test_aws_profile")}, "options": {}})
    seconds = time.perf_counter() - started
    inventory = resources(snapshot)
    serial_start = time.perf_counter()
    value = canonical(snapshot)
    fd = os.open(root / "aws-default-collector-snapshot.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(value)
    serialization = time.perf_counter() - serial_start
    codes = Counter(c.get("error", {}).get("code", "") for c in snapshot["collections"] if c.get("error"))
    forbidden_codes = {k: v for k, v in codes.items() if any(x in k for x in ("call_limit", "page_limit", "resource_limit", "scope_limit", "inventory_not_requested"))}
    network = {kind: sum(r["type"] == kind for r in inventory) for kind in (
        "vpc", "subnet", "security_group", "instance", "network_interface", "route_table", "load_balancer", "vpc_peering", "nat_gateway", "internet_gateway")}
    summary = {"mode": "collector_only", "provider": "aws", "account": own["Account"], "collection_seconds": round(seconds, 4),
        "serialization_and_write_seconds": round(serialization, 4), "evaluation": "not executed", "scopes": snapshot["scopes"],
        "enabled_regions": snapshot.get("metadata", {}).get("regions"), "api_calls": snapshot.get("metadata", {}).get("calls"),
        "collector_metadata": snapshot.get("metadata", {}), "supported_type_count": len(AWS_TYPES),
        "collection_count": len(snapshot["collections"]), "observed_type_count": len({c["type"] for c in snapshot["collections"]}),
        "resource_count": len(inventory), "status_counts": dict(Counter(c["status"] for c in snapshot["collections"])),
        "reason_counts": dict(codes), "default_cap_failures": forbidden_codes, "network_inventory": network,
        "network_resource_count": sum(network.values()), "snapshot_bytes": len(value.encode()),
        "engine_imported": "peaso.engine" in sys.modules, "analysis_imported": "peaso.analysis" in sys.modules,
        "privilege_chain_modules_imported": any(k.startswith("peaso.privesc") for k in sys.modules),
        "metadata_generation_calls": len(audit)}
    # Metadata is configuration evidence, not credentials; full inventory stays private.
    private(root / "summary.json", summary)
    private(root / "account-metadata-write-audit.json", audit)
    print(json.dumps({k: v for k, v in summary.items() if k != "collector_metadata"}, indent=2), flush=True)
    assert not summary["engine_imported"] and not summary["analysis_imported"] and not summary["privilege_chain_modules_imported"]
    if forbidden_codes:
        raise AssertionError("Default collector has implicit caps or omitted inventories")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--child", action="store_true")
    args = parser.parse_args()
    root = Path(args.directory).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.child:
        child(root)
        return
    source = Path(__file__).resolve().parents[2]
    build = root / "collector-build"
    paths = [source / "peaso/__init__.py", source / "peaso/snapshot.py"]
    paths += [p for folder in ("peaso/collectors", "peaso/auth") for p in (source / folder).rglob("*.py") if "__pycache__" not in p.parts]
    manifest = []
    for path in sorted(paths):
        relative = path.relative_to(source)
        target = build / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        content = path.read_bytes()
        target.write_bytes(content)
        manifest.append({"path": str(relative), "sha256": hashlib.sha256(content).hexdigest()})
    private(root / "collector-source-manifest.json", manifest)
    environment = {**os.environ, "PYTHONPATH": str(build)}
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--directory", str(root), "--child"], cwd=build, env=environment)
    after = [{"path": row["path"], "sha256": hashlib.sha256((source / row["path"]).read_bytes()).hexdigest()} for row in manifest]
    changed = [row["path"] for row, final in zip(manifest, after) if row["sha256"] != final["sha256"]]
    private(root / "source-after-read.json", {"files": after, "primary_files_changed_during_measurement": changed})
    if (root / "summary.json").exists():
        summary = json.loads((root / "summary.json").read_text())
        summary.update(primary_files_changed_during_measurement=changed, measurement_source_hashes_immutable=True,
                       qa_identity_verification_calls=1 + summary["metadata_generation_calls"])
        private(root / "summary.json", summary)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
