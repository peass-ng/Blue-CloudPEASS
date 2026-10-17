"""Run the exact default CLI gate in one frozen build with phase-only instrumentation."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


INSTRUMENTATION = '''
import atexit,json,os,time
from datetime import datetime,timezone
from pathlib import Path
import peaso.engine as engine
import peaso.cli as cli
import boto3.session

root=Path(os.environ['PEASO_QA_TIMING_DIR'])
timings={'collection_seconds':0.0,'evaluation_seconds':0.0,'serialization_and_write_seconds':0.0}
def timed(name,function):
    def wrapped(*args,**kwargs):
        start=time.perf_counter()
        try:return function(*args,**kwargs)
        finally:timings[name]+=time.perf_counter()-start
    return wrapped
engine.collect_snapshot=timed('collection_seconds',engine.collect_snapshot)
engine.evaluate_snapshot=timed('evaluation_seconds',engine.evaluate_snapshot)
cli._write=timed('serialization_and_write_seconds',cli._write)
audit=[]
original=boto3.session.Session.client
def client(session,service_name,*args,**kwargs):
    result=original(session,service_name,*args,**kwargs)
    if service_name=='iam':
        def before(**kwargs):
            caller=original(session,'sts',region_name='us-east-1').get_caller_identity()
            if caller['Account']!='947247140022':raise RuntimeError('Unapproved credential report write account')
            audit.append({'account':caller['Account'],'principal':caller['Arn'],'operation':'iam:GenerateCredentialReport',
                'purpose':'User directive6 metadata evidence only','verification':'caller_verified_before_write',
                'at':datetime.now(timezone.utc).isoformat(),'delete_operation':'No IAM report deletion API; authorized account metadata generation'})
            save()
        result.meta.events.register('before-call.iam.GenerateCredentialReport',before)
    return result
boto3.session.Session.client=client
def private(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as stream:json.dump(value,stream,indent=2)
def save():
    private(root/'phase-timings.json',timings)
    private(root/'account-metadata-write-audit.json',audit)
atexit.register(save)
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    root = Path(args.directory).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    source = Path(__file__).resolve().parents[2]
    if (source / "peaso" / "privesc").exists() or "_run_privesc" in (source / "peaso" / "engine.py").read_text():
        raise RuntimeError("Default live QA requires the defensive-only exported build")
    build = root / "runtime-build"
    packages = ("peaso", "bluepeass", "scripts", "risk_rules")
    def digest(base):
        result = hashlib.sha256()
        for package in packages:
            for path in sorted((base / package).rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts and path.suffix in {".py", ".json", ".yaml", ".yml"}:
                    result.update(str(path.relative_to(base)).encode())
                    result.update(path.read_bytes())
        return result.hexdigest()
    for _ in range(3):
        before = digest(source)
        for package in packages:
            shutil.copytree(source / package, build / package, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        if before == digest(source) == digest(build):
            break
    else:
        raise RuntimeError("Source changed during build freeze")
    hooks = root / "instrumentation"
    hooks.mkdir(exist_ok=True, mode=0o700)
    (hooks / "sitecustomize.py").write_text(INSTRUMENTATION)
    os.chmod(hooks / "sitecustomize.py", 0o600)
    environment = {**os.environ, "PATH": str(source / ".venv" / "bin") + os.pathsep + os.environ["PATH"],
        "PYTHONPATH": str(hooks) + os.pathsep + str(build), "PEASO_QA_TIMING_DIR": str(root)}
    snapshot_path, report_path = root / "aws-snap.json", root / "aws-report.json"
    command = ["python3", "-m", "peaso", "scan", "--provider", "aws", "--profile", "naxusai-admin", "--snapshot-output", str(snapshot_path), "-o", str(report_path)]
    started = time.perf_counter()
    result = subprocess.run(command, cwd=build, env=environment)
    wall = time.perf_counter() - started
    if result.returncode:
        raise RuntimeError("Default CLI failed with exit " + str(result.returncode))
    from peaso.engine import hydrate_frameworks  # per-check fields live in check_meta (schema 1.1)
    snapshot, report = json.loads(snapshot_path.read_text()), hydrate_frameworks(json.loads(report_path.read_text()))
    codes = Counter(c.get("error", {}).get("code", "") for c in snapshot["collections"] if c.get("error"))
    failures = {code: count for code, count in codes.items() if any(term in code for term in ("call_limit", "page_limit", "resource_limit", "inventory_not_requested"))}
    summary = {"command": command, "build_sha256": before, "wall_seconds": round(wall, 4),
        "timings": json.loads((root / "phase-timings.json").read_text()), "provider": "aws",
        "scopes": snapshot["scopes"], "metadata": {k: snapshot.get("metadata", {}).get(k) for k in ("regions", "limits", "explicit_limits", "omitted_inventories", "collection_plan")},
        "resources": len(report["resources"]), "checks": report["stats"]["check_count"], "findings": len(report["findings"]),
        "categories": dict(Counter(f["category"] for f in report["findings"])), "statuses": dict(Counter(c["status"] for c in snapshot["collections"])),
        "reason_counts": dict(codes), "default_cap_failures": failures,
        "network": {"nodes": len(report["graphs"]["network"]["nodes"]), "edges": len(report["graphs"]["network"]["edges"])},
        "coverage_complete": report["stats"]["coverage_complete"], "snapshot_mode": oct(snapshot_path.stat().st_mode & 0o777), "report_mode": oct(report_path.stat().st_mode & 0o777)}
    output = root / "summary.json"
    output.write_text(json.dumps(summary, indent=2))
    os.chmod(output, 0o600)
    print(json.dumps(summary, indent=2))
    if failures or summary["network"]["nodes"] == 0:
        raise AssertionError("Default full inventory release gate failed")


if __name__ == "__main__":
    main()
