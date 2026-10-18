"""Defined offline benchmark: 10k Deployments, four native template predicates."""
import argparse
import json
import platform
import time
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot


def benchmark(count=10000):
    items = []
    for number in range(count):
        hardened = number % 2 == 0
        items.append({"metadata": {"name": f"deployment-{number}", "namespace": "apps"}, "spec": {"template": {"spec": {
            "hostNetwork": not hardened, "securityContext": {"runAsNonRoot": hardened},
            "containers": [{"name": "app", "securityContext": {"privileged": not hardened}, "ports": [{"containerPort": 443, "hostPort": 0 if hardened else 443}]}]}}}})
    snapshot = make_snapshot("k8s", ["synthetic-cluster/apps"], [{"type": "deployment", "scope": "synthetic-cluster/apps", "status": "collected", "items": items}], created_at="2026-10-10T00:00:00+00:00", metadata={"synthetic": True})
    checks = ["k8s.deployment." + name for name in ("no_privileged", "non_root", "no_host_network", "no_host_ports")]
    started = time.perf_counter()
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=checks)
    elapsed = time.perf_counter() - started
    assert report["stats"]["by_status"] == {"PASS": 4 * ((count + 1) // 2), "FAIL": 4 * (count // 2)}
    return {"python": platform.python_version(), "platform": platform.platform(), "resources": count, "checks": checks,
        "findings": report["stats"]["finding_count"], "seconds": round(elapsed, 6), "resources_per_second": round(count / elapsed),
        "cloud_calls": 0, "limitations": "Four applicable Deployment template checks in one scope; excludes live collection, graph building and rendering."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--resources", type=int, default=10000)
    print(json.dumps(benchmark(parser.parse_args().resources), indent=2))
