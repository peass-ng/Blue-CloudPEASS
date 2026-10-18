"""Defined offline benchmark: N EC2 instances, native IMDSv2 evaluation, one scope."""
import argparse
import json
import platform
import time
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot


def benchmark(count=30000):
    snapshot = make_snapshot("aws", ["111111111111/us-east-1"], [{"type": "instance", "scope": "111111111111/us-east-1", "service": "ec2", "status": "collected",
        "items": [{"InstanceId": f"i-{number:016x}", "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required" if number % 2 == 0 else "optional"}} for number in range(count)]}],
        created_at="2026-10-10T00:00:00+00:00", metadata={"synthetic": True})
    started = time.perf_counter()
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.ec2.imdsv2"])
    elapsed = time.perf_counter() - started
    assert report["stats"]["resource_count"] == count
    assert report["stats"]["by_status"] == {"PASS": (count + 1) // 2, "FAIL": count // 2}
    return {"python": platform.python_version(), "platform": platform.platform(), "resources": count,
        "checks": ["aws.ec2.imdsv2"], "categories": ["hardening"], "seconds": round(elapsed, 6),
        "resources_per_second": round(count / elapsed), "findings": report["stats"]["finding_count"], "cloud_calls": 0,
        "limitations": "One applicable native predicate and scope; this does not measure live collection, all rules, graphs, or report rendering."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--resources", type=int, default=30000)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.resources), indent=2))
