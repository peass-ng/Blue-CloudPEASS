"""Benchmark complete current evaluation of a private real collected snapshot.

Output contains only provider/count/timing/digest metadata; native facts stay private.
"""
import argparse
import copy
import json
import platform
import time
from peaso.engine import evaluate_snapshot
from peaso.snapshot import digest


def benchmark(path):
    with open(path, encoding="utf-8") as stream:
        snapshot = json.load(stream)
    before = digest(snapshot)
    times, reports = [], []
    for _ in range(2):
        started = time.perf_counter()
        report = evaluate_snapshot(snapshot)
        times.append(round(time.perf_counter() - started, 6))
        reports.append(report)
    assert digest(snapshot) == before and reports[0] == reports[1]
    started = time.perf_counter()
    serialized = json.dumps(reports[1], sort_keys=True, separators=(",", ":"))
    serialization = round(time.perf_counter() - started, 6)
    stats = reports[1]["stats"]
    return {"provider": snapshot["provider"], "python": platform.python_version(), "platform": platform.platform(),
        "categories": stats["categories"], "check_count": stats["check_count"], "resources": stats["resource_count"],
        "findings": stats["finding_count"], "by_status": stats["by_status"], "cold_seconds": times[0], "warm_seconds": times[1],
        "serialization_seconds": serialization, "report_json_bytes": len(serialized.encode()), "cloud_calls": 0,
        "input_unchanged": True, "cold_warm_report_equal": True,
        "limitations": "Current full native evaluation of saved real inventory; excludes cloud collection and Markdown rendering. Expanded catalog may differ from earlier QA run."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot")
    print(json.dumps(benchmark(parser.parse_args().snapshot), indent=2))
