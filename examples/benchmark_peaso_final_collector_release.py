"""Measure releasing finished checkpoint facts before final snapshot redaction.

Run: python examples/benchmark_peaso_final_collector_release.py [items]
Only synthetic, inert native facts are generated. Modes run in separate processes.
"""
from __future__ import annotations

import copy
import gc
import json
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from peaso.auth import redact
from peaso.snapshot import make_snapshot, seal


def run(mode: str, count: int) -> dict:
    scope = "123456789012/us-east-1"
    tracemalloc.start()
    started = time.perf_counter()
    snapshot = make_snapshot("aws", [scope], [{"type": "cloudwatch_metric", "scope": scope,
        "status": "collected", "items": [{"id": f"metric-{index}", "Dimensions": [
            {"Name": "InstanceId", "Value": f"i-{index:016x}"}],
            "Namespace": "AWS/EC2", "MetricName": "CPUUtilization"}
            for index in range(count)]}], created_at="2026-10-23T00:00:00+00:00")
    checkpoint_facts = copy.deepcopy(snapshot["collections"])
    if mode == "released":
        del checkpoint_facts
        gc.collect()
    result = seal(redact(snapshot, ("inert-fixture-credential",)))
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"mode": mode, "items": count, "snapshot_id": result["snapshot_id"],
            "peak_bytes": peak, "seconds": round(elapsed, 3)}


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    if len(sys.argv) > 2:
        print(json.dumps(run(sys.argv[2], count)))
    else:
        rows = [json.loads(subprocess.check_output(
            [sys.executable, str(Path(__file__).resolve()), str(count), mode], text=True))
            for mode in ("retained", "released")]
        if rows[0]["snapshot_id"] != rows[1]["snapshot_id"]:
            raise SystemExit("Final snapshot digests differ")
        print(json.dumps({"items": count, "snapshot_id_equal": True,
                          "retained_peak_bytes": rows[0]["peak_bytes"],
                          "released_peak_bytes": rows[1]["peak_bytes"],
                          "peak_reduction_ratio": round(1 - rows[1]["peak_bytes"] / rows[0]["peak_bytes"], 4),
                          "retained_seconds": rows[0]["seconds"],
                          "released_seconds": rows[1]["seconds"]}))
