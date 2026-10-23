"""Measure the removed cumulative checkpoint copies with identical public bytes.

Run: python examples/benchmark_peaso_checkpoint_copy.py [items_per_scope]
Synthetic native facts only; measures Python allocation peaks after the input is built.
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
from peaso.snapshot import make_snapshot, seal, validate


def run(mode: str, size: int) -> dict:
    scope = "123456789012/us-east-1"
    collections = {("cloudwatch_metric", scope): {
        "type": "cloudwatch_metric", "scope": scope, "status": "collected",
        "items": [{"id": f"metric-{index}", "Dimensions": [
            {"Name": "InstanceId", "Value": f"i-{index:016x}"}],
            "Namespace": "AWS/EC2", "MetricName": "CPUUtilization"}
            for index in range(size)]}}
    sections = {"hardening": {"status": "running"}}
    metadata = {"intentional_partial": True, "sections": sections}
    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    if mode == "before":
        selected = copy.deepcopy(collections)
        raw = make_snapshot("aws", [scope], list(selected.values()), created_at="2026-10-23T00:00:00+00:00",
                            metadata={"intentional_partial": True})
        raw["metadata"]["sections"] = sections
        raw = seal(raw)
    else:
        selected = dict(collections)
        raw = make_snapshot("aws", [scope], list(selected.values()), created_at="2026-10-23T00:00:00+00:00",
                            metadata=metadata)
    snapshot = validate(raw)
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"mode": mode, "items": size, "snapshot_id": snapshot["snapshot_id"],
            "seconds": round(elapsed, 3), "peak_bytes": peak}


if __name__ == "__main__":
    size = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    if len(sys.argv) > 2:
        print(json.dumps(run(sys.argv[2], size)))
    else:
        results = [json.loads(subprocess.check_output(
            [sys.executable, str(Path(__file__).resolve()), str(size), mode], text=True))
            for mode in ("before", "after")]
        if results[0]["snapshot_id"] != results[1]["snapshot_id"]:
            raise SystemExit("Checkpoint snapshots differ")
        print(json.dumps({"items": size, "snapshot_id_equal": True,
                          "before_peak_bytes": results[0]["peak_bytes"],
                          "after_peak_bytes": results[1]["peak_bytes"],
                          "peak_reduction_ratio": round(1 - results[1]["peak_bytes"] / results[0]["peak_bytes"], 4),
                          "before_seconds": results[0]["seconds"], "after_seconds": results[1]["seconds"]}))
