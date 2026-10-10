"""Explicit compute-only estimates from observed worker stages, never AWS bills."""
from datetime import datetime
import math
import os
import time


def runtime_estimate(events):
    seconds = {"collector": 0.0, "analyzer": 0.0}
    attempts = []
    for index, event in enumerate(events):
        if event["status"] not in {"collecting", "analyzing"}:
            continue
        start = datetime.fromisoformat(event["at"]).timestamp()
        end = datetime.fromisoformat(events[index + 1]["at"]).timestamp() if index + 1 < len(events) else time.time()
        elapsed = max(0.0, end - start)
        stage = "collector" if event["status"] == "collecting" else "analyzer"
        seconds[stage] += elapsed
        attempts.append((stage, max(60, math.ceil(elapsed))))
    hosted = os.getenv("PEASO_STORAGE") == "dynamodb"
    cpu, memory = float(os.getenv("PEASO_TASK_VCPU", "0.25")), float(os.getenv("PEASO_TASK_MEMORY_GIB", "0.5"))
    cpu_rate = float(os.getenv("PEASO_VCPU_SECOND_USD", "0.000011244"))
    memory_rate = float(os.getenv("PEASO_MEMORY_GIB_SECOND_USD", "0.000001235"))
    sizes = {stage: {"vcpu": float(os.getenv(f"PEASO_{stage.upper()}_VCPU", str(cpu))), "memory_gib": float(os.getenv(f"PEASO_{stage.upper()}_MEMORY_GIB", str(memory)))} for stage in seconds}
    return {"stage_seconds": {key: round(value, 3) for key, value in seconds.items()},
            "compute_cost_estimate": {"amount_usd": round(sum(duration * (sizes[stage]["vcpu"] * cpu_rate + sizes[stage]["memory_gib"] * memory_rate) for stage, duration in attempts), 8) if hosted else None,
                "model": "Observed worker stages with a 60-second minimum per task attempt", "vcpu": cpu, "memory_gib": memory,
                "pricing_region": os.getenv("AWS_REGION", "us-east-1"), "pricing_source": "https://aws.amazon.com/fargate/pricing/",
                "stage_sizes": sizes,
                "limitations": "Estimate only; excludes image download and task provisioning time, Lambda, Step Functions, S3, DynamoDB, logs, network and public IPv4 charges"}}
