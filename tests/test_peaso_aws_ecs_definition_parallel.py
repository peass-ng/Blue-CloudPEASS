"""Independent ECS definition reads overlap without changing native evidence."""
from copy import deepcopy
import threading
import time

from peaso.collectors.aws_b_services import ENRICHERS


class DefinitionReads:
    def __init__(self, workers):
        self.workers = workers
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.calls = []

    def detail(self, session, service, region, operation, **arguments):
        assert (service, region, operation) == ("ecs", "us-east-1", "describe_task_definition")
        arn = arguments["taskDefinition"]
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.calls.append(arn)
        time.sleep(0.01)
        with self.lock:
            self.active -= 1
        if arn.endswith(":3"):
            return {"collection_status": "denied", "error": {"code": "AccessDeniedException"}}
        return {"collection_status": "collected", "taskDefinition": {
            "taskDefinitionArn": arn, "containerDefinitions": [{"name": "app",
                "environment": [{"name": "TOKEN", "value": "private-value"}]}]}}


def test_ecs_definition_parallelism_preserves_order_denials_and_redaction():
    arns = [f"arn:aws:ecs:us-east-1:123456789012:task-definition/demo:{i}" for i in range(1, 9)]
    rows = [{"taskDefinitionArn": arn} for arn in arns]
    before = deepcopy(rows)
    serial, parallel = DefinitionReads(1), DefinitionReads(12)
    enrich = ENRICHERS["ecs_task_definition"]
    expected = enrich(serial, object(), "us-east-1", rows)
    actual = enrich(parallel, object(), "us-east-1", rows)
    assert actual == expected
    assert rows == before
    assert [row["taskDefinitionArn"] for row in actual] == arns
    assert len(serial.calls) == len(parallel.calls) == len(arns)
    assert set(parallel.calls) == set(arns)
    assert serial.peak == 1
    assert 1 < parallel.peak <= 4
    assert actual[2]["Definition"]["collection_status"] == "denied"
    assert "private-value" not in str(actual)
