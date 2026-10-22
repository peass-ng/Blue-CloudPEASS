"""ECS Exec readiness metadata is retained without container secrets."""
import ast
import copy
from pathlib import Path


class Read:
    def __init__(self, items, status="collected", error=None):
        self.items, self.status, self.error = items, status, error


def test_describe_tasks_keeps_only_exec_agent_state():
    source = Path(__file__).resolve().parents[1] / "peaso/collectors/aws_privesc_facts.py"
    node, = (n for n in ast.parse(source.read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name == "_ecs_per_cluster")
    task = "arn:aws:ecs:us-east-1:123456789012:task/prod/abc"
    cluster = "arn:aws:ecs:us-east-1:123456789012:cluster/prod"
    row = {"taskArn": task, "clusterArn": cluster, "lastStatus": "RUNNING", "enableExecuteCommand": True,
           "containers": [{"name": "app", "lastStatus": "RUNNING", "reason": "private-error",
                           "environment": [{"name": "PASSWORD", "value": "private-value"}],
                           "managedAgents": [{"name": "ExecuteCommandAgent", "lastStatus": "RUNNING",
                                              "reason": "private-agent-error"}]}]}
    namespace = {
        "copy": copy, "OK": ("collected", "empty"),
        "_TASK_FIELDS": ("taskArn", "clusterArn", "lastStatus", "enableExecuteCommand"),
        "_ENI_DETAILS": set(),
        "_clusters": lambda *_args: Read([cluster]),
        "_describe_batches": lambda *_args: ([row], None),
        "_failure_of": lambda *_args: ("partial", "failed"),
        "_finish": lambda items, failure: Read(items, "partial" if failure else "collected"),
    }
    class Requests:
        def pages(self, *_args, **_kwargs):
            return Read([task])
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)
    result = namespace["_ecs_per_cluster"]("ecs_task")(Requests(), object(), "us-east-1", "123456789012")
    assert result.status == "collected"
    assert result.items[0]["containers"] == [{"name": "app", "lastStatus": "RUNNING",
                                              "managedAgents": [{"name": "ExecuteCommandAgent", "lastStatus": "RUNNING"}]}]
    assert "private" not in str(result.items)
