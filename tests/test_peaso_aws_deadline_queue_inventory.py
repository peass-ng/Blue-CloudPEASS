"""Deadline queue inventory must bind one farm, queue and exact IAM role."""

from types import SimpleNamespace
import json
from pathlib import Path

from peaso.collectors.aws_b_services import _deadline_queues
from scripts.peaso_deploy_customer_policy import build_policy, policy_size


FARM = "farm-" + "a" * 32
QUEUE = "queue-" + "b" * 32
ROLE = "arn:aws:iam::111111111111:role/render"


class Reads:
    max_items = 100

    def __init__(self, *, detail=None, queues=None):
        self.calls = []
        self.queue_rows = queues if queues is not None else [{"farmId": FARM, "queueId": QUEUE}]
        self.queue_detail = detail if detail is not None else {
            "collection_status": "collected", "farmId": FARM, "queueId": QUEUE,
            "roleArn": ROLE, "status": "SCHEDULING"}

    def pages(self, _session, service, _region, operation, expression, **arguments):
        self.calls.append((service, operation, expression, arguments))
        if operation == "list_farms":
            return SimpleNamespace(status="collected", error=None, items=[{"farmId": FARM}])
        if operation == "list_queues":
            return SimpleNamespace(status="collected", error=None, items=self.queue_rows)
        raise AssertionError(operation)

    def detail(self, _session, service, _region, operation, **arguments):
        self.calls.append((service, operation, None, arguments))
        assert operation == "get_queue"
        return self.queue_detail


def test_deadline_queue_read_binds_exact_parent_and_role_without_vending_credentials():
    reads = Reads()
    result = _deadline_queues(reads, object(), "us-east-1", "111111111111")
    assert result.status == "collected"
    assert result.items == [{"id": FARM + "/" + QUEUE, "farmId": FARM,
                             "queueId": QUEUE, "roleArn": ROLE, "status": "SCHEDULING",
                             "collection_status": "collected",
                             "_provenance": {"source_operation": "deadline:GetQueue", "read_only": True}}]
    assert [operation for _, operation, _, _ in reads.calls] == ["list_farms", "list_queues", "get_queue"]
    assert reads.calls[-1][3] == {"farmId": FARM, "queueId": QUEUE}


def test_deadline_queue_read_rejects_mismatched_parent_or_missing_role():
    for detail in ({"collection_status": "collected", "farmId": "farm-" + "c" * 32,
                    "queueId": QUEUE, "roleArn": ROLE},
                   {"collection_status": "collected", "farmId": FARM, "queueId": QUEUE},
                   {"collection_status": "denied", "farmId": FARM, "queueId": QUEUE,
                    "roleArn": ROLE}):
        result = _deadline_queues(Reads(detail=detail), object(), "us-east-1", "111111111111")
        assert result.status == "partial" and result.items == []
    mismatched_summary = [{"farmId": "farm-" + "c" * 32, "queueId": QUEUE}]
    reads = Reads(queues=mismatched_summary)
    result = _deadline_queues(reads, object(), "us-east-1", "111111111111")
    assert result.status == "partial" and result.items == []
    assert [operation for _, operation, _, _ in reads.calls] == ["list_farms", "list_queues"]


def test_customer_template_grants_all_queue_metadata_reads_within_policy_quota():
    needed = {"deadline:ListFarms", "deadline:ListQueues", "deadline:GetQueue"}
    generated = build_policy({("deadline", "list_farms"), ("deadline", "list_queues"),
                              ("deadline", "get_queue")}, include_credential_report_generation=False)
    generated_actions = {action for statement in generated["Statement"]
                         for action in ([statement["Action"]] if isinstance(statement["Action"], str)
                                        else statement["Action"])}
    assert needed <= generated_actions
    root = Path(__file__).resolve().parents[1]
    template = json.loads((root / "infra/aws/customer-role.json").read_text())
    policies = [resource["Properties"]["PolicyDocument"]
                for name, resource in template["Resources"].items()
                if name.startswith("CspmConfigurationReadOnly")]
    actions = {action for policy in policies for statement in policy["Statement"]
               for action in ([statement["Action"]] if isinstance(statement["Action"], str)
                              else statement["Action"])}
    assert needed <= actions
    assert all(policy_size(policy) <= 6144 for policy in policies)
