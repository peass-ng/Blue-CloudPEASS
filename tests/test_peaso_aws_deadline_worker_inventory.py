"""Existing Deadline workers must bind one farm, fleet, role and worker ID."""

from types import SimpleNamespace
import json
from pathlib import Path

from peaso.collectors.aws_b_services import _deadline_fleet_roles, _deadline_workers
from scripts.peaso_deploy_customer_policy import build_policy, policy_size


FARM = "farm-" + "a" * 32
FLEET = "fleet-" + "b" * 32
WORKER = "worker-" + "c" * 32
ROLE = "arn:aws:iam::111111111111:role/fleet"


class Reads:
    max_items = 100

    def __init__(self, *, detail=None, worker=None):
        self.calls = []
        self.fleet_detail = detail if detail is not None else {
            "collection_status": "collected", "farmId": FARM, "fleetId": FLEET,
            "roleArn": ROLE, "status": "ACTIVE", "configuration": {"customerManaged": {}},
            "maxWorkerCount": 2, "workerCount": 1,
            "hostConfiguration": {"scriptBody": "SECRET_SENTINEL"}}
        self.worker = worker if worker is not None else {
            "farmId": FARM, "fleetId": FLEET, "workerId": WORKER, "status": "RUNNING",
            "log": {"error": "SECRET_SENTINEL"}, "hostProperties": {"hostName": "private"}}

    def pages(self, _session, service, _region, operation, expression, **arguments):
        self.calls.append((operation, arguments))
        if operation == "list_farms":
            rows = [{"farmId": FARM}]
        elif operation == "list_fleets":
            rows = [{"farmId": FARM, "fleetId": FLEET}]
        elif operation == "list_workers":
            rows = [self.worker]
        else:
            raise AssertionError(operation)
        return SimpleNamespace(status="collected", error=None, items=rows)

    def detail(self, _session, service, _region, operation, **arguments):
        self.calls.append((operation, arguments))
        assert operation == "get_fleet"
        return self.fleet_detail


def test_worker_inventory_records_exact_binding_without_host_or_log_content():
    reads = Reads()
    result = _deadline_workers(reads, object(), "us-east-1", "111111111111")
    assert result.status == "collected" and len(result.items) == 1
    assert result.items[0]["id"] == FARM + "/" + FLEET + "/" + WORKER
    assert result.items[0]["roleArn"] == ROLE
    assert "SECRET_SENTINEL" not in json.dumps(result.items)
    assert "private" not in json.dumps(result.items)
    assert [operation for operation, _ in reads.calls] == [
        "list_farms", "list_fleets", "get_fleet", "list_workers"]
    assert reads.calls[-1][1]["fleetId"] == FLEET


def test_worker_inventory_rejects_mismatched_parent_or_missing_role():
    wrong_worker = {"farmId": FARM, "fleetId": "fleet-" + "d" * 32,
                    "workerId": WORKER, "status": "RUNNING"}
    wrong_detail = {"collection_status": "collected", "farmId": FARM,
                    "fleetId": FLEET, "status": "ACTIVE"}
    for reads in (Reads(worker=wrong_worker), Reads(detail=wrong_detail)):
        result = _deadline_workers(reads, object(), "us-east-1", "111111111111")
        assert result.status == "partial" and result.items == []


def test_fleet_role_inventory_keeps_fleets_without_workers_and_omits_host_script():
    reads = Reads()
    result = _deadline_fleet_roles(reads, object(), "us-east-1", "111111111111")
    assert result.status == "collected" and len(result.items) == 1
    assert result.items[0]["id"] == FARM + "/" + FLEET
    assert result.items[0]["roleArn"] == ROLE
    assert result.items[0]["fleetMode"] == "customerManaged"
    assert result.items[0]["maxWorkerCount"] > result.items[0]["workerCount"]
    assert "SECRET_SENTINEL" not in json.dumps(result.items)
    assert [operation for operation, _ in reads.calls] == ["list_farms", "list_fleets", "get_fleet"]


def test_customer_template_grants_deadline_worker_metadata_reads_within_quota():
    needed = {"deadline:ListFarms", "deadline:ListFleets", "deadline:GetFleet",
              "deadline:ListWorkers"}
    generated = build_policy({("deadline", "list_farms"), ("deadline", "list_fleets"),
                              ("deadline", "get_fleet"), ("deadline", "list_workers")},
                             include_credential_report_generation=False)
    generated_actions = {action for statement in generated["Statement"]
                         for action in ([statement["Action"]] if isinstance(statement["Action"], str)
                                        else statement["Action"])}
    assert needed <= generated_actions
    template = json.loads((Path(__file__).resolve().parents[1] / "infra/aws/customer-role.json").read_text())
    policies = [resource["Properties"]["PolicyDocument"]
                for name, resource in template["Resources"].items()
                if name.startswith("CspmConfigurationReadOnly")]
    actions = {action for policy in policies for statement in policy["Statement"]
               for action in ([statement["Action"]] if isinstance(statement["Action"], str)
                              else statement["Action"])}
    assert needed <= actions
    assert all(policy_size(policy) <= 6144 for policy in policies)
