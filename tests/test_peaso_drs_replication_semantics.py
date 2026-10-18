"""DRS current source replication is distinct from recovery job history."""
from __future__ import annotations

import pytest

from peaso.checks import CHECKS
from peaso.checks.claude2_aws_b_common import SCOPE, CONTEXT, inventory, indexes
from peaso.collectors import aws
from peaso.collectors import aws_facts_data_identity as facts
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot


CID = "aws.c2b.drs.region_has_job"
SOURCE_ID = "s-00000000000000001"


def source(state="CONTINUOUS", **overrides):
    return {"sourceServerID": SOURCE_ID, "dataReplicationInfo": {"dataReplicationState": state}, **overrides}


def evaluate(*sources, source_status=None, jobs=None):
    check = next(row for row in CHECKS if row.id == CID)
    current = inventory("drs_source_server", list(sources), status=source_status)
    if jobs is not None:
        current = indexes(current, inventory("drs_job", jobs))
        current["context"] = dict(CONTEXT)
    return check.evaluate({"scope": SCOPE}, current)


def test_no_jobs_with_current_continuous_sources_passes_with_manual_remainder():
    status, evidence = evaluate(source(), jobs=[])
    assert status == "PASS"
    assert evidence["replication_states"] == {"CONTINUOUS": 1}
    assert "Recovery drills" in evidence["manual_readiness"]


def test_historical_jobs_do_not_prove_configured_sources_or_readiness():
    status, evidence = evaluate(jobs=[{"jobID": "historical-recovery", "status": "COMPLETED"}])
    assert status == "NOT_APPLICABLE"
    assert evidence["source_servers"] == 0
    assert "required protection scope" in evidence["reason"]


@pytest.mark.parametrize("state", ["STOPPED", "STALLED", "DISCONNECTED"])
def test_explicit_nonreplicating_source_fails(state):
    status, evidence = evaluate(source(state))
    assert status == "FAIL" and evidence["replication_states"] == {state: 1}


@pytest.mark.parametrize("state", ["INITIATING", "INITIAL_SYNC", "BACKLOG", "CREATING_SNAPSHOT", "PAUSED", "RESCAN", "NEW_PROVIDER_STATE"])
def test_transitional_or_new_state_is_unknown(state):
    status, evidence = evaluate(source(state))
    assert status == "UNKNOWN" and evidence["replication_states"] == {state: 1}


@pytest.mark.parametrize("broken", [
    {"sourceServerID": SOURCE_ID},
    {"sourceServerID": SOURCE_ID, "dataReplicationInfo": {"dataReplicationState": None}},
    {"sourceServerID": SOURCE_ID, "dataReplicationInfo": {"collection_status": "denied"}},
])
def test_missing_malformed_or_denied_source_state_is_unknown(broken):
    status, evidence = evaluate(broken)
    assert status == "UNKNOWN" and evidence["replication_states"] == {"UNREAD": 1}


def test_incomplete_source_inventory_is_unknown_even_with_history():
    assert evaluate(source(), source_status="partial", jobs=[{"jobID": "old"}])[0] == "UNKNOWN"
    assert evaluate(source(), source_status="denied")[0] == "UNKNOWN"


def test_selected_check_requests_only_source_servers_not_job_history():
    request = {"connector": {"provider": "aws"}, "categories": ["hardening"], "checks": [CID]}
    assert plan_collection(request) == ["drs_source_server"]
    assert "drs_job" in plan_collection({"connector": {"provider": "aws"}})
    assert aws.SPECS["drs_source_server"] == ("drs", "describe_source_servers", "items")


def test_snapshot_report_keeps_manual_readiness_limit():
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "drs_source_server", "service": "drs", "scope": SCOPE,
        "status": "collected", "items": [source()]}], created_at="2026-10-12T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, checks=[CID], include_not_applicable=True)
    finding = next(row for row in report["findings"] if row["check_id"] == CID)
    assert finding["status"] == "PASS"
    assert "Recovery drills" in finding["evidence"]["manual_readiness"]


def test_pagination_projects_current_source_state_without_job_api(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    session = boto3.Session(aws_access_key_id="fixture", aws_secret_access_key="fixture", region_name="us-east-1")
    drs = session.client("drs", region_name="us-east-1")
    stub = Stubber(drs)
    first = {"sourceServerID": SOURCE_ID, "dataReplicationInfo": {"dataReplicationState": "CONTINUOUS"},
        "sourceProperties": {"identificationHints": {"hostname": "private-host"}}}
    second = {"sourceServerID": "s-00000000000000002", "dataReplicationInfo": {"dataReplicationState": "STALLED"}}
    stub.add_response("describe_source_servers", {"items": [first], "nextToken": "next"}, {})
    stub.add_response("describe_source_servers", {"items": [second]}, {"nextToken": "next"})
    stub.activate()
    calls = []

    def client(self, _session, service, region):
        calls.append(service)
        assert service == "drs"
        return drs

    monkeypatch.setattr(aws.Requests, "client", client)
    requests = aws.Requests({})
    try:
        read = facts.FETCHERS["drs_source_server"](requests, session, "us-east-1", "123456789012")
    finally:
        stub.assert_no_pending_responses()
        stub.deactivate()
    assert read.status == "collected" and len(read.items) == 2
    assert read.items[0] == {"sourceServerID": SOURCE_ID, "dataReplicationInfo": {"dataReplicationState": "CONTINUOUS"}}
    assert set(calls) == {"drs"} and requests.calls == 2


def test_source_inventory_uninitialized_and_denied_are_distinct(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    session = boto3.Session(aws_access_key_id="fixture", aws_secret_access_key="fixture", region_name="us-east-1")
    drs = session.client("drs", region_name="us-east-1")
    stub = Stubber(drs)
    stub.add_client_error("describe_source_servers", "UninitializedAccountException")
    stub.add_client_error("describe_source_servers", "AccessDeniedException")
    stub.activate()
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: drs)
    try:
        empty = facts.FETCHERS["drs_source_server"](aws.Requests({}), session, "us-east-1", "123456789012")
        denied = facts.FETCHERS["drs_source_server"](aws.Requests({}), session, "us-east-1", "123456789012")
    finally:
        stub.assert_no_pending_responses()
        stub.deactivate()
    assert empty.status == "empty" and empty.error["code"] == "UninitializedAccountException"
    assert denied.status == "denied"
