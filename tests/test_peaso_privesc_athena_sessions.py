"""An Athena session reaches only its recorded execution role and engine route."""

import json
from pathlib import Path

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.collectors import aws_facts_data_identity as facts
from peaso.privesc import versioned_catalog
from scripts.peaso_deploy_customer_policy import build_policy, policy_size
from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, real, reached, role, role_arn, user,
)


WORKGROUP = f"arn:aws:athena:{REGION}:{ACCOUNT}:workgroup/spark"
SESSION = f"{WORKGROUP}/session/session-1"
CALC = "aws-athena-startcalculationexecution-existing-session"
NOTEBOOK = "aws-athena-createpresignednotebookurl"
CONNECT = "aws-athena-getsessionendpoint-spark-connect"


@pytest.fixture
def athena_sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name=REGION)
    client = session.client("athena", region_name=REGION)
    stub = Stubber(client)
    stub.activate()
    monkeypatch.setattr(aws.Requests, "client", lambda *_: client)
    yield session, stub
    stub.assert_no_pending_responses()
    stub.deactivate()


def test_session_collector_keeps_exact_role_but_no_token(athena_sdk):
    session, stub = athena_sdk
    stub.add_response("list_work_groups", {"WorkGroups": [{"Name": "spark"}]}, {})
    stub.add_response("list_sessions", {"Sessions": [{"SessionId": "session-1"}]}, {"WorkGroup": "spark"})
    stub.add_response("get_session", {"SessionId": "session-1", "WorkGroup": "spark",
        "SessionConfiguration": {"ExecutionRole": role_arn("target")},
        "Status": {"State": "IDLE"}, "EngineVersion": "PySpark engine version 3",
        "NotebookVersion": "Athena notebook version 1"}, {"SessionId": "session-1"})
    read = facts.FETCHERS["athena_session"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected"
    assert read.items == [{"SessionId": "session-1", "WorkGroup": "spark",
        "SessionConfiguration": {"ExecutionRole": role_arn("target")},
        "Status": {"State": "IDLE"}, "EngineVersion": "PySpark engine version 3",
        "NotebookVersion": "Athena notebook version 1"}]


def test_denied_session_detail_is_unknown_not_empty(athena_sdk):
    session, stub = athena_sdk
    stub.add_response("list_work_groups", {"WorkGroups": [{"Name": "spark"}]}, {})
    stub.add_response("list_sessions", {"Sessions": [{"SessionId": "session-1"}]}, {"WorkGroup": "spark"})
    stub.add_client_error("get_session", "AccessDeniedException", expected_params={"SessionId": "session-1"})
    read = facts.FETCHERS["athena_session"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "denied" and read.items == []


def test_partial_detail_keeps_known_session_and_marks_collection_partial(athena_sdk):
    session, stub = athena_sdk
    stub.add_response("list_work_groups", {"WorkGroups": [{"Name": "spark"}]}, {})
    stub.add_response("list_sessions", {"Sessions": [{"SessionId": "session-1"},
                                                     {"SessionId": "session-2"}]}, {"WorkGroup": "spark"})
    stub.add_response("get_session", {"SessionId": "session-1", "WorkGroup": "spark",
        "SessionConfiguration": {"ExecutionRole": role_arn("target")},
        "Status": {"State": "IDLE"}, "EngineVersion": "PySpark engine version 3"},
        {"SessionId": "session-1"})
    stub.add_client_error("get_session", "AccessDeniedException", expected_params={"SessionId": "session-2"})
    read = facts.FETCHERS["athena_session"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "partial" and len(read.items) == 1
    assert read.items[0]["SessionConfiguration"]["ExecutionRole"] == role_arn("target")


def scenario(technique, *, role_name="target", state="IDLE", engine=None, notebook=None,
             workgroup="spark", permissions=True, session_permission=True, inventory_status="collected"):
    engine = engine or ("Apache Spark version 3.5" if technique == CONNECT else "PySpark engine version 3")
    action = {CALC: "athena:StartCalculationExecution", NOTEBOOK: "athena:CreatePresignedNotebookUrl",
              CONNECT: "athena:GetSessionEndpoint"}[technique]
    statements = []
    if permissions:
        statements.append(allow(action, resource=WORKGROUP))
    if technique == CONNECT and session_permission:
        statements.append(allow(action, resource=SESSION))
    caller = user("alice", *statements)
    record = {"SessionId": "session-1", "WorkGroup": workgroup,
              "SessionConfiguration": {"ExecutionRole": role_arn(role_name)},
              "Status": {"State": state}, "EngineVersion": engine,
              "NotebookVersion": notebook}
    snap = aws_snap([caller], [role("target", "athena.amazonaws.com"), role("other", "athena.amazonaws.com")],
                    [col("athena_session", [record] if inventory_status == "collected" else [], inventory_status)])
    return reached(real(snap, technique, include_unknown=True), ALICE, technique)


@pytest.mark.parametrize("technique,notebook", ((CALC, None), (NOTEBOOK, "Athena notebook version 1"),
                                              (CONNECT, None)))
def test_each_session_route_reaches_its_exact_role(technique, notebook):
    assert scenario(technique, notebook=notebook) == {role_arn("target"): "conditional"}
    assert scenario(technique, role_name="other", notebook=notebook) == {role_arn("other"): "conditional"}


@pytest.mark.parametrize("technique,change", (
    (CALC, {"state": "BUSY"}),
    (CALC, {"engine": "Apache Spark version 3.5"}),
    (NOTEBOOK, {"notebook": None}),
    (NOTEBOOK, {"engine": "Apache Spark version 3.5", "notebook": "Athena notebook version 1"}),
    (CONNECT, {"engine": "PySpark engine version 3"}),
    (CONNECT, {"session_permission": False}),
    (CONNECT, {"state": "TERMINATED"}),
    (CALC, {"permissions": False}),
    (CALC, {"workgroup": "different"}),
))
def test_unmatched_engine_state_session_or_scope_cannot_reach_role(technique, change):
    assert scenario(technique, **change) == {}


def test_current_and_prior_binding_remain_exact():
    binding = versioned_catalog.current_binding()
    entries, status = versioned_catalog.lookup_entries([CALC, NOTEBOOK, CONNECT], binding)
    assert status == "exact_strict_privesc" and set(entries) == {CALC, NOTEBOOK, CONNECT}
    old = {"schema": versioned_catalog.BINDING_SCHEMA,
           "manifest_sha256": versioned_catalog.RECENT_CURRENT_MANIFEST,
           "effective_tree_sha256": versioned_catalog.RECENT_CURRENT_TREE,
           "source_revision": versioned_catalog.V4_REVISION}
    entries, status = versioned_catalog.lookup_entries([CALC, NOTEBOOK, CONNECT], old)
    assert status == "exact_previous_current" and entries == {}


def test_customer_role_includes_session_inventory_reads_within_policy_limit():
    root = Path(__file__).resolve().parents[1]
    template = json.loads((root / "infra/aws/customer-role.json").read_text())
    policies = [row["Properties"]["PolicyDocument"] for name, row in template["Resources"].items()
                if name.startswith("CspmConfigurationReadOnly")]
    actions = {action for document in policies for statement in document["Statement"]
               for action in ([statement["Action"]] if isinstance(statement["Action"], str)
                              else statement["Action"])}
    assert {"athena:ListWorkGroups", "athena:ListSessions", "athena:GetSession"} <= actions
    assert all(policy_size(document) <= 6144 for document in policies)
    for operation, action in (("list_work_groups", "athena:ListWorkGroups"),
                              ("list_sessions", "athena:ListSessions"),
                              ("get_session", "athena:GetSession")):
        generated = build_policy({("athena", operation)}, include_credential_report_generation=False)
        assert generated["Statement"][0]["Action"] == [action]
