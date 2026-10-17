"""Portable private RDS native proposal, including the actual AWS planner path."""
from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import boto3
from botocore.stub import Stubber
import pytest

from peaso.checks import CHECKS, CHECK_ALIASES
from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

MODULE = Path(__file__).resolve().parents[1] / "peaso/checks/remaining_aws_gcp_native.py"
from peaso.checks import remaining_aws_gcp_native as PRIVATE
NIST = "aws.nist.rds_cluster_member_enhanced_monitoring"
FEDRAMP = "aws_fedramp_rds_cluster_members_enhanced_monitoring"
ACCOUNT = "123456789012"
REGION = "us-east-1"
CLUSTER = f"arn:aws:rds:{REGION}:{ACCOUNT}:cluster:db-a"
INSTANCE = f"arn:aws:rds:{REGION}:{ACCOUNT}:db:member-a"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/RDSMonitor"
IDENTITY = {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAREVIEWER"}


def _items(interval=60, role=ROLE):
    cluster = {"DBClusterArn": CLUSTER, "DBClusterIdentifier": "db-a",
        "DBClusterMembers": [{"DBInstanceIdentifier": "member-a"}]}
    member = {"DBInstanceArn": INSTANCE, "DBInstanceIdentifier": "member-a",
        "DBClusterIdentifier": "db-a", "MonitoringInterval": interval,
        "MonitoringRoleArn": role}
    return cluster, member


def _status(snapshot):
    report = evaluate_snapshot(snapshot, checks=[NIST])
    findings = [f for f in report["findings"] if f["check_id"] == NIST and f["resource_id"] != "inventory:rds_cluster"]
    assert len(findings) == 1
    return findings[0]["status"]


def _collect(monkeypatch, *, cluster=None, member=None, second_page=False, deny_instance=False):
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION)
    sts_client = session.client("sts", region_name=REGION)
    rds_client = session.client("rds", region_name=REGION)
    sts_stub, rds_stub = Stubber(sts_client), Stubber(rds_client)
    sts_stub.activate(); rds_stub.activate()
    sts_stub.add_response("get_caller_identity", IDENTITY, {})
    if second_page:
        rds_stub.add_response("describe_db_clusters", {"DBClusters": [], "Marker": "next"}, {})
        rds_stub.add_response("describe_db_clusters", {"DBClusters": [cluster]}, {"Marker": "next"})
    else:
        rds_stub.add_response("describe_db_clusters", {"DBClusters": [cluster]}, {})
    if deny_instance:
        rds_stub.add_client_error("describe_db_instances", service_error_code="AccessDenied",
            service_message="denied", http_status_code=403, expected_params={})
    else:
        rds_stub.add_response("describe_db_instances", {"DBInstances": [member]}, {})
    clients = {("sts", REGION): sts_client, ("rds", REGION): rds_client}
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: clients[(service, region)])
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "pinned-fixture"))
    try:
        snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT],
            "auth": {"profile": "fixture"}, "options": {"regions": [REGION],
            "service_concurrency": 1, "scope_concurrency": 1}}, ["rds_cluster", "rds_instance"])
        sts_stub.assert_no_pending_responses(); rds_stub.assert_no_pending_responses()
        return snapshot
    finally:
        sts_stub.deactivate(); rds_stub.deactivate()


def test_registry_and_alias():
    assert sum(c.id == NIST for c in CHECKS) == 1
    assert CHECK_ALIASES[FEDRAMP] == NIST
    check = next(c for c in CHECKS if c.id == NIST)
    assert check.kind == "rds_cluster" and tuple(check.dependencies) == ("rds_cluster", "rds_instance")


@pytest.mark.parametrize("interval,role,expected", [(60, ROLE, "PASS"), (0, ROLE, "FAIL"), (60, "", "FAIL")])
def test_actual_planner_to_snapshot_to_engine(monkeypatch, interval, role, expected):
    cluster, member = _items(interval, role)
    assert _status(_collect(monkeypatch, cluster=cluster, member=member, second_page=True)) == expected


def test_missing_denied_partial_malformed_foreign(monkeypatch):
    cluster, member = _items()
    snapshot = _collect(monkeypatch, cluster=cluster, member=member)
    assert _status(snapshot) == "PASS"
    for change in ("missing", "partial", "malformed", "foreign"):
        altered = copy.deepcopy(snapshot)
        cluster_env = next(c for c in altered["collections"] if c["type"] == "rds_cluster" and c["status"] == "collected")
        instance_env = next(c for c in altered["collections"] if c["type"] == "rds_instance" and c["status"] == "collected")
        if change == "missing":
            instance_env["items"][0].pop("MonitoringInterval")
        elif change == "partial":
            instance_env["status"] = "partial"; instance_env["error"] = {"code": "page_failure"}
        elif change == "malformed":
            instance_env["items"][0]["MonitoringInterval"] = "60"
        else:
            instance_env["items"][0]["DBInstanceArn"] = INSTANCE.replace(ACCOUNT, "999999999999")
        altered.pop("snapshot_id", None)
        assert _status(altered) == "UNKNOWN", change
    denied = _collect(monkeypatch, cluster=cluster, member=member, deny_instance=True)
    assert _status(denied) == "UNKNOWN"


@pytest.mark.parametrize("role,expected", [
    (f"arn:aws:iam::{ACCOUNT}:role/service-role/monitor/RDSMonitor", "PASS"),
    ("not-an-arn", "UNKNOWN"),
    (f"arn:aws-cn:iam::{ACCOUNT}:role/RDSMonitor", "UNKNOWN"),
    ("arn:aws:iam::999999999999:role/RDSMonitor", "UNKNOWN"),
    (f"arn:aws:iam::{ACCOUNT}:user/RDSMonitor", "UNKNOWN"),
])
def test_rds_monitoring_role_identity(monkeypatch, role, expected):
    cluster, member = _items(role=role)
    assert _status(_collect(monkeypatch, cluster=cluster, member=member)) == expected


def test_rds_cluster_member_partition_conflict(monkeypatch):
    cluster, member = _items()
    snapshot = _collect(monkeypatch, cluster=cluster, member=member)
    for kind, field in (("rds_cluster", "DBClusterArn"), ("rds_instance", "DBInstanceArn")):
        altered = copy.deepcopy(snapshot)
        env = next(c for c in altered["collections"] if c["type"] == kind and c["status"] == "collected")
        env["items"][0][field] = env["items"][0][field].replace("arn:aws:", "arn:aws-cn:")
        altered.pop("snapshot_id", None)
        assert _status(altered) == "UNKNOWN"

ECS_ID = "aws_ecs_task_definition_credential_environment_names"
TASK_ARN = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/web:1"


def _collect_ecs(monkeypatch, names, *, foreign=False, malformed=False, second_page=False):
    import json
    from peaso.collectors import aws_b_services
    from peaso.collectors import aws_facts_compute_edge
    private_path = MODULE.parents[1] / "collectors/aws_facts_compute_edge.py"
    spec = importlib.util.spec_from_file_location("peaso.collectors.aws_facts_compute_edge_private", private_path)
    private = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(private)
    original = aws_b_services.ENRICHERS["ecs_task_definition"]
    monkeypatch.setitem(aws.ENRICHERS, "ecs_task_definition", lambda req, ses, reg, rows:
        private._ecs_environment_names(req, ses, reg, original(req, ses, reg, rows)))
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION)
    sts_client = session.client("sts", region_name=REGION); ecs_client = session.client("ecs", region_name=REGION)
    sts_stub, ecs_stub = Stubber(sts_client), Stubber(ecs_client)
    sts_stub.activate(); ecs_stub.activate()
    sts_stub.add_response("get_caller_identity", IDENTITY, {})
    if second_page:
        ecs_stub.add_response("list_task_definitions", {"taskDefinitionArns": [], "nextToken": "next"}, {})
        ecs_stub.add_response("list_task_definitions", {"taskDefinitionArns": [TASK_ARN]}, {"nextToken": "next"})
    else:
        ecs_stub.add_response("list_task_definitions", {"taskDefinitionArns": [TASK_ARN]}, {})
    container = {"name": "web", "environment": [{"name": n, "value": "DO-NOT-STORE"} for n in names]}
    if malformed:
        container["environment"][0].pop("name")
    definition = {"taskDefinitionArn": TASK_ARN.replace(ACCOUNT, "999999999999") if foreign else TASK_ARN,
                  "status": "ACTIVE", "containerDefinitions": [container]}
    ecs_stub.add_response("describe_task_definition", {"taskDefinition": definition}, {"taskDefinition": TASK_ARN})
    clients = {("sts", REGION): sts_client, ("ecs", REGION): ecs_client}
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: clients[(service, region)])
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "pinned-fixture"))
    try:
        snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "fixture"},
            "options": {"regions": [REGION], "service_concurrency": 1, "scope_concurrency": 1}}, ["ecs_task_definition"])
        sts_stub.assert_no_pending_responses(); ecs_stub.assert_no_pending_responses()
        assert "DO-NOT-STORE" not in json.dumps(snapshot)
        return snapshot
    finally:
        sts_stub.deactivate(); ecs_stub.deactivate()


@pytest.mark.parametrize("names,expected", [([], "PASS"), (["AWS_ACCESS_KEY_ID"], "FAIL"), (["OTHER"], "PASS")])
def test_ecs_main_planner_to_engine_no_values(monkeypatch, names, expected):
    snapshot = _collect_ecs(monkeypatch, names, second_page=True)
    report = evaluate_snapshot(snapshot, checks=[ECS_ID])
    findings = [f for f in report["findings"] if f["check_id"] == ECS_ID and f["resource_id"] != "inventory:ecs_task_definition"]
    assert len(findings) == 1 and findings[0]["status"] == expected


def test_ecs_malformed_and_foreign_are_unknown(monkeypatch):
    for kw in ({"foreign": True}, {"malformed": True}):
        snapshot = _collect_ecs(monkeypatch, ["AWS_ACCESS_KEY_ID"], **kw)
        report = evaluate_snapshot(snapshot, checks=[ECS_ID])
        findings = [f for f in report["findings"] if f["check_id"] == ECS_ID and f["resource_id"] != "inventory:ecs_task_definition"]
        assert len(findings) == 1 and findings[0]["status"] == "UNKNOWN"


def test_ecs_missing_partial_denied_foreign_snapshot(monkeypatch):
    snapshot = _collect_ecs(monkeypatch, ["OTHER"])
    for change in ("missing", "partial", "foreign"):
        altered = copy.deepcopy(snapshot)
        env = next(c for c in altered["collections"] if c["type"] == "ecs_task_definition" and c["status"] == "collected")
        if change == "missing":
            env["items"][0]["Definition"]["taskDefinition"]["containerDefinitions"][0].pop("environment")
        elif change == "partial":
            env["status"] = "partial"; env["error"] = {"code": "page_failure"}
        else:
            env["items"][0]["taskDefinitionArn"] = TASK_ARN.replace(ACCOUNT, "999999999999")
        altered.pop("snapshot_id", None)
        report = evaluate_snapshot(altered, checks=[ECS_ID])
        statuses = [f["status"] for f in report["findings"] if f["check_id"] == ECS_ID and f["resource_id"] != "inventory:ecs_task_definition"]
        assert statuses == ["UNKNOWN"], change
    denied = copy.deepcopy(snapshot)
    env = next(c for c in denied["collections"] if c["type"] == "ecs_task_definition" and c["status"] == "collected")
    env["status"] = "denied"; env["items"] = []; env["error"] = {"code": "AccessDenied"}
    denied.pop("snapshot_id", None)
    report = evaluate_snapshot(denied, checks=[ECS_ID])
    statuses = [f["status"] for f in report["findings"] if f["check_id"] == ECS_ID]
    assert statuses == ["DENIED"]


def test_ecs_collector_malformed_detail_fails_closed_without_api_values():
    path = MODULE.parents[1] / "collectors/aws_facts_compute_edge.py"
    spec = importlib.util.spec_from_file_location("peaso.collectors.aws_facts_compute_edge_private_malformed", path)
    private = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(private)
    class NoCalls:
        def call(self, *args, **kwargs):
            raise AssertionError("malformed detail must not trigger a raw API read")
    row = {"taskDefinitionArn": TASK_ARN, "Definition": ["malformed"]}
    assert private._ecs_environment_names(NoCalls(), object(), REGION, [row]) == [row]


SECRET_ID = "aws.pci.secretsmanager.kms_encryption_any"
SECRET_ARN = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:db-AbCdEf"
KEY_ID = "11111111-2222-3333-4444-555555555555"
KEY_ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/{KEY_ID}"


def _collect_secret(monkeypatch, *, key_ref=KEY_ARN, key_state="Enabled", deny_detail=False):
    import json
    private_path = MODULE.parents[1] / "collectors/aws.py"
    spec = importlib.util.spec_from_file_location("peaso.collectors.aws_private_secret", private_path)
    private = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, private)
    spec.loader.exec_module(private)
    monkeypatch.setattr(aws, "_enrich", private._enrich)
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION)
    clients = {service: session.client(service, region_name=REGION)
               for service in ("sts", "secretsmanager", "kms")}
    stubs = {service: Stubber(client) for service, client in clients.items()}
    for stub in stubs.values():
        stub.activate()
    stubs["sts"].add_response("get_caller_identity", IDENTITY, {})
    stale = f"arn:aws:kms:{REGION}:{ACCOUNT}:alias/stale"
    stubs["secretsmanager"].add_response("list_secrets", {"SecretList": [], "NextToken": "next"}, {})
    stubs["secretsmanager"].add_response("list_secrets", {"SecretList": [
        {"ARN": SECRET_ARN, "Name": "db", "KmsKeyId": stale}]}, {"NextToken": "next"})
    if deny_detail:
        stubs["secretsmanager"].add_client_error("describe_secret", service_error_code="AccessDeniedException",
            service_message="denied", http_status_code=403, expected_params={"SecretId": SECRET_ARN})
    else:
        detail = {"ARN": SECRET_ARN, "Name": "db", "RotationEnabled": False}
        if key_ref is not None:
            detail["KmsKeyId"] = key_ref
        stubs["secretsmanager"].add_response("describe_secret", detail, {"SecretId": SECRET_ARN})
    stubs["secretsmanager"].add_response("get_resource_policy", {}, {"SecretId": SECRET_ARN})
    stubs["kms"].add_response("list_keys", {"Keys": [], "Truncated": True, "NextMarker": "next"}, {})
    stubs["kms"].add_response("list_keys", {"Keys": [{"KeyId": KEY_ID, "KeyArn": KEY_ARN}],
        "Truncated": False}, {"Marker": "next"})
    stubs["kms"].add_response("describe_key", {"KeyMetadata": {
        "AWSAccountId": ACCOUNT, "KeyId": KEY_ID, "Arn": KEY_ARN,
        "CreationDate": 1, "Enabled": key_state == "Enabled", "Description": "fixture",
        "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": key_state, "Origin": "AWS_KMS",
        "KeyManager": "CUSTOMER"}}, {"KeyId": KEY_ID})
    stubs["kms"].add_response("get_key_rotation_status", {"KeyRotationEnabled": False}, {"KeyId": KEY_ID})
    stubs["kms"].add_response("get_key_policy", {"Policy": "{}"}, {"KeyId": KEY_ID, "PolicyName": "default"})
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: clients[service])
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "pinned-fixture"))
    try:
        snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "fixture"},
            "options": {"regions": [REGION], "service_concurrency": 1, "scope_concurrency": 1}},
            ["secret", "kms_key"])
        for stub in stubs.values():
            stub.assert_no_pending_responses()
        assert "SecretString" not in json.dumps(snapshot)
        secret = next(c for c in snapshot["collections"] if c["type"] == "secret" and c["status"] == "collected")["items"][0]
        assert secret.get("KmsKeyId") != stale
        assert secret["_coverage"]["KmsKeyId"]["source_operation"] == "secretsmanager:DescribeSecret"
        return snapshot
    finally:
        for stub in stubs.values():
            stub.deactivate()


def _secret_status(snapshot):
    report = evaluate_snapshot(snapshot, checks=[SECRET_ID])
    findings = [f for f in report["findings"] if f["check_id"] == SECRET_ID and
                f["resource_id"] != "inventory:secret"]
    assert len(findings) == 1
    return findings[0]["status"]


@pytest.mark.parametrize("key_ref,key_state,expected", [
    (KEY_ARN, "Enabled", "PASS"), (KEY_ID, "Enabled", "PASS"),
    (KEY_ARN, "Disabled", "FAIL"), (None, "Enabled", "UNKNOWN"),
    (f"arn:aws:kms:{REGION}:{ACCOUNT}:alias/db", "Enabled", "UNKNOWN"),
    ("alias/aws/secretsmanager", "Enabled", "UNKNOWN"),
])
def test_secret_main_planner_describe_key_join(monkeypatch, key_ref, key_state, expected):
    assert _secret_status(_collect_secret(monkeypatch, key_ref=key_ref, key_state=key_state)) == expected


def test_secret_denied_partial_foreign_malformed(monkeypatch):
    snapshot = _collect_secret(monkeypatch)
    assert _secret_status(snapshot) == "PASS"
    for change in ("secret_partial", "kms_partial", "kms_denied", "foreign_secret",
                   "foreign_key", "foreign_kms_metadata", "malformed_key", "stale_list"):
        altered = copy.deepcopy(snapshot)
        secret = next(c for c in altered["collections"] if c["type"] == "secret" and c["status"] == "collected")
        kms = next(c for c in altered["collections"] if c["type"] == "kms_key" and c["status"] == "collected")
        if change == "secret_partial":
            secret["status"] = "partial"; secret["error"] = {"code": "page_failure"}
        elif change in ("kms_partial", "kms_denied"):
            kms["status"] = "partial" if change == "kms_partial" else "denied"
            kms["error"] = {"code": "page_failure" if change == "kms_partial" else "AccessDenied"}
            if change == "kms_denied":
                kms["items"] = []
        elif change == "foreign_secret":
            secret["items"][0]["ARN"] = SECRET_ARN.replace(ACCOUNT, "999999999999")
        elif change == "foreign_key":
            secret["items"][0]["KmsKeyId"] = KEY_ARN.replace(ACCOUNT, "999999999999")
        elif change == "foreign_kms_metadata":
            kms["items"][0]["Metadata"]["KeyMetadata"]["Arn"] = KEY_ARN.replace(ACCOUNT, "999999999999")
        elif change == "malformed_key":
            kms["items"][0]["Metadata"]["KeyMetadata"]["KeyState"] = ["Enabled"]
        else:
            secret["items"][0]["_coverage"]["KmsKeyId"] = {"status": "collected", "source_operation": "secretsmanager:ListSecrets"}
        altered.pop("snapshot_id", None)
        assert _secret_status(altered) == "UNKNOWN", change
    assert _secret_status(_collect_secret(monkeypatch, deny_detail=True)) == "UNKNOWN"


@pytest.mark.parametrize("state,expected", [("Enabled", "PASS"), ("Disabled", "FAIL")])
@pytest.mark.parametrize("unrelated_detail", [None, {"collection_status": "denied"}, {"collection_status": "collected", "KeyMetadata": "malformed"}])
def test_kms_unrelated_detail_does_not_hide_selected_key(state, expected, unrelated_detail):
    from peaso.checks import evaluate_check
    from peaso.checks.facts import MemoIndex
    account, region = ACCOUNT, REGION
    key_id = "11111111-1111-1111-1111-111111111111"
    other_id = "22222222-2222-2222-2222-222222222222"
    key_arn = f"arn:aws:kms:{region}:{account}:key/{key_id}"
    other_arn = f"arn:aws:kms:{region}:{account}:key/{other_id}"
    secret = {"ARN": f"arn:aws:secretsmanager:{region}:{account}:secret:fixture-abcdef", "Name": "fixture",
              "AccountId": account, "Region": region, "KmsKeyId": key_arn,
              "_coverage": {"KmsKeyId": {"status": "collected", "source_operation": "secretsmanager:DescribeSecret"}}}
    target = {"KeyArn": key_arn, "KeyId": key_id, "AccountId": account, "Region": region,
              "Metadata": {"collection_status": "collected", "KeyMetadata": {"Arn": key_arn, "KeyId": key_id, "KeyManager": "CUSTOMER", "KeyState": state}}}
    other = {"KeyArn": other_arn, "KeyId": other_id, "AccountId": account, "Region": region, "Metadata": unrelated_detail}
    def index(keys):
        scope = account + "/" + region
        result = {"context": {"provider": "aws", "scope": scope, "metadata": {"caller_identities": [IDENTITY]}}, "collections": {}}
        for kind, rows in [("secret", [secret]), ("kms_key", keys)]:
            result["collections"][kind] = [{"type": kind, "scope": scope, "account_id": account, "global": False, "status": "collected", "items": rows}]
            result[kind] = [{"type": kind, "scope": scope, "provider": "aws", "data": row} for row in rows]
        return MemoIndex(result)
    assert evaluate_check("aws.pci.secretsmanager.kms_encryption_any", secret, index([target, other]))[0] == expected
    denied_target = copy.deepcopy(target); denied_target["Metadata"] = {"collection_status": "denied"}
    assert evaluate_check("aws.pci.secretsmanager.kms_encryption_any", secret, index([denied_target, other]))[0] == "UNKNOWN"
    foreign = copy.deepcopy(other); foreign["KeyArn"] = other_arn.replace(account, "999999999999")
    assert evaluate_check("aws.pci.secretsmanager.kms_encryption_any", secret, index([target, foreign]))[0] == "UNKNOWN"
