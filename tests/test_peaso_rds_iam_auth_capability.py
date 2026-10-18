"""Read-only RDS IAM-auth capability collection with exact option filters."""
import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.collectors import aws_facts_cb_ca as facts


REGION = "us-east-1"
ACCOUNT = "111111111111"
ARN1 = f"arn:aws:rds:{REGION}:{ACCOUNT}:db:db1"
ARN2 = f"arn:aws:rds:{REGION}:{ACCOUNT}:db:db2"
FILTERS = {"Engine": "mysql", "EngineVersion": "8.0.40", "DBInstanceClass": "db.r6g.large"}


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id="fixture-key", aws_secret_access_key="fixture-secret", region_name=REGION)
    client = session.client("rds", region_name=REGION)
    stub = Stubber(client)
    stub.activate()
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: client)
    yield session, stub
    stub.assert_no_pending_responses()
    stub.deactivate()


def instance(arn, **other):
    return {"DBInstanceArn": arn, **FILTERS, **other}


def option(supported):
    return {**FILTERS, "SupportsIAMDatabaseAuthentication": supported}


def fetch(session):
    return facts.FETCHERS["rds_iam_auth_capability"](aws.Requests({}), session, REGION, ACCOUNT)


def test_targeted_query_paginates_and_coalesces_identical_shapes(sdk):
    session, stub = sdk
    stub.add_response("describe_db_instances", {"DBInstances": [instance(ARN1), instance(ARN2),
        instance(f"arn:aws:rds:{REGION}:{ACCOUNT}:db:oracle", Engine="oracle-ee"),
        instance(f"arn:aws:rds:{REGION}:{ACCOUNT}:db:member", DBClusterIdentifier="cluster-1")]}, {})
    stub.add_response("describe_orderable_db_instance_options", {"OrderableDBInstanceOptions": [option(True)], "Marker": "next"}, FILTERS)
    stub.add_response("describe_orderable_db_instance_options", {"OrderableDBInstanceOptions": [option(True)]}, {**FILTERS, "Marker": "next"})
    read = fetch(session)
    assert read.status == "collected" and len(read.items) == 2
    assert {row["DBInstanceArn"] for row in read.items} == {ARN1, ARN2}
    assert all(row["SupportsIAMDatabaseAuthentication"] is True for row in read.items)
    assert all(set(row) == {"id", "DBInstanceArn", "Engine", "EngineVersion", "DBInstanceClass", "SupportsIAMDatabaseAuthentication"} for row in read.items)


@pytest.mark.parametrize("mode", ["false", "empty", "denied", "conflict", "malformed"])
def test_capability_states_stay_distinct(sdk, mode):
    session, stub = sdk
    stub.add_response("describe_db_instances", {"DBInstances": [instance(ARN1)]}, {})
    if mode == "denied":
        stub.add_client_error("describe_orderable_db_instance_options", "AccessDenied", expected_params=FILTERS)
    elif mode == "empty":
        stub.add_response("describe_orderable_db_instance_options", {"OrderableDBInstanceOptions": []}, FILTERS)
    elif mode == "conflict":
        stub.add_response("describe_orderable_db_instance_options", {"OrderableDBInstanceOptions": [option(True), option(False)]}, FILTERS)
    elif mode == "malformed":
        stub.add_response("describe_orderable_db_instance_options", {"OrderableDBInstanceOptions": [{**FILTERS}]}, FILTERS)
    else:
        stub.add_response("describe_orderable_db_instance_options", {"OrderableDBInstanceOptions": [option(False)]}, FILTERS)
    [row] = fetch(session).items
    if mode == "false":
        assert row["SupportsIAMDatabaseAuthentication"] is False
    else:
        assert "SupportsIAMDatabaseAuthentication" not in row
        assert row["_coverage"]["SupportsIAMDatabaseAuthentication"]["status"] == ("denied" if mode == "denied" else "empty" if mode == "empty" else "malformed")


def test_instance_inventory_denied_blocks_capability_inventory(sdk):
    session, stub = sdk
    stub.add_client_error("describe_db_instances", "AccessDenied", expected_params={})
    read = fetch(session)
    assert read.status == "denied" and read.items == []


def test_production_read_guard_allows_exact_describe_and_blocks_mutation(sdk):
    session, stub = sdk
    stub.add_response("describe_orderable_db_instance_options", {"OrderableDBInstanceOptions": []}, FILTERS)
    requests = aws.Requests({})
    assert requests.call(session, "rds", REGION, "describe_orderable_db_instance_options", **FILTERS)["OrderableDBInstanceOptions"] == []
    with pytest.raises(aws.ReadFailure):
        requests.call(session, "rds", REGION, "modify_db_instance", DBInstanceIdentifier="db1", EnableIAMDatabaseAuthentication=True)
