"""A writable MWAA DAG must bind to the same environment and execution role."""

from peaso.privesc import schema
from peaso.privesc import versioned_catalog
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_followups import ACCOUNT, ALICE, aws_snap, pol, role, user


SCOPE = f"{ACCOUNT}/us-east-1"
BUCKET = "arn:aws:s3:::team-airflow"
OBJECT = BUCKET + "/dags/reports/custom.py"
TARGET = f"arn:aws:iam::{ACCOUNT}:role/airflow-exec"
ENTRY = next(row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"]
             if row["id"] == "aws-mwaa-s3-putobject-dag")


def _model(*, put=OBJECT, read=OBJECT, list_bucket=BUCKET, execution_role=TARGET,
           status="AVAILABLE", inventory_status="collected", dag_path="dags/reports"):
    actor = user("alice", {"Effect": "Allow", "Action": "s3:PutObject", "Resource": put})
    execution = role("airflow-exec", pol({"Effect": "Allow", "Principal": {
        "Service": ["airflow.amazonaws.com", "airflow-env.amazonaws.com"]},
        "Action": "sts:AssumeRole"}),
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": list_bucket},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": read},
        {"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"})
    env = {"Arn": f"arn:aws:airflow:us-east-1:{ACCOUNT}:environment/team",
           "Status": status, "ExecutionRoleArn": execution_role,
           "SourceBucketArn": BUCKET, "DagS3Path": dag_path}
    snap = aws_snap([actor], [execution], [("mwaa_environment", SCOPE, [env], inventory_status)])
    return AwsModel(snap)


def _verdict(model):
    return model.precondition("mwaa_existing_dag_object_execution_role",
                              {TARGET: model.principals[TARGET]}, model.principals[ALICE]).get(TARGET)


def test_exact_named_python_object_reaches_only_environment_role():
    model = _model()
    assert _verdict(model) == ("conditional", "mwaa_existing_dag_object_and_execution_role")
    edges = Evaluator(model, [ENTRY], include_unknown=False).run()
    assert {target for edge in edges if edge.source.id == ALICE for target in edge.targets} == {TARGET}


def test_other_object_role_or_unavailable_environment_does_not_prove_route():
    for change in ({"put": BUCKET + "/other/custom.py"},
                   {"put": BUCKET + "/dags/reports/custom.txt"},
                   {"read": BUCKET + "/other/custom.py"},
                   {"list_bucket": "arn:aws:s3:::other-bucket"},
                   {"execution_role": f"arn:aws:iam::{ACCOUNT}:role/other"},
                   {"status": "DELETING"}):
        assert _verdict(_model(**change)) != (
            "conditional", "mwaa_existing_dag_object_and_execution_role"), change


def test_incomplete_inventory_and_invalid_dag_path_remain_unproved():
    assert _verdict(_model(inventory_status="access_denied"))[0] == "unknown"
    assert _verdict(_model(dag_path="dags/../other"))[0] == "unknown"


def test_current_route_and_previous_catalog_meanings_are_exact():
    current = versioned_catalog.current_binding()
    entries, status = versioned_catalog.lookup_entries([ENTRY["id"]], current)
    assert status == "exact_strict_privesc" and ENTRY["id"] in entries
    old = dict(current,
               manifest_sha256=versioned_catalog.MWAA_DAG_PREVIOUS_MANIFEST,
               effective_tree_sha256=versioned_catalog.MWAA_DAG_PREVIOUS_TREE)
    entries, status = versioned_catalog.lookup_entries(
        [ENTRY["id"], "aws-mwaa-passrole-updateenvironment"], old)
    assert status == "exact_previous_current"
    assert ENTRY["id"] not in entries and "aws-mwaa-passrole-updateenvironment" in entries
