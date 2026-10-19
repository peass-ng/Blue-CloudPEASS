"""Synthetic guards for RDS signals awaiting live canary validation."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "222233334444"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/example-operator"
SOURCE = f"arn:aws:rds:us-east-1:{ACCOUNT}:snapshot:example-snapshot"
CLUSTER = f"arn:aws:rds:us-east-1:{ACCOUNT}:cluster:example-cluster"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/example-export"
TARGET = f"arn:aws:redshift-serverless:us-east-1:{ACCOUNT}:namespace/example-namespace"
FLAGS = {
    "ModifyDBClusterSnapshotAttribute": "rds_cluster_snapshot_public_restore_added",
    "StartExportTask": "rds_database_export_requested",
    "CreateIntegration": "rds_zero_etl_integration_requested",
    "CreateBlueGreenDeployment": "rds_blue_green_deployment_requested",
    "StartDBInstanceAutomatedBackupsReplication": "rds_cross_region_backup_replication_requested",
    "CreateDBInstance": "rds_aurora_public_member_requested",
    "StopDBCluster": "rds_cluster_stop_requested",
}
RULES = tuple(
    Rule(id=flag, title=flag, description=flag, level="medium",
         technique_id=flag, product="aws",
         selection={"event.name": event, "event.outcome": "success", f"request.{flag}": True})
    for event, flag in FLAGS.items()
) + (
    Rule(id="rds_cluster_snapshot_external_restore_added", title="external", description="external",
         level="high", technique_id="rds_cluster_snapshot_external_restore_added", product="aws",
         selection={"event.name": "ModifyDBClusterSnapshotAttribute", "event.outcome": "success",
                    "request.rds_cluster_snapshot_external_restore_added": True}),
)


def event(name: str, request: dict) -> dict:
    return {"eventSource": "rds.amazonaws.com", "eventName": name,
            "eventType": "AwsApiCall", "eventCategory": "Management",
            "managementEvent": True, "readOnly": False, "recipientAccountId": ACCOUNT,
            "userIdentity": {"type": "IAMUser", "arn": ACTOR},
            "eventID": "synthetic-rds-event", "eventTime": "2026-10-19T12:00:00Z",
            "requestParameters": request, "responseElements": None}


def hits(record: dict) -> list[str]:
    return [h.rule_id for h in detect_aws_events([record], RULES)]


def test_cluster_snapshot_public_and_foreign_account_are_distinct() -> None:
    item = event("ModifyDBClusterSnapshotAttribute", {
        "dBClusterSnapshotIdentifier": "example-snapshot", "attributeName": "restore",
        "valuesToAdd": ["all"], "valuesToRemove": [],
    })
    assert hits(item) == ["rds_cluster_snapshot_public_restore_added"]
    item["requestParameters"]["valuesToAdd"] = ["999999999999"]
    assert hits(item) == ["rds_cluster_snapshot_external_restore_added"]
    item["requestParameters"]["valuesToAdd"] = [ACCOUNT]
    assert hits(item) == []
    item["requestParameters"]["valuesToAdd"] = []
    item["requestParameters"]["valuesToRemove"] = ["all"]
    assert hits(item) == []


def test_snapshot_export_requires_source_bucket_role_kms_and_accepted_call() -> None:
    item = event("StartExportTask", {
        "exportTaskIdentifier": "example-export", "sourceArn": SOURCE,
        "s3BucketName": "example-export-bucket", "iamRoleArn": ROLE,
        "kmsKeyId": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555",
    })
    assert hits(item) == ["rds_database_export_requested"]
    live_cluster = deepcopy(item)
    live_cluster["requestParameters"]["sourceArn"] = CLUSTER
    assert hits(live_cluster) == ["rds_database_export_requested"]
    for change in (
        lambda x: x.update(errorCode="AccessDenied"),
        lambda x: x.update(eventCategory="Data"),
        lambda x: x["requestParameters"].update(sourceArn=SOURCE.replace(ACCOUNT, "999999999999")),
        lambda x: x["requestParameters"].update(sourceArn=f"arn:aws:rds:us-east-1:{ACCOUNT}:db:example-db"),
        lambda x: x["requestParameters"].update(iamRoleArn=ROLE.replace(ACCOUNT, "999999999999")),
        lambda x: x["requestParameters"].update(s3BucketName=""),
        lambda x: x["requestParameters"].pop("kmsKeyId"),
    ):
        changed = deepcopy(item)
        change(changed)
        assert hits(changed) == []


def test_zero_etl_creation_requires_cluster_and_redshift_destination() -> None:
    item = event("CreateIntegration", {
        "sourceArn": CLUSTER, "targetArn": TARGET, "integrationName": "example-integration"})
    assert hits(item) == ["rds_zero_etl_integration_requested"]
    db_source = deepcopy(item)
    db_source["requestParameters"]["sourceArn"] = f"arn:aws:rds:us-east-1:{ACCOUNT}:db:example-db"
    assert hits(db_source) == ["rds_zero_etl_integration_requested"]
    for change in (
        lambda x: x["requestParameters"].update(sourceArn=SOURCE),
        lambda x: x["requestParameters"].update(targetArn=f"arn:aws:s3:::{ACCOUNT}"),
        lambda x: x.update(errorCode="InvalidParameterValue"),
        lambda x: x.update(readOnly=True),
    ):
        changed = deepcopy(item)
        change(changed)
        assert hits(changed) == []


def test_blue_green_clone_request_requires_local_source() -> None:
    item = event("CreateBlueGreenDeployment", {
        "source": CLUSTER, "blueGreenDeploymentName": "example-deployment"})
    assert hits(item) == ["rds_blue_green_deployment_requested"]
    for source in (SOURCE, CLUSTER.replace(ACCOUNT, "999999999999"), "example-cluster"):
        changed = deepcopy(item)
        changed["requestParameters"]["source"] = source
        assert hits(changed) == []
    item["errorCode"] = "InvalidParameterValue"
    assert hits(item) == []


def test_backup_replication_requires_distinct_destination_region() -> None:
    source = f"arn:aws:rds:us-west-2:{ACCOUNT}:db:example-db"
    item = event("StartDBInstanceAutomatedBackupsReplication", {
        "sourceDBInstanceArn": source, "backupRetentionPeriod": 1})
    item["awsRegion"] = "us-east-1"
    assert hits(item) == ["rds_cross_region_backup_replication_requested"]
    for change in (
        lambda x: x.update(awsRegion="us-west-2"),
        lambda x: x["requestParameters"].update(sourceDBInstanceArn=source.replace(ACCOUNT, "999999999999")),
        lambda x: x.update(errorCode="AccessDenied"),
    ):
        changed = deepcopy(item)
        change(changed)
        assert hits(changed) == []


def test_public_aurora_member_and_cluster_stop_are_distinct() -> None:
    member = event("CreateDBInstance", {
        "dBInstanceIdentifier": "example-member", "dBClusterIdentifier": "example-cluster",
        "engine": "aurora-postgresql", "publiclyAccessible": True})
    assert hits(member) == ["rds_aurora_public_member_requested"]
    for change in (
        lambda x: x["requestParameters"].update(publiclyAccessible=False),
        lambda x: x["requestParameters"].pop("dBClusterIdentifier"),
        lambda x: x["requestParameters"].update(engine="postgres"),
    ):
        changed = deepcopy(member)
        change(changed)
        assert hits(changed) == []
    stopped = event("StopDBCluster", {"dBClusterIdentifier": "example-cluster"})
    assert hits(stopped) == ["rds_cluster_stop_requested"]
    stopped["errorCode"] = "InvalidDBClusterStateFault"
    assert hits(stopped) == []
