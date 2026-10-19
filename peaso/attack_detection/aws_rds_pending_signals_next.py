"""Narrow RDS control-plane signals awaiting live canary validation."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

_SOURCE = re.compile(
    r"^arn:aws(?:-us-gov|-cn)?:rds:[a-z0-9-]+:(\d{12}):"
    r"(snapshot|cluster-snapshot|cluster|db):[A-Za-z0-9-]+$"
)
_ROLE = re.compile(r"^arn:aws(?:-us-gov|-cn)?:iam::(\d{12}):role/[A-Za-z0-9+=,.@_/-]+$")
_TARGET = re.compile(r"^arn:aws(?:-us-gov|-cn)?:redshift(?:-serverless)?:[a-z0-9-]+:\d{12}:.+$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_DB = re.compile(r"^arn:aws(?:-us-gov|-cn)?:rds:([a-z0-9-]+):(\d{12}):db:[A-Za-z0-9-]+$")
_NAMES = {
    "ModifyDBClusterSnapshotAttribute", "StartExportTask", "CreateIntegration",
    "CreateBlueGreenDeployment", "StartDBInstanceAutomatedBackupsReplication",
    "CreateDBInstance", "StopDBCluster",
}


def normalize_aws_rds_pending_signals(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report accepted writes; later state and data movement require separate evidence."""
    name = record.get("eventName")
    account = record.get("recipientAccountId")
    request = record.get("requestParameters")
    identity = record.get("userIdentity")
    if (record.get("eventSource") != "rds.amazonaws.com" or name not in _NAMES
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or not isinstance(identity.get("arn"), str)):
        return None

    target = None
    flag = None
    extra: dict[str, Any] = {}
    if name == "ModifyDBClusterSnapshotAttribute":
        target = request.get("dBClusterSnapshotIdentifier") or request.get("DBClusterSnapshotIdentifier")
        values = request.get("valuesToAdd")
        if (not isinstance(target, str) or not target or request.get("attributeName") != "restore"
                or not isinstance(values, list) or not all(isinstance(v, str) for v in values)):
            return None
        if "all" in values:
            flag = "rds_cluster_snapshot_public_restore_added"
        elif any(re.fullmatch(r"\d{12}", v) and v != account for v in values):
            flag = "rds_cluster_snapshot_external_restore_added"
        else:
            return None
    elif name == "StartExportTask":
        source = request.get("sourceArn")
        role = request.get("iamRoleArn")
        bucket = request.get("s3BucketName")
        task = request.get("exportTaskIdentifier")
        source_match = _SOURCE.fullmatch(source) if isinstance(source, str) else None
        role_match = _ROLE.fullmatch(role) if isinstance(role, str) else None
        if (not source_match or source_match.group(1) != account
                or source_match.group(2) not in {"snapshot", "cluster-snapshot", "cluster"}
                or not role_match or role_match.group(1) != account
                or not isinstance(bucket, str) or _BUCKET.fullmatch(bucket) is None
                or not isinstance(task, str) or not task
                or not isinstance(request.get("kmsKeyId"), str) or not request["kmsKeyId"]):
            return None
        target = source
        flag = "rds_database_export_requested"
        extra = {"request.export_bucket": bucket, "request.export_role": role,
                 "request.export_task_id": task}
    elif name == "CreateIntegration":
        source = request.get("sourceArn")
        destination = request.get("targetArn")
        integration = request.get("integrationName")
        source_match = _SOURCE.fullmatch(source) if isinstance(source, str) else None
        if (not source_match or source_match.group(1) != account
                or source_match.group(2) not in {"cluster", "db"}
                or not isinstance(destination, str) or _TARGET.fullmatch(destination) is None
                or not isinstance(integration, str) or not integration):
            return None
        target = source
        flag = "rds_zero_etl_integration_requested"
        extra = {"request.integration_target": destination,
                 "request.integration_name": integration}
    elif name == "CreateBlueGreenDeployment":
        source = request.get("source")
        deployment = request.get("blueGreenDeploymentName")
        match = _SOURCE.fullmatch(source) if isinstance(source, str) else None
        if (not match or match.group(1) != account or match.group(2) not in {"db", "cluster"}
                or not isinstance(deployment, str) or not deployment):
            return None
        target = source
        flag = "rds_blue_green_deployment_requested"
        extra = {"request.blue_green_deployment_name": deployment}
    elif name == "StartDBInstanceAutomatedBackupsReplication":
        source = request.get("sourceDBInstanceArn")
        match = _DB.fullmatch(source) if isinstance(source, str) else None
        region = record.get("awsRegion")
        if (not match or match.group(2) != account or not isinstance(region, str)
                or match.group(1) == region):
            return None
        target = source
        flag = "rds_cross_region_backup_replication_requested"
        extra = {"request.replication_destination_region": region}
    elif name == "CreateDBInstance":
        target = request.get("dBInstanceIdentifier")
        cluster = request.get("dBClusterIdentifier")
        engine = request.get("engine")
        if (not isinstance(target, str) or not target
                or not isinstance(cluster, str) or not cluster
                or not isinstance(engine, str) or not engine.startswith("aurora")
                or request.get("publiclyAccessible") is not True):
            return None
        flag = "rds_aurora_public_member_requested"
        extra = {"request.cluster_id": cluster}
    else:
        target = request.get("dBClusterIdentifier")
        if not isinstance(target, str) or not target:
            return None
        flag = "rds_cluster_stop_requested"
    return {
        "cloud.provider": "aws", "event.source": "rds.amazonaws.com",
        "event.name": name, "event.outcome": "success", "event.id": record.get("eventID"),
        "event.time": record.get("eventTime"), "account.id": account,
        "actor.id": identity["arn"], "target.id": target,
        f"request.{flag}": True, **extra,
    }
