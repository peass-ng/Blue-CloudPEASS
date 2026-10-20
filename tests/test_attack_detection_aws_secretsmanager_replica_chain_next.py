"""Synthetic derivatives of batch89 cross-Region replica management events."""

import json

from peaso.attack_detection import detect_aws_events


ACCOUNT = "999999999999"
PRIMARY = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:synthetic-replica-abc123"
REPLICA = f"arn:aws:secretsmanager:us-west-2:{ACCOUNT}:secret:synthetic-replica-abc123"
KEY = f"arn:aws:kms:us-west-2:{ACCOUNT}:key/00000000-0000-4000-8000-000000000001"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-reader"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-admin/session"
IDS = {
    "aws-secretsmanager-custom-kms-replication",
    "aws-secretsmanager-scoped-role-read-grant",
    "aws-secretsmanager-promoted-replica-role-granted",
    "aws-secretsmanager-cross-region-cmk-replica-read",
}


def event(name, target, request, *, region, time, event_id):
    return {
        "eventSource": "secretsmanager.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": name == "GetSecretValue",
        "recipientAccountId": ACCOUNT, "awsRegion": region,
        "eventTime": time, "eventID": event_id,
        "userIdentity": {"type": "IAMUser", "arn": ACTOR},
        "requestParameters": {"secretId": target, **request},
        "responseElements": None if name == "GetSecretValue" else {"arn": target},
    }


def sequence():
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": ROLE},
         "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}
    replicate = event("ReplicateSecretToRegions", PRIMARY,
                      {"addReplicaRegions": [{"region": "us-west-2", "kmsKeyId": KEY}],
                       "forceOverwriteReplicaSecret": False},
                      region="us-east-1", time="2026-10-21T00:00:00Z", event_id="synthetic-replicate")
    promote = event("StopReplicationToReplica", REPLICA, {},
                    region="us-west-2", time="2026-10-21T00:00:05Z", event_id="synthetic-promote")
    grant = event("PutResourcePolicy", REPLICA,
                  {"resourcePolicy": json.dumps(policy), "blockPublicPolicy": True},
                  region="us-west-2", time="2026-10-21T00:00:10Z", event_id="synthetic-grant")
    read = event("GetSecretValue", REPLICA, {},
                 region="us-west-2", time="2026-10-21T00:00:15Z", event_id="synthetic-read")
    read["userIdentity"] = {"type": "AssumedRole", "arn":
                            f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-reader/session",
                            "sessionContext": {"sessionIssuer": {"arn": ROLE}}}
    return [replicate, promote, grant, read]


def hits(events):
    return {hit.technique_id for hit in detect_aws_events(events)
            if hit.technique_id in IDS}


def test_cross_region_sequence_has_four_distinct_signals():
    records = sequence()
    assert hits(records) == IDS
    assert hits(records[:1]) == {"aws-secretsmanager-custom-kms-replication"}
    assert hits(records[1:3]) == {"aws-secretsmanager-scoped-role-read-grant",
                                  "aws-secretsmanager-promoted-replica-role-granted"}
    assert hits(records[2:]) == {"aws-secretsmanager-scoped-role-read-grant"}


def test_chain_requires_matching_secret_region_role_and_order():
    for index, mutation in (
        (0, lambda x: x["requestParameters"]["addReplicaRegions"][0].update(kmsKeyId="alias/aws/secretsmanager")),
        (0, lambda x: x["requestParameters"]["addReplicaRegions"][0].update(region="eu-west-1")),
        (1, lambda x: x.update(eventTime="2026-10-21T00:40:05Z")),
        (2, lambda x: x.update(eventTime="2026-10-21T00:40:10Z")),
        (3, lambda x: x["userIdentity"]["sessionContext"]["sessionIssuer"].update(arn=f"arn:aws:iam::{ACCOUNT}:role/other")),
        (3, lambda x: x.update(errorCode="AccessDeniedException")),
    ):
        records = sequence()
        mutation(records[index])
        assert "aws-secretsmanager-cross-region-cmk-replica-read" not in hits(records)


def test_policy_grant_rejects_public_or_conditioned_or_failed_change():
    for mutation in (
        lambda x: x["requestParameters"].update(resourcePolicy=json.dumps({"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]})),
        lambda x: x["requestParameters"].update(resourcePolicy=json.dumps({"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": ROLE}, "Action": "secretsmanager:GetSecretValue",
             "Resource": "*", "Condition": {"StringEquals": {"aws:PrincipalAccount": ACCOUNT}}}]})),
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(recipientAccountId="111111111111"),
    ):
        records = sequence()
        mutation(records[2])
        assert "aws-secretsmanager-scoped-role-read-grant" not in hits(records)
        assert "aws-secretsmanager-promoted-replica-role-granted" not in hits(records)


def test_existing_promotion_rule_still_detects_destination_event():
    names = {hit.technique_id for hit in detect_aws_events([sequence()[1]])}
    assert "aws-secretsmanager-replica-promoted" in names
