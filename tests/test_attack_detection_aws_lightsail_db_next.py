"""Synthetic derivatives of an owned Lightsail database and snapshot lab."""
from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-db-actor/run"
SOURCE = "synthetic-db-source"
RESTORED = "synthetic-db-restored"
SNAPSHOT = "synthetic-db-snapshot"
NAMES = {"GetRelationalDatabaseMasterUserPassword", "UpdateRelationalDatabase",
         "GetRelationalDatabaseSnapshots", "CreateRelationalDatabaseFromSnapshot"}


def event(name, request, response, number):
    return {"eventSource": "lightsail.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall", "managementEvent": True,
            "readOnly": name.startswith("Get"), "recipientAccountId": ACCOUNT,
            "awsRegion": "us-east-1", "eventID": f"11111111-1111-4111-8111-{number:012d}",
            "eventTime": f"2026-01-01T00:00:{number:02d}Z",
            "userIdentity": {"accountId": ACCOUNT, "arn": ACTOR},
            "requestParameters": request, "responseElements": response}


def operations(resource, kind, status="Succeeded"):
    return {"operations": [{"resourceName": resource, "operationType": kind, "status": status}]}


def records():
    return [
        event("GetRelationalDatabaseMasterUserPassword",
              {"relationalDatabaseName": SOURCE, "passwordVersion": "CURRENT"},
              {"masterUserPassword": "synthetic-private-password"}, 1),
        event("UpdateRelationalDatabase",
              {"relationalDatabaseName": SOURCE, "publiclyAccessible": True, "applyImmediately": True},
              operations(SOURCE, "UpdateRelationalDatabase"), 2),
        event("GetRelationalDatabaseSnapshots", None,
              {"relationalDatabaseSnapshots": [{"name": SNAPSHOT}]}, 3),
        event("UpdateRelationalDatabase",
              {"relationalDatabaseName": SOURCE, "applyImmediately": True},
              operations(SOURCE, "UpdateRelationalDatabase", "Started"), 4),
        event("GetRelationalDatabaseMasterUserPassword",
              {"relationalDatabaseName": SOURCE, "passwordVersion": "PREVIOUS"},
              {"masterUserPassword": "synthetic-previous-password"}, 5),
        event("CreateRelationalDatabaseFromSnapshot",
              {"relationalDatabaseName": RESTORED, "relationalDatabaseSnapshotName": SNAPSHOT,
               "relationalDatabaseBundleId": "micro_2_0", "publiclyAccessible": True},
              operations(RESTORED, "CreateRelationalDatabaseFromSnapshot", "Started"), 6),
    ]


def rules():
    return [r for r in load_rules(product="aws")
            if r.selection.get("event.source") == "lightsail.amazonaws.com"
            and r.selection.get("event.name") in NAMES
            and r.title.startswith("Lightsail database")]


def test_six_lightsail_database_routes_match_without_password_material():
    detections = detect_aws_events(records(), rules())
    assert len(detections) == len(rules()) == 6
    assert {d.rule_id for d in detections} == {r.id for r in rules()}
    assert "synthetic-private-password" not in str(detections)
    assert "synthetic-previous-password" not in str(detections)
    assert SNAPSHOT not in str([d for d in detections if d.title == "Lightsail database snapshots enumerated"])


def test_lightsail_database_denials_private_updates_and_failed_restores_rejected():
    changes = [
        (0, {"errorCode": "AccessDeniedException"}),
        (1, {"requestParameters": {"relationalDatabaseName": SOURCE, "publiclyAccessible": False}}),
        (2, {"readOnly": False}),
        (3, {"responseElements": operations(SOURCE, "UpdateRelationalDatabase", "Failed")}),
        (4, {"requestParameters": {"relationalDatabaseName": SOURCE, "passwordVersion": "PENDING"}}),
        (5, {"responseElements": operations(RESTORED, "CreateRelationalDatabaseFromSnapshot", "Failed")}),
    ]
    for index, change in changes:
        record = deepcopy(records()[index])
        record.update(change)
        assert not detect_aws_events([record], rules()), index
