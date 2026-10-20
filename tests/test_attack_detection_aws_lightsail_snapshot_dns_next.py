"""Synthetic derivatives of an owned Lightsail key, snapshot and DNS lab."""
from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-lightsail-actor/run"
INSTANCE = "synthetic-restored"
SNAPSHOT = "synthetic-snapshot"
DOMAIN = "synthetic-lab.invalid"
NAMES = {"DownloadDefaultKeyPair", "GetInstanceSnapshots", "CreateInstancesFromSnapshot",
         "ExportSnapshot", "CreateDomainEntry", "UpdateDomainEntry"}


def event(name, request, response, number):
    return {"eventSource": "lightsail.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall", "managementEvent": True,
            "readOnly": name in {"DownloadDefaultKeyPair", "GetInstanceSnapshots"},
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventID": f"11111111-1111-4111-8111-{number:012d}",
            "eventTime": f"2026-01-01T00:00:{number:02d}Z",
            "userIdentity": {"accountId": ACCOUNT, "arn": ACTOR},
            "requestParameters": request, "responseElements": response}


def operation(resource, kind, status="Succeeded"):
    return {"resourceName": resource, "operationType": kind, "status": status}


def records():
    return [
        event("DownloadDefaultKeyPair", None, {"privateKeyBase64": "synthetic-private-key"}, 1),
        event("GetInstanceSnapshots", None, {"instanceSnapshots": [{"name": SNAPSHOT}]}, 2),
        event("CreateInstancesFromSnapshot", {"instanceSnapshotName": SNAPSHOT,
              "instanceNames": [INSTANCE]},
              {"operations": [operation(INSTANCE, "CreateInstancesFromSnapshot", "Started")]}, 3),
        event("ExportSnapshot", {"sourceSnapshotName": SNAPSHOT},
              {"operations": [operation(SNAPSHOT, "ExportSnapshot", "Started")]}, 4),
        event("CreateDomainEntry", {"domainName": DOMAIN,
              "domainEntry": {"name": "dev." + DOMAIN, "target": "192.0.2.1", "type": "A"}},
              {"operation": operation(DOMAIN, "CreateDomainEntry")}, 5),
        event("UpdateDomainEntry", {"domainName": DOMAIN,
              "domainEntry": {"id": "synthetic-entry", "name": "dev." + DOMAIN,
                              "target": "192.0.2.2", "type": "A"}},
              {"operations": [operation(DOMAIN, "DeleteDomainEntry"),
                              operation(DOMAIN, "CreateDomainEntry")]}, 6),
    ]


def rules():
    return [r for r in load_rules(product="aws")
            if r.selection.get("event.source") == "lightsail.amazonaws.com"
            and r.selection.get("event.name") in NAMES]


def test_six_lightsail_snapshot_dns_routes_match_without_secret_material():
    matches = detect_aws_events(records(), rules())
    assert len(matches) == 6
    assert {d.rule_id for d in matches} == {r.id for r in rules()}
    assert "synthetic-private-key" not in str(matches)
    assert SNAPSHOT not in str([d for d in matches if d.title == "Lightsail instance snapshots enumerated"])


def test_lightsail_snapshot_dns_denials_and_unconfirmed_writes_rejected():
    changes = [
        (0, {"errorCode": "AccessDeniedException"}),
        (1, {"readOnly": False}),
        (2, {"responseElements": {"operations": [operation(INSTANCE, "CreateInstancesFromSnapshot", "Failed")]}}),
        (3, {"requestParameters": {"sourceSnapshotName": "../other"}}),
        (4, {"requestParameters": {"domainName": DOMAIN, "domainEntry": {"name": "other.invalid",
                                                                  "target": "192.0.2.1", "type": "A"}}}),
        (5, {"responseElements": {"operations": [operation(DOMAIN, "CreateDomainEntry", "Failed")]}}),
    ]
    for index, change in changes:
        record = deepcopy(records()[index])
        record.update(change)
        assert not detect_aws_events([record], rules()), index
