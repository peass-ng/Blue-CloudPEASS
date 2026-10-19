"""Indefinite EventBridge archive creation and update require accepted ARN."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id="archive", title="Indefinite archive", level="medium", description="archive",
    technique_id="aws-eventbridge-indefinite-archive", product="aws",
    selection={"event.source": "events.amazonaws.com", "event.outcome": "success",
               "request.eventbridge_indefinite_archive": True})


def test_indefinite_archive_and_negative_variants() -> None:
    archive = "peasso-detect-archive-bda4b68eba"
    arn = f"arn:aws:events:us-east-1:947247140022:archive/{archive}"
    event = {"eventSource": "events.amazonaws.com", "eventName": "CreateArchive",
        "eventCategory": "Management", "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": False, "awsRegion": "us-east-1", "recipientAccountId": "947247140022",
        "requestParameters": {"archiveName": archive, "retentionDays": 0,
            "eventSourceArn": "arn:aws:events:us-east-1:947247140022:event-bus/peasso-detect-archive-bus-bda4b68eba"},
        "responseElements": {"archiveArn": arn, "state": "ENABLED"}}
    def hits(value: dict) -> list[str]:
        return [x.technique_id for x in detect_aws_events([value], [RULE])]
    assert hits(event) == [RULE.technique_id]
    default = deepcopy(event)
    default["requestParameters"].pop("retentionDays")
    assert hits(default) == [RULE.technique_id]
    update = deepcopy(event)
    update["eventName"] = "UpdateArchive"
    update["requestParameters"].pop("eventSourceArn")
    assert hits(update) == [RULE.technique_id]
    for change in ("one_day", "failed", "wrong_arn", "foreign_bus", "delete", "missing_retention_update"):
        item = deepcopy(update if change == "missing_retention_update" else event)
        if change == "one_day": item["requestParameters"]["retentionDays"] = 1
        if change == "failed": item["errorCode"] = "AccessDeniedException"
        if change == "wrong_arn": item["responseElements"]["archiveArn"] += "-other"
        if change == "foreign_bus": item["requestParameters"]["eventSourceArn"] = "arn:aws:events:us-east-1:202533532952:event-bus/foreign"
        if change == "delete": item["eventName"] = "DeleteArchive"
        if change == "missing_retention_update": item["requestParameters"].pop("retentionDays")
        assert hits(item) == [], change
