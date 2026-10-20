"""Chime Voice Connector signals from synthetic disposable live derivatives."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_chime_voice_batch66_events.json"
IDS = {
    "81109514-dfc2-4ff6-8d9b-25bdf7275e5a",
    "2ffab03c-04a4-41a1-8fd4-090694957d75",
    "acac99cb-818c-4e95-8734-d55a1c289385",
    "12037b5f-bada-4ddd-b58f-acbb631aefb7",
    "978fb51e-3e1d-4304-bfa0-01f5f15f1e43",
    "976a2828-e741-4dae-9c23-c40d2ef1d0bb",
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(rules) == 6
    return rules


def found(rows):
    return detect_aws_events(rows, selected())


def ids(rows):
    return {d.rule_id for d in found(rows)}


def test_six_rules_match_six_live_shaped_voice_control_events():
    rows = events()
    detections = found(rows)
    assert len(rows) == len(detections) == 6
    assert {d.rule_id for d in detections} == IDS
    assert {r["recipientAccountId"] for r in rows} == {"999999999999"}
    assert all(r["eventID"].startswith("synthetic-") for r in rows)
    assert "synthetic-user" not in json.dumps([d.evidence for d in detections])
    assert "<redacted>" not in json.dumps([d.evidence for d in detections])


def test_termination_requires_valid_cidr_accepted_by_service():
    for change in (
        lambda x: x.update(errorCode="BadRequestException"),
        lambda x: x["requestParameters"]["termination"].update(cidrAllowedList=["not-cidr"]),
        lambda x: x["responseElements"]["termination"].update(disabled=True),
        lambda x: x.update(eventSource="chime.amazonaws.com"),
    ):
        rows = events()
        change(rows[0])
        assert "81109514-dfc2-4ff6-8d9b-25bdf7275e5a" not in ids(rows)


def test_credentials_require_success_and_no_password_in_alert():
    for change in (
        lambda x: x.update(errorCode="ForbiddenException"),
        lambda x: x["requestParameters"].update(credentials=[]),
        lambda x: x["requestParameters"]["credentials"][0].pop("password"),
    ):
        rows = events()
        change(rows[1])
        assert "2ffab03c-04a4-41a1-8fd4-090694957d75" not in ids(rows)


def test_routes_and_streaming_require_effective_enabled_response():
    rows = events()
    rows[2]["responseElements"]["origination"]["disabled"] = True
    rows[3]["responseElements"]["streamingConfiguration"]["disabled"] = True
    result = ids(rows)
    assert "acac99cb-818c-4e95-8734-d55a1c289385" not in result
    assert "12037b5f-bada-4ddd-b58f-acbb631aefb7" not in result


def test_logging_only_detects_disabled_settings():
    rows = events()
    logging_ids = {
        "978fb51e-3e1d-4304-bfa0-01f5f15f1e43",
        "976a2828-e741-4dae-9c23-c40d2ef1d0bb",
    }
    assert not logging_ids.intersection(ids(rows[:5]))
    assert sum(d.rule_id in logging_ids for d in found(rows)) == 2
    rows[5]["responseElements"]["loggingConfiguration"]["enableSIPLogs"] = True
    assert "978fb51e-3e1d-4304-bfa0-01f5f15f1e43" not in ids(rows)
