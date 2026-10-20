"""Synthetic derivatives of disposable Chime media pipeline events."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_chime_media_batch68_events.json"
IDS = {
    "9966c00b-cd8d-40cd-bb6b-b0c6bb4246b5",
    "e333a0c1-5818-427e-930a-e60183fcdee8",
    "7a604427-7c14-4c2d-a8da-c20e82a1871e",
    "8ccfecb8-37fa-42ee-b8ef-0d6e024ed3fb",
    "4c285197-5f7b-49b7-94a4-3e4c3d9bd4ff",
    "7d512ab5-e3c0-4c07-9ffd-d517e278db1f",
    "81e7632b-7c5c-4bdf-aa0f-f0fca5641adc",
}
LIVE_READ = "4c285197-5f7b-49b7-94a4-3e4c3d9bd4ff"


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def found(rows):
    selected = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(selected) == 7
    return detect_aws_events(rows, selected)


def ids(rows):
    return {d.rule_id for d in found(rows)}


def test_seven_rules_match_live_shaped_control_events():
    rows = events()
    detections = found(rows)
    assert len(rows) == 7 and len(detections) == 8
    assert {d.rule_id for d in detections} == IDS
    assert sum(d.rule_id == LIVE_READ for d in detections) == 1
    assert all(e["eventID"].startswith("synthetic-") for e in rows)
    assert {e["recipientAccountId"] for e in rows} == {"999999999999"}
    assert "HIDDEN_DUE_TO_SECURITY_REASONS" not in json.dumps([d.evidence for d in detections])


def test_live_read_requires_exact_prior_pipeline_id():
    rows = events()
    rows[3]["requestParameters"]["mediaPipelineId"] = (
        "44444444-4444-4444-8444-444444444444"
    )
    assert LIVE_READ not in ids(rows)
    rows = events()
    rows.pop(1)
    assert LIVE_READ not in ids(rows)


def test_live_read_requires_matching_account_region_and_window():
    for change in (
        lambda rows: rows[3].update(recipientAccountId="888888888888",
                                    userIdentity={"accountId": "888888888888", "arn": "arn:aws:iam::888888888888:user/synthetic"}),
        lambda rows: rows[3].update(awsRegion="us-west-2"),
        lambda rows: rows[3].update(eventTime="2026-10-22T20:03:00Z"),
        lambda rows: rows[3].update(errorCode="NotFoundException"),
    ):
        rows = events()
        change(rows)
        assert LIVE_READ not in ids(rows)


def test_rejected_capture_and_unaccepted_live_sink_do_not_match():
    rows = events()
    rows[0]["errorCode"] = "BadRequestException"
    rows[1]["responseElements"]["mediaLiveConnectorPipeline"]["sinks"] = []
    matches = ids(rows)
    assert "9966c00b-cd8d-40cd-bb6b-b0c6bb4246b5" not in matches
    assert "e333a0c1-5818-427e-930a-e60183fcdee8" not in matches
    assert LIVE_READ not in matches


def test_failed_read_and_wrong_event_source_do_not_match():
    rows = events()
    rows[2]["errorCode"] = "NotFoundException"
    rows[4]["eventSource"] = "chime.amazonaws.com"
    matches = ids(rows)
    assert "8ccfecb8-37fa-42ee-b8ef-0d6e024ed3fb" not in matches
    assert sum(d.rule_id == "7a604427-7c14-4c2d-a8da-c20e82a1871e" for d in found(rows)) == 1
