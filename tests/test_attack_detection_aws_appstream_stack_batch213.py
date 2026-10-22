"""AppStream client transfer changes require accepted request and response settings."""

from __future__ import annotations

import copy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
SETTINGS = [
    {"action": "CLIPBOARD_COPY_FROM_LOCAL_DEVICE", "permission": "ENABLED"},
    {"action": "CLIPBOARD_COPY_TO_LOCAL_DEVICE", "permission": "ENABLED"},
    {"action": "FILE_UPLOAD", "permission": "ENABLED"},
    {"action": "FILE_DOWNLOAD", "permission": "ENABLED"},
    {"action": "PRINTING_TO_LOCAL_DEVICE", "permission": "ENABLED"},
]
EVENT = {
    "eventSource": "appstream.amazonaws.com", "eventName": "UpdateStack",
    "eventType": "AwsApiCall", "eventCategory": "Management",
    "managementEvent": True, "readOnly": False,
    "eventID": "synthetic-update", "eventTime": "2026-10-22T00:00:00Z",
    "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
    "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
    "requestParameters": {"name": "synthetic-stack", "userSettings": SETTINGS},
    "responseElements": {"stack": {"name": "synthetic-stack", "userSettings": SETTINGS}},
}
RULES = (
    Rule(id="egress", title="egress", description="egress", level="medium",
         technique_id="egress", product="aws", selection={
             "event.source": "appstream.amazonaws.com", "event.name": "UpdateStack",
             "event.outcome": "success", "request.appstream_client_egress_enabled": True,
         }),
    Rule(id="ingress", title="ingress", description="ingress", level="medium",
         technique_id="ingress", product="aws", selection={
             "event.source": "appstream.amazonaws.com", "event.name": "UpdateStack",
             "event.outcome": "success", "request.appstream_client_ingress_enabled": True,
         }),
)


def _hits(events):
    return detect_aws_events(events, RULES)


def test_all_client_transfer_channels_enabled_hashes_stack():
    hits = _hits([EVENT])
    assert {hit.technique_id for hit in hits} == {"egress", "ingress"}
    assert all(hit.target_id.startswith("sha256:") for hit in hits)
    assert all("synthetic-stack" not in str(hit) for hit in hits)


def test_egress_and_ingress_are_independent():
    for actions, expected in (
        ({"FILE_DOWNLOAD"}, {"egress"}),
        ({"FILE_UPLOAD"}, {"ingress"}),
    ):
        event = copy.deepcopy(EVENT)
        event["requestParameters"]["userSettings"] = [x for x in SETTINGS if x["action"] in actions]
        assert {hit.technique_id for hit in _hits([event])} == expected


def test_denied_unconfirmed_and_mismatched_updates_are_rejected():
    for change in (
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e.update(eventCategory="Data"),
        lambda e: e.update(readOnly=True),
        lambda e: e["responseElements"]["stack"].update(name="other"),
        lambda e: e["responseElements"]["stack"].update(userSettings=[]),
        lambda e: e["requestParameters"].update(userSettings=[]),
        lambda e: e.update(eventSource="iam.amazonaws.com"),
    ):
        event = copy.deepcopy(EVENT)
        change(event)
        assert not _hits([event])


def test_disabled_and_conflicting_settings_do_not_match():
    event = copy.deepcopy(EVENT)
    for item in event["requestParameters"]["userSettings"]:
        item["permission"] = "DISABLED"
    assert not _hits([event])
    event = copy.deepcopy(EVENT)
    event["requestParameters"]["userSettings"].append(
        {"action": "FILE_DOWNLOAD", "permission": "DISABLED"})
    assert not _hits([event])
