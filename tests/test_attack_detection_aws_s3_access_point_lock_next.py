"""Access Point and Object Lock detections from synthetic CloudTrail derivatives."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_s3_access_point_lock_batch63_events.json"
IDS = {
    "7a285926-854e-45a0-b742-cdf99075b021",
    "50dcdd2b-b0fc-44e0-a93b-1fecff99e9c0",
    "b562fdfb-d7a4-4633-baaf-78d250246415",
    "95259b77-bb55-4cb2-9bc7-ec41be17ec87",
    "291951fd-0550-4279-a8d9-170151459d34",
    "5df2e422-8e15-4320-82fa-f87e69471497",
    "a309b59e-25bc-4b50-9d70-adf92cc86b35",
    "6998d3d7-da0a-42b0-ae96-2ef0a2a5d17c",
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(rules) == 8
    return rules


def found(rows):
    return detect_aws_events(rows, selected())


def ids(rows):
    return {x.rule_id for x in found(rows)}


def test_eight_rule_ids_match_nine_real_shaped_signals():
    rows = events()
    detections = found(rows)
    assert len(rows) == 10
    assert len(detections) == 9
    assert {x.rule_id for x in detections} == IDS
    assert {x["recipientAccountId"] for x in rows} == {"999999999999"}
    assert all(x["eventID"].startswith("synthetic-") for x in rows)
    assert sum(x.rule_id == "291951fd-0550-4279-a8d9-170151459d34"
               for x in detections) == 2


def test_access_point_read_requires_matching_resource_and_success():
    for change in (
        lambda x: x["requestParameters"].pop("accessPointName"),
        lambda x: x.update(resources=x["resources"][:-1]),
        lambda x: x["requestParameters"].update(accountId="888888888888"),
        lambda x: x.update(errorCode="AccessDenied"),
    ):
        rows = events()
        change(rows[4])
        result = ids(rows)
        assert "95259b77-bb55-4cb2-9bc7-ec41be17ec87" not in result
        assert "6998d3d7-da0a-42b0-ae96-2ef0a2a5d17c" not in result


def test_direct_denial_correlation_requires_same_actor_object_and_window():
    for change in (
        lambda x: x.update(errorCode=None),
        lambda x: x["userIdentity"].update(arn="arn:aws:iam::999999999999:user/other"),
        lambda x: x["requestParameters"].update(key="synthetic/different.txt"),
        lambda x: x.update(eventTime="2026-10-20T18:00:00Z"),
    ):
        rows = events()
        change(rows[3])
        assert "6998d3d7-da0a-42b0-ae96-2ef0a2a5d17c" not in ids(rows)
        assert "95259b77-bb55-4cb2-9bc7-ec41be17ec87" in ids(rows)


def test_delegation_requires_own_account_and_object_permission():
    for change in (
        lambda x: x["requestParameters"]["bucketPolicy"]["Statement"][0]
            ["Condition"]["StringEquals"].update({"s3:DataAccessPointAccount": "888888888888"}),
        lambda x: x["requestParameters"]["bucketPolicy"]["Statement"][0]
            .update(Action="s3:ListBucket"),
        lambda x: x.update(resources=[]),
    ):
        rows = events()
        change(rows[1])
        assert "50dcdd2b-b0fc-44e0-a93b-1fecff99e9c0" not in ids(rows)


def test_object_lock_events_require_success_version_and_explicit_default_rule():
    rows = events()
    rows[5]["errorCode"] = "AccessDenied"
    rows[6]["requestParameters"]["versionId"] = "null"
    rows[7]["requestParameters"].pop("versionId")
    rows[8]["requestParameters"]["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]["Mode"] = "COMPLIANCE"
    result = ids(rows)
    assert "291951fd-0550-4279-a8d9-170151459d34" not in result
    assert "5df2e422-8e15-4320-82fa-f87e69471497" not in result
    assert "a309b59e-25bc-4b50-9d70-adf92cc86b35" not in result
