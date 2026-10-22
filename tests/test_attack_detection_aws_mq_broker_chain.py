"""Synthetic derivatives of a disposable ActiveMQ control-plane chain."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection.aws_mq_broker_chain import correlate_aws_mq_broker_chain
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"


def event(name, request, response, offset, event_id):
    stamp = datetime(2026, 10, 22, 12, tzinfo=timezone.utc) + timedelta(seconds=offset)
    return {"eventSource": "amazonmq.amazonaws.com", "eventName": name,
            "eventType": "AwsApiCall", "eventCategory": "Management",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-2",
            "eventTime": stamp.isoformat(), "eventID": event_id,
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": ACTOR},
            "requestParameters": request, "responseElements": response}


def chain():
    configuration = event("UpdateConfiguration",
                          {"configuration-id": "synthetic-configuration", "data": "***"},
                          {"id": "synthetic-configuration", "latestRevision": {"revision": 2}},
                          0, "synthetic-revision")
    broker = event("UpdateBroker",
                   {"broker-id": "synthetic-broker",
                    "configuration": {"id": "synthetic-configuration", "revision": 2}},
                   {"brokerId": "synthetic-broker",
                    "configuration": {"id": "synthetic-configuration", "revision": 2}},
                   1, "synthetic-attachment")
    user = event("CreateUser",
                 {"broker-id": "synthetic-broker", "username": "synthetic-user",
                  "groups": ["synthetic-operators"], "consoleAccess": True,
                  "password": "***"},
                 None, 2, "synthetic-event-three")
    return [configuration, broker, user]


def test_accepted_chain_correlates_without_exposing_request_material():
    rows = chain()
    result = correlate_aws_mq_broker_chain(rows)
    assert len(result) == 1
    assert result[0]["request.mq_configuration_user_chain"] is True
    assert result[0]["event.name"] == "CreateUser"
    assert "synthetic-user" not in str(result)
    assert "synthetic-configuration" not in str(result)


def test_user_update_and_same_second_cloudtrail_times():
    rows = chain()
    rows[2]["eventName"] = "UpdateUser"
    rows[1]["eventTime"] = rows[0]["eventTime"]
    rows[2]["eventTime"] = rows[0]["eventTime"]
    assert len(correlate_aws_mq_broker_chain(rows[::-1])) == 1


def test_chain_rejects_mismatched_or_failed_operations():
    changes = (
        lambda r: r[1]["requestParameters"]["configuration"].update(revision=3),
        lambda r: r[1]["responseElements"]["configuration"].update(revision=3),
        lambda r: r[2]["requestParameters"].update({"broker-id": "other-broker"}),
        lambda r: r[2]["userIdentity"].update(arn=f"arn:aws:iam::{ACCOUNT}:user/other"),
        lambda r: r[2]["userIdentity"].update(accountId="888888888888"),
        lambda r: r[0].update(errorCode="AccessDeniedException"),
        lambda r: r[1].update(readOnly=True),
        lambda r: r[2]["requestParameters"].update(groups=[]),
        lambda r: r[2].update(eventTime="2026-10-22T13:02:00+00:00"),
        lambda r: r[2].update(eventTime="2026-10-22T11:59:00+00:00"),
    )
    for change in changes:
        rows = deepcopy(chain())
        change(rows)
        assert not correlate_aws_mq_broker_chain(rows)


def test_rule_engine_receives_only_complete_chain():
    rule = Rule(id="synthetic-mq-chain", title="Synthetic MQ chain", level="medium",
                description="Synthetic test rule", technique_id="synthetic-mq-chain",
                product="aws", selection={
                    "event.source": "amazonmq.amazonaws.com",
                    "event.name": "CreateUser",
                    "event.outcome": "success",
                    "request.mq_configuration_user_chain": True,
                })
    assert len(detect_aws_events(chain(), [rule])) == 1
    assert not detect_aws_events(chain()[:2], [rule])
