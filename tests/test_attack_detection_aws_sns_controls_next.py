"""SNS topic and subscription controls require accepted, exact configuration writes."""

from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "222233334444"
TOPIC = f"arn:aws:sns:us-east-1:{ACCOUNT}:example-topic"
SUBSCRIPTION = TOPIC + ":a9516acf-8f02-43cc-9b6a-b407373cc57f"


def rule(name, field):
    return Rule(id=field, title=field, level="medium", description=field,
                technique_id=field, product="aws", selection={
                    "event.source": "sns.amazonaws.com", "event.name": name,
                    "event.outcome": "success", field: True})


RULES = (
    rule("SetTopicAttributes", "request.sns_kms_key_cleared"),
    rule("SetSubscriptionAttributes", "request.sns_filter_cleared"),
    rule("SetTopicAttributes", "request.sns_org_wildcard_subscribe_grant"),
    rule("Subscribe", "request.sns_replay_subscribe_requested"),
    rule("SetSubscriptionAttributes", "request.sns_replay_policy_set"),
    rule("SetTopicAttributes", "request.sns_archive_cleared"),
)


def event(name, request):
    return {"eventSource": "sns.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "requestParameters": request,
            "responseElements": None}


def hits(item):
    return [d.technique_id for d in detect_aws_events([item], RULES)]


def test_kms_key_must_be_explicitly_cleared_by_successful_topic_write():
    item = event("SetTopicAttributes", {"topicArn": TOPIC, "attributeName": "KmsMasterKeyId", "attributeValue": ""})
    assert hits(item) == ["request.sns_kms_key_cleared"]
    for changed in ({"attributeValue": "alias/aws/sns"}, {"attributeName": "DisplayName"},
                    {"topicArn": TOPIC.replace(ACCOUNT, "111111111111")},
                    {"responseElements": {"errorCode": "AccessDenied"}}):
        assert hits({**item, **changed, "requestParameters": {**item["requestParameters"], **changed}}) == []


def test_empty_filter_is_distinct_from_specific_filter():
    item = event("SetSubscriptionAttributes", {"subscriptionArn": SUBSCRIPTION,
            "attributeName": "FilterPolicy", "attributeValue": "{}"})
    assert hits(item) == ["request.sns_filter_cleared"]
    for value in ('{"kind":["public"]}', '[]', '', 'null'):
        other = deepcopy(item)
        other["requestParameters"]["attributeValue"] = value
        assert hits(other) == []
    item["errorCode"] = "AccessDenied"
    assert hits(item) == []


def test_org_wildcard_subscribe_grant_requires_exact_topic_and_condition():
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
              "Action": "sns:Subscribe", "Resource": TOPIC,
              "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}}}]}
    item = event("SetTopicAttributes", {"topicArn": TOPIC, "attributeName": "Policy",
            "attributeValue": json.dumps(policy)})
    assert hits(item) == ["request.sns_org_wildcard_subscribe_grant"]
    for change in ({"Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}},
                   {"Action": "sns:Publish"}, {"Resource": TOPIC + "-other"},
                   {"Condition": {"StringEquals": {"aws:PrincipalOrgID": "invalid"}}}):
        other = deepcopy(item)
        policy2 = deepcopy(policy)
        policy2["Statement"][0].update(change)
        other["requestParameters"]["attributeValue"] = json.dumps(policy2)
        assert hits(other) == []


def test_fifo_replay_and_archive_clear_have_distinct_management_events():
    replay = json.dumps({"PointType": "Timestamp", "StartingPoint": "2026-10-19T14:33:44.000Z"})
    subscribe = event("Subscribe", {"topicArn": TOPIC + ".fifo", "protocol": "sqs",
                 "attributes": {"ReplayPolicy": replay}})
    assert hits(subscribe) == ["request.sns_replay_subscribe_requested"]
    missing = deepcopy(subscribe)
    missing["requestParameters"]["attributes"] = {}
    assert hits(missing) == []
    update = event("SetSubscriptionAttributes", {"subscriptionArn": SUBSCRIPTION,
                "attributeName": "ReplayPolicy", "attributeValue": replay})
    assert hits(update) == ["request.sns_replay_policy_set"]
    update["errorCode"] = "AccessDenied"
    assert hits(update) == []
    archive = event("SetTopicAttributes", {"topicArn": TOPIC + ".fifo",
                 "attributeName": "ArchivePolicy", "attributeValue": "{}"})
    assert hits(archive) == ["request.sns_archive_cleared"]
    archive["requestParameters"]["attributeValue"] = '{"MessageRetentionPeriod":"1"}'
    assert hits(archive) == []
