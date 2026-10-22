"""Exact graph joins for SAML role trust and resource-policy self grants."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, SAML, allow, aws_snap, col, federated, real,
    reached, role, role_arn, user,
)


UPDATE_SAML = "aws-iam-updatesamlprovider"
RECREATE_SAML = "aws-iam-recreate-samlprovider"
SNS = "aws-sns-settopicattributes-self-subscribe"
SQS = "aws-sqs-setqueueattributes-self-receive"
DYNAMO = "aws-dynamodb-putresourcepolicy-self-getitem"
TOPIC = f"arn:aws:sns:{REGION}:{ACCOUNT}:alerts"
QUEUE = f"arn:aws:sqs:{REGION}:{ACCOUNT}:inbox"
TABLE = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/sensitive"


def _saml_snapshot(actions, resource=SAML, trusted=SAML):
    target = role("sso", federated(trusted, "sts:AssumeRoleWithSAML"))
    actor = user("alice", allow(actions, resource=resource))
    return aws_snap([actor], [target], [col("iam_saml_provider", [{"Arn": SAML}])])


def test_update_saml_provider_requires_same_provider_as_target_trust():
    assert reached(real(_saml_snapshot("iam:UpdateSAMLProvider"), UPDATE_SAML), ALICE, UPDATE_SAML) == {
        role_arn("sso"): "derived"}
    wrong = SAML.replace("/okta", "/other")
    for snapshot in (_saml_snapshot("iam:UpdateSAMLProvider", resource=wrong),
                     _saml_snapshot("iam:UpdateSAMLProvider", trusted=wrong)):
        assert role_arn("sso") not in reached(real(snapshot, UPDATE_SAML), ALICE, UPDATE_SAML)


def test_recreate_saml_provider_requires_delete_and_create_on_same_provider():
    both = [allow("iam:DeleteSAMLProvider", resource=SAML), allow("iam:CreateSAMLProvider", resource=SAML)]
    snapshot = _saml_snapshot("iam:DeleteSAMLProvider")
    actor = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    actor["UserPolicyList"][0]["PolicyDocument"]["Statement"] = both
    assert reached(real(snapshot, RECREATE_SAML), ALICE, RECREATE_SAML) == {role_arn("sso"): "derived"}
    for statements in (both[:1], [both[0], allow("iam:CreateSAMLProvider", resource=SAML.replace("/okta", "/other"))]):
        actor["UserPolicyList"][0]["PolicyDocument"]["Statement"] = statements
        assert role_arn("sso") not in reached(real(snapshot, RECREATE_SAML), ALICE, RECREATE_SAML)


def _sns_snapshot(*, writer=TOPIC, prior_subscribe=False):
    topic = {"TopicArn": TOPIC, "Attributes": {"collection_status": "collected",
             "Attributes": {"TopicArn": TOPIC}}}
    grants = [allow("sns:SetTopicAttributes", resource=writer)]
    if prior_subscribe:
        grants.append(allow("sns:Subscribe", resource=TOPIC))
    return aws_snap([user("alice", *grants)], [], [col("sns_topic", [topic])])


def test_sns_self_subscribe_requires_exact_writable_topic_and_new_permission():
    assert reached(real(_sns_snapshot(), SNS), ALICE, SNS)
    assert not reached(real(_sns_snapshot(writer=TOPIC.replace("alerts", "other")), SNS), ALICE, SNS)
    assert not reached(real(_sns_snapshot(prior_subscribe=True), SNS), ALICE, SNS)


def _sqs_snapshot(*, writer=QUEUE, prior_receive=False):
    queue = {"QueueArn": QUEUE, "QueueUrl": f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/inbox",
             "Attributes": {"collection_status": "collected", "Attributes": {"QueueArn": QUEUE, "KmsMasterKeyId": ""}}}
    grants = [allow("sqs:SetQueueAttributes", resource=writer)]
    if prior_receive:
        grants.append(allow("sqs:ReceiveMessage", resource=QUEUE))
    return aws_snap([user("alice", *grants)], [], [col("sqs_queue", [queue])])


def test_sqs_self_receive_requires_exact_writable_queue_and_new_permission():
    assert reached(real(_sqs_snapshot(), SQS), ALICE, SQS)
    assert not reached(real(_sqs_snapshot(writer=QUEUE.replace("inbox", "other")), SQS), ALICE, SQS)
    assert not reached(real(_sqs_snapshot(prior_receive=True), SQS), ALICE, SQS)


def _dynamo_snapshot(*, writer=TABLE, prior_get=False, encryption=None):
    table = {"TableArn": TABLE, "TableName": "sensitive", "TableStatus": "ACTIVE"}
    if encryption:
        table["SSEDescription"] = {"SSEType": encryption}
    item = {"TableName": "sensitive", "Table": {"collection_status": "collected", "Table": table},
            "ResourcePolicy": {"collection_status": "empty"}}
    grants = [allow("dynamodb:PutResourcePolicy", resource=writer)]
    if prior_get:
        grants.append(allow("dynamodb:GetItem", resource=TABLE))
    return aws_snap([user("alice", *grants)], [], [col("dynamodb_table", [item])])


def test_dynamo_self_getitem_requires_exact_table_and_new_permission():
    assert reached(real(_dynamo_snapshot(), DYNAMO), ALICE, DYNAMO)
    assert not reached(real(_dynamo_snapshot(writer=TABLE.replace("sensitive", "other")), DYNAMO), ALICE, DYNAMO)
    assert not reached(real(_dynamo_snapshot(prior_get=True), DYNAMO), ALICE, DYNAMO)
    assert not reached(real(_dynamo_snapshot(encryption="KMS"), DYNAMO), ALICE, DYNAMO)
