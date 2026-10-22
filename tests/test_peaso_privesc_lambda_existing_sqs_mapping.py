"""Existing SQS source mappings need a real writable/readable queue."""
from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-lambda-passrole-createfunction-createeventsourcemapping"
ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ID)
SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
QUEUE = "arn:aws:sqs:us-east-1:111111111111:events"
FUNCTION = "arn:aws:lambda:us-east-1:111111111111:function:peasoprivsecaudit0"


def _case(*, readable=True, writable=True, encryption="", visibility="30", mapping_function=FUNCTION):
    snap = _snapshot(ENTRY)
    user = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    statements = [
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": TARGET},
        {"Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": FUNCTION},
        {"Effect": "Allow", "Action": "lambda:CreateEventSourceMapping", "Resource": "*",
         "Condition": {"ArnEquals": {"lambda:FunctionArn": mapping_function}}},
    ]
    if writable:
        statements.append({"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": QUEUE})
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"] = statements
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    role["AssumeRolePolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
         "Action": "sts:AssumeRole"}]
    if readable:
        role["RolePolicyList"] = [{"PolicyName": "queue-reader", "PolicyDocument": {
            "Statement": [{"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage",
                                                          "sqs:GetQueueAttributes"], "Resource": QUEUE}]}}]
    scope = "111111111111/us-east-1"
    snap["collections"].extend([
        {"type": "lambda_function", "scope": scope, "service": "lambda", "status": "empty",
         "error": None, "items": []},
        {"type": "sqs_queue", "scope": scope, "service": "sqs", "status": "collected",
         "error": None, "items": [{"QueueUrl": "https://sqs.us-east-1.amazonaws.com/111111111111/events",
                                 "Attributes": {"collection_status": "collected", "Attributes": {
                                     "QueueArn": QUEUE, "VisibilityTimeout": visibility,
                                     "KmsMasterKeyId": encryption}}}]},
    ])
    return snap


def _definite(snap):
    return reached(privesc.analyze(snap, entries=[ENTRY], include_unknown=False), SOURCE, ID)


def test_existing_queue_and_function_grants_join():
    assert _definite(_case()) == {TARGET: "conditional"}


def test_missing_queue_send_or_role_read_does_not_create_role_edge():
    assert TARGET not in _definite(_case(writable=False))
    assert TARGET not in _definite(_case(readable=False))


def test_mapping_must_allow_the_created_function():
    assert TARGET not in _definite(_case(mapping_function=FUNCTION.replace("audit0", "audit1")))


def test_encrypted_or_unusable_queue_stays_unresolved():
    assert TARGET not in _definite(_case(encryption="alias/customer"))
    assert TARGET not in _definite(_case(visibility="0"))
