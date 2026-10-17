"""Native optional omission must be proven; denied or malformed stays unknown."""
import pytest

from peaso.collectors import aws


class Responses:
    def detail(self, session, service, region, operation, **arguments):
        if operation in {"get_topic_attributes", "get_queue_attributes"}:
            return {"collection_status": "collected", "Attributes": {}}
        return {"collection_status": "collected"}
    def pages(self, *args, **kwargs):
        return aws.ReadResult([], "empty")


def test_cloudtrail_optional_kms_omission_is_proved_by_native_list_object():
    row = {"Name": "audit", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit", "HomeRegion": "us-east-1"}
    item = aws._enrich(Responses(), object(), "us-east-1", "cloudtrail", [row])[0]
    assert item["KmsKeyId"] == ""
    assert item["_coverage"]["KmsKeyId"]["status"] == "empty"
    assert "KmsKeyId" not in row


def test_secret_rotation_omission_is_unknown_without_describe_fact():
    row = {"Name": "metadata-only", "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:metadata-only-123456"}
    class Detail(Responses):
        def detail(self, session, service, region, operation, **arguments):
            if operation == "describe_secret":
                return {"collection_status": "collected", "ARN": row["ARN"], "Name": row["Name"]}
            return super().detail(session, service, region, operation, **arguments)
    item = aws._enrich(Detail(), object(), "us-east-1", "secret", [row], account="123456789012", partition="aws")[0]
    assert "RotationEnabled" not in item
    assert item["_coverage"]["RotationEnabled"] == {"status": "empty", "source_operation": "secretsmanager:DescribeSecret"}


@pytest.mark.parametrize("kind,row", [("sns_topic", {"TopicArn": "arn:aws:sns:us-east-1:123456789012:topic"}), ("sqs_queue", {"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/queue"})])
def test_successful_attributes_omit_kms_key_with_explicit_known_empty_coverage(kind, row):
    item = aws._enrich(Responses(), object(), "us-east-1", kind, [row])[0]
    attrs = item["Attributes"]["Attributes"]
    assert attrs["KmsMasterKeyId"] == ""
    assert attrs["_coverage"]["KmsMasterKeyId"]["status"] == "empty"


@pytest.mark.parametrize("kind,row", [("sns_topic", {"TopicArn": "arn:aws:sns:us-east-1:123456789012:topic"}), ("sqs_queue", {"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/queue"})])
def test_denied_attributes_never_project_missing_key_as_known_empty(kind, row):
    class Denied(Responses):
        def detail(self, *args, **kwargs):
            return {"collection_status": "denied", "error": {"code": "AccessDenied"}}
    item = aws._enrich(Denied(), object(), "us-east-1", kind, [row])[0]
    assert item["Attributes"]["collection_status"] == "denied"
    assert "Attributes" not in item["Attributes"]


def test_explicit_native_settings_are_not_overwritten_by_omission_projection():
    item = {"RotationEnabled": True}
    aws._documented_omission(item, "RotationEnabled", False, "secretsmanager:ListSecrets")
    assert item == {"RotationEnabled": True}
