"""Synthetic derivative of a disposable HealthOmics S3 data event."""

from copy import deepcopy

from peaso.attack_detection.aws_healthomics_s3_alias_b420 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
SERVICE = "000000000000"
BUCKET = "aws-omics-us-east-1-s-synthetic"
KEY = "SENTINEL-genomic-read.fastq.gz"
RULE = Rule(
    id="synthetic-omics-s3-ap", title="Synthetic HealthOmics S3 AP read",
    description="Synthetic", level="medium", technique_id="synthetic-omics-s3-ap",
    product="aws", selection={"event.source": "s3.amazonaws.com",
                              "event.name": "GetObject", "event.outcome": "success",
                              "request.healthomics_s3_read_set_read": True},
)
PRESIGNED_RULE = Rule(
    id="synthetic-omics-s3-presigned", title="Synthetic presigned read",
    description="Synthetic", level="medium",
    technique_id="synthetic-omics-s3-presigned", product="aws",
    selection={"event.source": "s3.amazonaws.com", "event.name": "GetObject",
               "event.outcome": "success",
               "request.healthomics_presigned_read_set_read": True},
)


def _row():
    return {
        "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
        "eventType": "AwsApiCall", "eventCategory": "Data",
        "managementEvent": False, "readOnly": True,
        "eventID": "synthetic-omics-ap-get", "eventTime": "2026-10-23T00:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-reader"},
        "requestParameters": {"bucketName": BUCKET, "key": KEY,
                              "accessPointAlias": "synthetic-omics-alias-s3alias"},
        "resources": [
            {"type": "AWS::S3::Bucket", "accountId": SERVICE,
             "ARN": f"arn:aws:s3:::{BUCKET}"},
            {"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::{BUCKET}/{KEY}"},
            {"type": "AWS::S3::AccessPoint", "accountId": SERVICE,
             "ARN": f"arn:aws:s3:us-east-1:{SERVICE}:accesspoint/synthetic-omics-ap"},
        ],
        "additionalEventData": {"httpStatusCode": 200},
        "responseElements": None,
    }


def test_synthetic_omics_s3_data_event_hits_without_genomic_path():
    row = _row()
    event = normalize(row)
    assert event is not None and event["target.id"].startswith("sha256:")
    hits = detect_aws_events([row], (RULE,))
    assert len(hits) == 1
    for secret in (KEY, BUCKET, "synthetic-omics-alias", SERVICE):
        assert secret not in str(event)
        assert secret not in str(hits)


def test_wrong_owner_or_mismatched_object_is_rejected():
    row = _row()
    row["resources"][2]["accountId"] = ACCOUNT
    assert normalize(row) is None
    row = _row()
    row["resources"][1]["ARN"] = f"arn:aws:s3:::{BUCKET}/other"
    assert normalize(row) is None


def test_failed_get_or_management_event_is_rejected():
    for change in (
        lambda row: row.update(errorCode="AccessDenied"),
        lambda row: row.update(eventCategory="Management"),
        lambda row: row["additionalEventData"].update(httpStatusCode=403),
        lambda row: row["requestParameters"].pop("accessPointAlias"),
    ):
        row = deepcopy(_row())
        change(row)
        assert normalize(row) is None


def test_presigned_query_string_read_is_distinguished_from_header_auth():
    row = _row()
    row["additionalEventData"].update(
        AuthenticationMethod="QueryString", SignatureVersion="SigV4"
    )
    event = normalize(row)
    assert event is not None
    assert event["request.healthomics_presigned_read_set_read"] is True
    assert KEY not in str(event)
    hits = detect_aws_events([row], (PRESIGNED_RULE,))
    assert len(hits) == 1
    assert KEY not in str(hits)
    assert detect_aws_events([_row()], (PRESIGNED_RULE,)) == []
    assert "request.healthomics_presigned_read_set_read" not in normalize(_row())
    row["additionalEventData"]["SignatureVersion"] = "SigV2"
    assert "request.healthomics_presigned_read_set_read" not in normalize(row)
