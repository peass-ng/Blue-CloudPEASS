"""Synthetic derivatives of a disposable HealthOmics sequence-store trial."""

from copy import deepcopy

from peaso.attack_detection.aws_healthomics_sequence_b415 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
NAMES = (
    "UpdateSequenceStore", "CreateMultipartReadSetUpload", "UploadReadSetPart",
    "CompleteMultipartReadSetUpload", "BatchDeleteReadSet", "DeleteSequenceStore",
)
RULES = tuple(Rule(
    id=f"synthetic-omics-{i}", title=f"Synthetic {name}", description="Synthetic",
    level="medium", technique_id=f"synthetic-omics-sequence-{i}", product="aws",
    selection={"event.source": "omics.amazonaws.com", "event.name": name,
               "event.outcome": "success",
               "request.healthomics_sequence_store_change_accepted": True},
) for i, name in enumerate(NAMES))
READ_RULE = Rule(
    id="synthetic-omics-read", title="Synthetic read set retrieval",
    description="Synthetic", level="medium", technique_id="synthetic-omics-read",
    product="aws", selection={
        "event.source": "omics.amazonaws.com", "event.name": "GetReadSet",
        "event.outcome": "success", "request.healthomics_read_set_part_retrieved": True,
    },
)


def _row(name: str) -> dict:
    row = {
        "eventSource": "omics.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "eventID": "synthetic-event-" + name, "eventTime": "2026-10-23T00:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"sequenceStoreId": "synthetic-store"},
        "responseElements": None,
    }
    request = row["requestParameters"]
    if name == "UpdateSequenceStore":
        request["propagatedSetLevelTags"] = ["synthetic-tag"]
        row["responseElements"] = {"id": "synthetic-store"}
    elif name == "CreateMultipartReadSetUpload":
        request.update(name="synthetic-read-set", sampleId="SENTINEL-SAMPLE",
                       subjectId="SENTINEL-SUBJECT", sourceFileType="FASTQ")
        row["responseElements"] = {"sequenceStoreId": "synthetic-store",
                                   "uploadId": "synthetic-upload"}
    elif name == "UploadReadSetPart":
        request.update(uploadId="synthetic-upload", partSource="SOURCE1",
                       partNumber=1, payload={"bytes": "SENTINEL-PAYLOAD"})
        row["responseElements"] = {"checksum": "SENTINEL-CHECKSUM"}
    elif name == "CompleteMultipartReadSetUpload":
        request.update(uploadId="synthetic-upload", parts=[{"partNumber": 1,
                       "partSource": "SOURCE1", "checksum": "SENTINEL-CHECKSUM"}])
        row["responseElements"] = {"readSetId": "synthetic-read-set"}
    elif name == "BatchDeleteReadSet":
        request["ids"] = ["synthetic-read-set"]
    return row


def test_six_live_shapes_hit_six_rules_and_hide_sensitive_material():
    rows = [_row(name) for name in NAMES]
    hits = detect_aws_events(rows, RULES)
    assert len(hits) == len(NAMES)
    events = [normalize(row) for row in rows]
    assert all(event is not None and event["target.id"].startswith("sha256:")
               for event in events)
    for secret in ("SENTINEL", "synthetic-store", "synthetic-upload", "synthetic-read-set"):
        assert secret not in str(events)
        assert secret not in str(hits)


def test_errors_and_foreign_account_are_negative():
    for name in NAMES:
        row = _row(name)
        row["errorCode"] = "AccessDeniedException"
        assert normalize(row) is None
        row = _row(name)
        row["userIdentity"]["accountId"] = "888888888888"
        assert normalize(row) is None


def test_incomplete_upload_and_mismatched_store_are_negative():
    changes = (
        ("CreateMultipartReadSetUpload", lambda row: row["responseElements"].update(sequenceStoreId="other")),
        ("UploadReadSetPart", lambda row: row["requestParameters"].update(partNumber=0)),
        ("UploadReadSetPart", lambda row: row["responseElements"].update(checksum="")),
        ("CompleteMultipartReadSetUpload", lambda row: row["requestParameters"].update(parts=[])),
        ("BatchDeleteReadSet", lambda row: row["requestParameters"].update(ids=[])),
        ("UpdateSequenceStore", lambda row: row["requestParameters"].pop("propagatedSetLevelTags")),
    )
    for name, change in changes:
        row = _row(name)
        change(row)
        assert normalize(row) is None


def test_read_events_not_misclassified_as_changes():
    for name in ("GetReadSetMetadata", "ListReadSets"):
        row = _row("DeleteSequenceStore")
        row["eventName"] = name
        row["readOnly"] = True
        assert normalize(row) is None
    row = deepcopy(_row("DeleteSequenceStore"))
    row["eventCategory"] = "Data"
    assert normalize(row) is None


def test_read_set_part_retrieval_has_distinct_signal_and_no_bytes():
    row = _row("DeleteSequenceStore")
    row["eventName"] = "GetReadSet"
    row["readOnly"] = True
    row["requestParameters"].update(id="synthetic-read-set", file="SOURCE1", partNumber=1)
    row["responseElements"] = {"payload": "SENTINEL-GENOMIC-DATA"}
    event = normalize(row)
    assert event is not None
    assert event["request.healthomics_read_set_part_retrieved"] is True
    assert "request.healthomics_sequence_store_change_accepted" not in event
    assert len(detect_aws_events([row], (READ_RULE,))) == 1
    assert "SENTINEL" not in str(event)
    assert "synthetic-read-set" not in str(event)
    for change in (
        lambda r: r.update(errorCode="AccessDeniedException"),
        lambda r: r["requestParameters"].update(file="UNKNOWN"),
        lambda r: r["requestParameters"].update(partNumber=0),
        lambda r: r.update(readOnly=False),
    ):
        negative = deepcopy(row)
        change(negative)
        assert normalize(negative) is None
