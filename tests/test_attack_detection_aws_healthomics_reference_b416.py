"""Synthetic derivatives of the disposable HealthOmics reference trial."""

from copy import deepcopy

from peaso.attack_detection.aws_healthomics_reference_b416 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
FIELDS = {
    "StartReferenceImportJob": "request.healthomics_reference_import_started",
    "GetReference": "request.healthomics_reference_part_retrieved",
    "DeleteReference": "request.healthomics_reference_deletion_accepted",
    "DeleteReferenceStore": "request.healthomics_reference_store_deletion_accepted",
}
RULES = tuple(Rule(
    id=f"synthetic-ref-{i}", title=f"Synthetic {name}",
    description="Synthetic", level="medium", technique_id=f"synthetic-ref-{i}",
    product="aws", selection={"event.source": "omics.amazonaws.com",
                              "event.name": name, "event.outcome": "success", field: True},
) for i, (name, field) in enumerate(FIELDS.items()))


def _row(name: str) -> dict:
    row = {
        "eventSource": "omics.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": name == "GetReference",
        "eventID": "synthetic-" + name, "eventTime": "2026-10-23T00:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"referenceStoreId": "synthetic-reference-store"},
        "responseElements": None,
    }
    request = row["requestParameters"]
    if name == "StartReferenceImportJob":
        role = f"arn:aws:iam::{ACCOUNT}:role/synthetic-import-role"
        request.update(roleArn=role, sources=[{"sourceFile": "s3://synthetic-bucket/SENTINEL.fasta",
                                               "name": "synthetic-reference"}])
        row["responseElements"] = {"referenceStoreId": "synthetic-reference-store",
                                   "roleArn": role, "status": "SUBMITTED", "id": "synthetic-job"}
    elif name == "GetReference":
        request.update(id="synthetic-reference", file="SOURCE", partNumber=1)
        row["responseElements"] = {"payload": "SENTINEL-GENOMIC-BYTES"}
    elif name == "DeleteReference":
        request["id"] = "synthetic-reference"
    return row


def test_four_accepted_api_shapes_hit_without_leaking_content_or_ids():
    rows = [_row(name) for name in FIELDS]
    hits = detect_aws_events(rows, RULES)
    assert len(hits) == 4
    normalized = [normalize(row) for row in rows]
    assert all(event is not None and event["target.id"].startswith("sha256:")
               for event in normalized)
    for hidden in ("SENTINEL", "synthetic-reference-store", "synthetic-reference", "synthetic-bucket"):
        assert hidden not in str(normalized)
        assert hidden not in str(hits)


def test_errors_foreign_identity_and_read_only_mismatch_are_negative():
    for name in FIELDS:
        for change in (
            lambda row: row.update(errorCode="AccessDeniedException"),
            lambda row: row["userIdentity"].update(accountId="888888888888"),
            lambda row: row.update(readOnly=name != "GetReference"),
        ):
            row = _row(name)
            change(row)
            assert normalize(row) is None


def test_import_and_read_require_coherent_request():
    changes = (
        ("StartReferenceImportJob", lambda row: row["responseElements"].update(referenceStoreId="other")),
        ("StartReferenceImportJob", lambda row: row["requestParameters"].update(sources=[])),
        ("StartReferenceImportJob", lambda row: row["responseElements"].update(status="FAILED")),
        ("GetReference", lambda row: row["requestParameters"].update(file="UNKNOWN")),
        ("GetReference", lambda row: row["requestParameters"].update(partNumber=0)),
        ("DeleteReference", lambda row: row["requestParameters"].pop("id")),
    )
    for name, change in changes:
        row = _row(name)
        change(row)
        assert normalize(row) is None


def test_metadata_reads_not_misclassified():
    row = deepcopy(_row("GetReference"))
    row["eventName"] = "GetReferenceMetadata"
    assert normalize(row) is None
