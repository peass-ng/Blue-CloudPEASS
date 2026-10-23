"""Synthetic derivatives of disposable HealthOmics read-set S3 jobs."""

from copy import deepcopy

from peaso.attack_detection.aws_healthomics_s3_jobs_b418 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
IMPORT = Rule(
    id="synthetic-omics-import", title="Synthetic read-set import",
    description="Synthetic", level="medium", technique_id="synthetic-omics-import",
    product="aws", selection={"event.source": "omics.amazonaws.com",
                              "event.name": "StartReadSetImportJob",
                              "event.outcome": "success",
                              "request.healthomics_read_set_import_submitted": True},
)
EXPORT = Rule(
    id="synthetic-omics-export", title="Synthetic read-set export",
    description="Synthetic", level="medium", technique_id="synthetic-omics-export",
    product="aws", selection={"event.source": "omics.amazonaws.com",
                              "event.name": "StartReadSetExportJob",
                              "event.outcome": "success",
                              "request.healthomics_read_set_export_submitted": True},
)


def _row(export: bool) -> dict:
    name = "StartReadSetExportJob" if export else "StartReadSetImportJob"
    role = f"arn:aws:iam::{ACCOUNT}:role/synthetic-job-role"
    request = {"sequenceStoreId": "synthetic-store", "roleArn": role}
    response = {"sequenceStoreId": "synthetic-store", "id": "synthetic-job",
                "status": "SUBMITTED"}
    if export:
        request.update(destination="s3://synthetic-bucket/SENTINEL-export/",
                       sources=[{"readSetId": "synthetic-read-set"}])
        response["destination"] = request["destination"]
    else:
        request["sources"] = [{"sourceFiles": {"source1": "s3://synthetic-bucket/SENTINEL.fastq.gz"},
                               "sourceFileType": "FASTQ", "subjectId": "SENTINEL-subject",
                               "sampleId": "SENTINEL-sample"}]
        response["roleArn"] = role
    return {
        "eventSource": "omics.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "eventID": "synthetic-" + name, "eventTime": "2026-10-23T00:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def test_import_and_export_real_shapes_hit_without_sensitive_fields():
    rows = [_row(False), _row(True)]
    hits = detect_aws_events(rows, (IMPORT, EXPORT))
    assert len(hits) == 2
    events = [normalize(row) for row in rows]
    assert all(event is not None and event["target.id"].startswith("sha256:")
               for event in events)
    for hidden in ("SENTINEL", "synthetic-bucket", "synthetic-read-set", "synthetic-store"):
        assert hidden not in str(events)
        assert hidden not in str(hits)


def test_import_requires_source_and_matching_role():
    row = _row(False)
    row["responseElements"]["roleArn"] = f"arn:aws:iam::888888888888:role/foreign"
    assert normalize(row) is None
    row = _row(False)
    row["requestParameters"]["sources"][0]["sourceFiles"] = {}
    assert normalize(row) is None


def test_export_requires_matching_destination_and_read_set():
    row = _row(True)
    row["responseElements"]["destination"] = "s3://synthetic-bucket/other/"
    assert normalize(row) is None
    row = _row(True)
    row["requestParameters"]["sources"] = []
    assert normalize(row) is None


def test_failures_foreign_actor_and_reads_are_negative():
    for export in (False, True):
        for change in (
            lambda row: row.update(errorCode="AccessDeniedException"),
            lambda row: row["userIdentity"].update(accountId="888888888888"),
            lambda row: row.update(readOnly=True),
        ):
            row = deepcopy(_row(export))
            change(row)
            assert normalize(row) is None
