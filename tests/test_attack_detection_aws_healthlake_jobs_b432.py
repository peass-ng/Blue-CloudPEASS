"""Synthetic derivatives of isolated HealthLake S3 import/export jobs."""

from copy import deepcopy

from peaso.attack_detection.aws_healthlake_jobs_b432 import normalize
from peaso.attack_detection.aws_healthlake_export_rest_b432 import normalize as normalize_rest_post
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
STORE = "a" * 32
BUCKET = "synthetic-private-healthlake-bucket"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-healthlake-role"
SECRET = "synthetic-patient-canary"


def row(name):
    request = {"datastoreId": STORE, "dataAccessRoleArn": ROLE,
               "jobName": SECRET}
    destination = {"s3Configuration": {"s3Uri": f"s3://{BUCKET}/output/",
                                        "kmsKeyId": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/synthetic"}}
    if name == "StartFHIRImportJob":
        request["inputDataConfig"] = {"s3Uri": f"s3://{BUCKET}/input/"}
        request["jobOutputDataConfig"] = destination
    else:
        request["outputDataConfig"] = destination
    return {
        "eventSource": "healthlake.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "eventID": "synthetic-" + name, "eventTime": "2026-10-23T03:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request,
        "responseElements": {"jobId": "synthetic-job", "jobStatus": "SUBMITTED",
                             "datastoreId": STORE},
    }


def test_accepted_import_export_submission_hides_locations_and_role():
    for name, marker in (
        ("StartFHIRImportJob", "request.healthlake_import_submitted"),
        ("StartFHIRExportJob", "request.healthlake_export_submitted"),
    ):
        raw = row(name)
        normalized = normalize(raw)
        assert normalized is not None and normalized[marker] is True
        assert all(value not in str(normalized) for value in (STORE, BUCKET, ROLE, SECRET))
        rule = Rule(id=name, title=name, description="Synthetic", level="high",
                    technique_id=name, product="aws",
                    selection={"event.source": "healthlake.amazonaws.com",
                               "event.name": name, "event.outcome": "success",
                               marker: True})
        hits = detect_aws_events([raw], (rule,))
        assert len(hits) == 1 and BUCKET not in str(hits)


def test_rejected_job_submissions_do_not_match():
    for name in ("StartFHIRImportJob", "StartFHIRExportJob"):
        key = "jobOutputDataConfig" if name == "StartFHIRImportJob" else "outputDataConfig"
        for change in (
            lambda x: x.update(errorCode="AccessDeniedException"),
            lambda x: x["responseElements"].update(jobStatus="FAILED"),
            lambda x: x["responseElements"].update(datastoreId="b" * 32),
            lambda x: x["userIdentity"].update(accountId="111111111111"),
            lambda x: x["requestParameters"].update(dataAccessRoleArn=f"arn:aws:iam::111111111111:role/other"),
            lambda x: x["requestParameters"][key]["s3Configuration"].update(s3Uri="https://not-s3.example/"),
        ):
            candidate = deepcopy(row(name))
            change(candidate)
            assert normalize(candidate) is None
    candidate = row("StartFHIRImportJob")
    candidate["requestParameters"]["inputDataConfig"]["s3Uri"] = "not-s3"
    assert normalize(candidate) is None


def test_rest_export_post_is_distinct_and_hides_destination_and_response_body():
    raw = row("StartFHIRExportJob")
    raw["eventName"] = "StartFHIRExportJobWithPost"
    raw["requestParameters"] = {
        "datastoreId": STORE,
        "exportJobParameters": {
            "dataAccessRoleArn": ROLE,
            "outputDataConfig": {"s3Configuration": {
                "s3Uri": f"s3://{BUCKET}/rest-post/"}},
        },
        "headers": {"authorization": SECRET},
    }
    raw["responseElements"] = {"statusCode": 202,
                               "responseBody": {"hb": list(SECRET.encode())}}
    normalized = normalize_rest_post(raw)
    assert normalized is not None
    assert normalized["request.healthlake_rest_export_post_submitted"] is True
    assert all(value not in str(normalized) for value in (STORE, BUCKET, ROLE, SECRET))
    rule = Rule(id="rest", title="rest", description="Synthetic", level="high",
                technique_id="rest", product="aws",
                selection={"event.source": "healthlake.amazonaws.com",
                           "event.name": "StartFHIRExportJobWithPost",
                           "event.outcome": "success",
                           "request.healthlake_rest_export_post_submitted": True})
    assert len(detect_aws_events([raw], (rule,))) == 1
    for change in (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x["responseElements"].update(statusCode=403),
        lambda x: x["requestParameters"]["exportJobParameters"].update(dataAccessRoleArn=f"arn:aws:iam::111111111111:role/other"),
        lambda x: x["requestParameters"]["exportJobParameters"]["outputDataConfig"]["s3Configuration"].update(s3Uri="https://invalid.example/"),
    ):
        candidate = deepcopy(raw)
        change(candidate)
        assert normalize_rest_post(candidate) is None
