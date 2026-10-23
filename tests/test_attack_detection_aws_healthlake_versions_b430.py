"""Synthetic derivatives of an isolated FHIR version/PATCH/$erase lab."""

from copy import deepcopy

from peaso.attack_detection.aws_healthlake_fhir_b429 import normalize as normalize_fhir
from peaso.attack_detection.aws_healthlake_erase_b430 import normalize as normalize_erase
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
STORE = "a" * 32
PATIENT = "synthetic-private-patient"
SECRET = "synthetic-private-clinical-value"


def row(name):
    request = {"datastoreId": STORE, "headers": {"authorization": SECRET}}
    if name == "StartFHIRBulkDeleteJob":
        request["bulkDeleteType"] = "erase_Patient_" + PATIENT
    else:
        request.update(resourceType="Patient", resourceId=PATIENT)
        if name == "VersionReadResource":
            request["versionId"] = "synthetic-version"
    return {
        "eventSource": "healthlake.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": name == "VersionReadResource",
        "eventID": "synthetic-" + name, "eventTime": "2026-10-23T02:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request,
        "responseElements": {"statusCode": 200, "responseBody": SECRET,
                             "headers": {"secret": SECRET}},
    }


def test_accepted_routes_match_and_omit_private_values():
    for name, normalizer, marker in (
        ("PatchResource", normalize_fhir, "request.healthlake_fhir_call"),
        ("VersionReadResource", normalize_fhir, "request.healthlake_fhir_call"),
        ("StartFHIRBulkDeleteJob", normalize_erase,
         "request.healthlake_fhir_erase_submitted"),
    ):
        raw = row(name)
        normalized = normalizer(raw)
        assert normalized is not None and normalized[marker] is True
        assert PATIENT not in str(normalized) and SECRET not in str(normalized)
        rule = Rule(id=name, title=name, description="Synthetic", level="high",
                    technique_id=name, product="aws",
                    selection={"event.source": "healthlake.amazonaws.com",
                               "event.name": name, "event.outcome": "success",
                               marker: True})
        hits = detect_aws_events([raw], (rule,))
        assert len(hits) == 1
        assert PATIENT not in str(hits) and SECRET not in str(hits)


def test_failed_or_mismatched_routes_do_not_match():
    for name, normalizer in (
        ("PatchResource", normalize_fhir),
        ("VersionReadResource", normalize_fhir),
        ("StartFHIRBulkDeleteJob", normalize_erase),
    ):
        for change in (
            lambda x: x.update(errorCode="ResourceNotFoundException"),
            lambda x: x["responseElements"].update(statusCode=403),
            lambda x: x["userIdentity"].update(accountId="111111111111"),
            lambda x: x.update(eventCategory="Data"),
            lambda x: x["requestParameters"].update(datastoreId="invalid"),
        ):
            candidate = deepcopy(row(name))
            change(candidate)
            assert normalizer(candidate) is None
    candidate = row("StartFHIRBulkDeleteJob")
    candidate["requestParameters"]["bulkDeleteType"] = "delete_Patient_" + PATIENT
    assert normalize_erase(candidate) is None
    candidate = row("VersionReadResource")
    candidate["requestParameters"].pop("versionId")
    assert normalize_fhir(candidate) is None
