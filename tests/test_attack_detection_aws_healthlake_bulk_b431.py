"""Synthetic derivatives of isolated HealthLake management events."""

from copy import deepcopy

from peaso.attack_detection.aws_healthlake_datastore_delete_b431 import normalize as normalize_delete
from peaso.attack_detection.aws_healthlake_bulk_patch_b431 import normalize as normalize_patch
from peaso.attack_detection.aws_healthlake_purge_b431 import normalize as normalize_purge
from peaso.attack_detection.aws_healthlake_bulk_delete_b431 import normalize as normalize_bulk_delete
from peaso.attack_detection.aws_healthlake_conditional_delete_b431 import normalize as normalize_conditional_delete
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
STORE = "a" * 32
SECRET = "synthetic-private-patient"


def delete_row():
    return {
        "eventSource": "healthlake.amazonaws.com",
        "eventName": "DeleteFHIRDatastore", "eventType": "AwsApiCall",
        "eventCategory": "Management", "managementEvent": True,
        "readOnly": False, "eventID": "synthetic-delete-event",
        "eventTime": "2026-10-23T02:00:00Z", "recipientAccountId": ACCOUNT,
        "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"datastoreId": STORE},
        "responseElements": {"datastoreId": STORE, "datastoreStatus": "DELETING",
                             "datastoreEndpoint": SECRET},
    }


def test_datastore_deletion_accepts_submission_and_omits_endpoint():
    raw = delete_row()
    normalized = normalize_delete(raw)
    assert normalized is not None
    assert STORE not in str(normalized) and SECRET not in str(normalized)
    rule = Rule(id="delete", title="delete", description="Synthetic",
                level="critical", technique_id="delete", product="aws",
                selection={"event.source": "healthlake.amazonaws.com",
                           "event.name": "DeleteFHIRDatastore",
                           "event.outcome": "success",
                           "request.healthlake_datastore_deletion_submitted": True})
    hits = detect_aws_events([raw], (rule,))
    assert len(hits) == 1 and SECRET not in str(hits)


def test_rejected_datastore_deletions_do_not_match():
    for change in (
        lambda x: x.update(errorCode="ResourceNotFoundException"),
        lambda x: x["responseElements"].update(datastoreStatus="ACTIVE"),
        lambda x: x["responseElements"].update(datastoreId="b" * 32),
        lambda x: x["userIdentity"].update(accountId="111111111111"),
        lambda x: x.update(readOnly=True),
    ):
        candidate = deepcopy(delete_row())
        change(candidate)
        assert normalize_delete(candidate) is None


def test_bulk_patch_submission_hides_byte_buffer_payload():
    raw = delete_row()
    raw["eventName"] = "StartFHIRBulkPatchJob"
    raw["requestParameters"] = {"datastoreId": STORE,
                                "requestBody": {"hb": list(SECRET.encode())},
                                "headers": {"authorization": SECRET}}
    raw["responseElements"] = {"statusCode": 202,
                               "responseBody": {"hb": list(SECRET.encode())}}
    normalized = normalize_patch(raw)
    assert normalized is not None
    assert STORE not in str(normalized) and SECRET not in str(normalized)
    rule = Rule(id="patch", title="patch", description="Synthetic",
                level="high", technique_id="patch", product="aws",
                selection={"event.source": "healthlake.amazonaws.com",
                           "event.name": "StartFHIRBulkPatchJob",
                           "event.outcome": "success",
                           "request.healthlake_bulk_patch_submitted": True})
    assert len(detect_aws_events([raw], (rule,))) == 1
    for change in (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x["responseElements"].update(statusCode=403),
        lambda x: x["userIdentity"].update(accountId="111111111111"),
    ):
        candidate = deepcopy(raw)
        change(candidate)
        assert normalize_patch(candidate) is None


def test_patient_purge_is_distinct_from_erase_and_hides_target():
    raw = delete_row()
    raw["eventName"] = "StartFHIRBulkDeleteJob"
    raw["requestParameters"] = {"datastoreId": STORE,
                                "bulkDeleteType": "purge_Patient_" + SECRET,
                                "headers": {"authorization": SECRET},
                                "queryStrings": {"secret": SECRET}}
    raw["responseElements"] = {"statusCode": 200,
                               "responseBody": {"hb": list(SECRET.encode())}}
    normalized = normalize_purge(raw)
    assert normalized is not None
    assert STORE not in str(normalized) and SECRET not in str(normalized)
    rule = Rule(id="purge", title="purge", description="Synthetic",
                level="critical", technique_id="purge", product="aws",
                selection={"event.source": "healthlake.amazonaws.com",
                           "event.name": "StartFHIRBulkDeleteJob",
                           "event.outcome": "success",
                           "request.healthlake_fhir_purge_submitted": True})
    assert len(detect_aws_events([raw], (rule,))) == 1
    for change in (
        lambda x: x["requestParameters"].update(bulkDeleteType="erase_Patient_" + SECRET),
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x["responseElements"].update(statusCode=403),
    ):
        candidate = deepcopy(raw)
        change(candidate)
        assert normalize_purge(candidate) is None


def test_bulk_delete_does_not_claim_hidden_hard_delete_mode():
    raw = delete_row()
    raw["eventName"] = "StartFHIRBulkDeleteJob"
    raw["requestParameters"] = {"datastoreId": STORE,
                                "bulkDeleteType": "bulk-delete_Patient",
                                "queryStrings": {"isHardDelete": "HIDDEN_DUE_TO_SECURITY_REASONS"}}
    raw["responseElements"] = {"statusCode": 200}
    normalized = normalize_bulk_delete(raw)
    assert normalized is not None
    assert normalized["request.healthlake_fhir_bulk_delete_submitted"] is True
    assert not any("hard" in key or "soft" in key for key in normalized)
    assert STORE not in str(normalized)
    rule = Rule(id="bulk", title="bulk", description="Synthetic",
                level="critical", technique_id="bulk", product="aws",
                selection={"event.source": "healthlake.amazonaws.com",
                           "event.name": "StartFHIRBulkDeleteJob",
                           "event.outcome": "success",
                           "request.healthlake_fhir_bulk_delete_submitted": True})
    assert len(detect_aws_events([raw], (rule,))) == 1
    for change in (
        lambda x: x["requestParameters"].update(bulkDeleteType="purge_Patient_" + SECRET),
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x["responseElements"].update(statusCode=403),
    ):
        candidate = deepcopy(raw)
        change(candidate)
        assert normalize_bulk_delete(candidate) is None


def test_conditional_delete_uses_search_key_without_leaking_value():
    raw = delete_row()
    raw["eventName"] = "DeleteResource"
    raw["requestParameters"] = {"datastoreId": STORE,
                                "resourceType": "Patient", "resourceId": SECRET,
                                "queryStrings": {"identifier": SECRET},
                                "headers": {"authorization": SECRET}}
    raw["responseElements"] = {"statusCode": 204}
    normalized = normalize_conditional_delete(raw)
    assert normalized is not None
    assert normalized["request.healthlake_conditional_delete_by_identifier"] is True
    assert SECRET not in str(normalized) and STORE not in str(normalized)
    rule = Rule(id="conditional", title="conditional", description="Synthetic",
                level="high", technique_id="conditional", product="aws",
                selection={"event.source": "healthlake.amazonaws.com",
                           "event.name": "DeleteResource", "event.outcome": "success",
                           "request.healthlake_conditional_delete_by_identifier": True})
    assert len(detect_aws_events([raw], (rule,))) == 1
    for change in (
        lambda x: x["requestParameters"].pop("queryStrings"),
        lambda x: x["requestParameters"].update(queryStrings={"_format": "json"}),
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x["responseElements"].update(statusCode=403),
    ):
        candidate = deepcopy(raw)
        change(candidate)
        assert normalize_conditional_delete(candidate) is None
