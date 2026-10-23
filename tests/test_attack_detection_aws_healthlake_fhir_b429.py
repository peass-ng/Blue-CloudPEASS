"""Synthetic derivatives of disposable HealthLake FHIR CloudTrail events."""

from copy import deepcopy

from peaso.attack_detection.aws_healthlake_fhir_b429 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
STORE = "a" * 32
PATIENT = "synthetic-patient-id"
QUERY = "synthetic-secret-query-value"
CASES = {
    "CreateResource": (False, 201, False),
    "UpdateResource": (False, 200, True),
    "DeleteResource": (False, 204, True),
    "ProcessBundle": (False, 200, False),
    "SearchEverything": (True, None, True),
    "SearchWithGet": (True, None, False),
    "SearchWithPost": (True, None, False),
    "ReadResource": (True, None, True),
    "GetHistoryByResourceId": (True, None, True),
}


def _row(name):
    readonly, status, needs_id = CASES[name]
    request = {"datastoreId": STORE, "headers": {"authorization": QUERY}}
    if name != "ProcessBundle":
        request["resourceType"] = "Patient"
    if needs_id:
        request["resourceId"] = PATIENT
    if name in ("SearchWithGet", "SearchWithPost"):
        request["queryStrings"] = {"identifier": QUERY}
    return {
        "eventSource": "healthlake.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": readonly,
        "eventID": "synthetic-" + name, "eventTime": "2026-10-23T02:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-reader"},
        "requestParameters": request,
        "responseElements": {"statusCode": status} if status else None,
    }


def test_nine_accepted_fhir_routes_match_without_clinical_identifiers():
    for name in CASES:
        row = _row(name)
        event = normalize(row)
        assert event is not None and event["request.healthlake_fhir_call"] is True
        assert STORE not in str(event) and PATIENT not in str(event)
        assert QUERY not in str(event)
        rule = Rule(id=name, title=name, description="Synthetic", level="medium",
                    technique_id=name, product="aws",
                    selection={"event.source": "healthlake.amazonaws.com",
                               "event.name": name, "event.outcome": "success",
                               "request.healthlake_fhir_call": True})
        hits = detect_aws_events([row], (rule,))
        assert len(hits) == 1
        assert PATIENT not in str(hits) and QUERY not in str(hits)


def test_errors_wrong_account_and_write_status_are_rejected():
    for name in CASES:
        for change in (
            lambda row: row.update(errorCode="ResourceNotFoundException"),
            lambda row: row["userIdentity"].update(accountId="111111111111"),
            lambda row: row.update(eventCategory="Data"),
            lambda row: row["requestParameters"].update(datastoreId="not-a-store"),
        ):
            row = deepcopy(_row(name))
            change(row)
            assert normalize(row) is None
    row = _row("UpdateResource")
    row["responseElements"]["statusCode"] = 403
    assert normalize(row) is None
    row = _row("SearchEverything")
    row["requestParameters"]["resourceType"] = "Observation"
    assert normalize(row) is None
