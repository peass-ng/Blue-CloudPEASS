"""Synthetic derivatives of two disposable Inspector filter lifecycles."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
NAME = "synthetic-inspector-filter"
ARN = f"arn:aws:inspector2:{REGION}:{ACCOUNT}:owner/{ACCOUNT}/filter/syntheticfilter"
CRITERIA_A = {"resourceId": [{"comparison": "EQUALS", "value": "i-00000000000000000"}]}
CRITERIA_B = {"resourceId": [{"comparison": "EQUALS", "value": "i-00000000000000001"}]}
IDS = {
    "aws-inspector-suppression-filter-created",
    "aws-inspector-suppression-filter-updated",
    "aws-inspector-suppression-criteria-changed",
    "aws-inspector-filter-tagged",
    "aws-inspector-filter-untagged",
    "aws-inspector-filter-deleted",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 6
    return selected


def event(name, second, request, response=None, *, error=None, account=ACCOUNT):
    result = {
        "eventSource": "inspector2.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": account, "awsRegion": REGION,
        "eventID": f"88888888-8888-4888-8888-{second:012d}",
        "eventTime": f"2026-10-21T08:15:{second:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": account,
                         "arn": f"arn:aws:sts::{account}:assumed-role/synthetic-lab/worker"},
        "requestParameters": request, "responseElements": response,
    }
    if error:
        result["errorCode"] = error
    return result


def sample():
    return [
        event("CreateFilter", 1, {"name": NAME, "action": "SUPPRESS",
              "filterCriteria": CRITERIA_A, "tags": {"synthetic-lab": "yes"}}, {"arn": ARN}),
        event("UpdateFilter", 3, {"filterArn": ARN, "action": "SUPPRESS",
              "filterCriteria": CRITERIA_B}, {"arn": ARN}),
        event("TagResource", 5, {"resourceArn": ARN, "tags": {"synthetic-state": "changed"}}),
        # CloudTrail flattened the one-element TagKeys array to a string.
        event("UntagResource", 7, {"resourceArn": ARN, "tagKeys": "synthetic-state"}),
        event("UpdateFilter", 9, {"filterArn": ARN, "action": "NONE"}, {"arn": ARN}),
        event("UpdateFilter", 11, {"filterArn": ARN, "action": "SUPPRESS"}, {"arn": ARN}),
        event("DeleteFilter", 13, {"arn": ARN}, {"arn": ARN}),
    ]


def hits(events):
    return [finding.technique_id for finding in detect_aws_events(events, rules())]


def test_synthetic_filter_lifecycle_matches_six_signals():
    detected = hits(sample())
    assert set(detected) == IDS
    assert len(detected) == 7
    assert detected.count("aws-inspector-suppression-filter-updated") == 2


def test_failed_or_foreign_filter_operations_are_rejected():
    rows = sample()
    rows[0]["errorCode"] = "AccessDeniedException"
    assert "aws-inspector-suppression-filter-created" not in hits(rows)
    assert "aws-inspector-suppression-criteria-changed" not in hits(rows)
    rows = sample()
    rows[1]["responseElements"]["arn"] = ARN.replace(ACCOUNT, "111111111111")
    assert hits(rows).count("aws-inspector-suppression-filter-updated") == 1
    assert "aws-inspector-suppression-criteria-changed" not in hits(rows)
    rows = sample()
    rows[2]["requestParameters"]["resourceArn"] = ARN.replace(ACCOUNT, "111111111111")
    assert "aws-inspector-filter-tagged" not in hits(rows)


def test_criteria_change_requires_prior_state_and_exact_filter():
    rows = sample()
    assert "aws-inspector-suppression-criteria-changed" not in hits(rows[1:])
    rows[1]["requestParameters"]["filterCriteria"] = CRITERIA_A
    assert "aws-inspector-suppression-criteria-changed" not in hits(rows)
    rows = sample()
    rows[0]["responseElements"]["arn"] = ARN.replace("syntheticfilter", "otherfilter")
    assert "aws-inspector-suppression-criteria-changed" not in hits(rows)


def test_deleted_filter_clears_correlation_and_duplicates_do_not_repeat_it():
    rows = sample()
    repeated = hits(rows + deepcopy(rows))
    assert repeated.count("aws-inspector-suppression-criteria-changed") == 1
    after = event("UpdateFilter", 15, {"filterArn": ARN, "action": "SUPPRESS",
             "filterCriteria": CRITERIA_A}, {"arn": ARN})
    assert hits(rows + [after]).count("aws-inspector-suppression-criteria-changed") == 1


def test_organization_owned_filter_arn_is_accepted():
    org_arn = ARN.replace(f"owner/{ACCOUNT}", "owner/o-1234567890ab")
    row = event("DeleteFilter", 1, {"arn": org_arn}, {"arn": org_arn})
    assert hits([row]) == ["aws-inspector-filter-deleted"]
