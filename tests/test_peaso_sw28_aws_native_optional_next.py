"""Registered AWS native checks must honor selected fact coverage."""
import pytest
from peaso.checks import evaluate_check


def check(cid, item):
    return evaluate_check(cid, item)[0]


def marked(value, field, marker):
    return {**value, "_coverage": {field: marker}}


@pytest.mark.parametrize("marker", [None, {"status": "denied"}, {"status": "collected"}])
def test_retention_unreadable_omission_unknown(marker):
    assert check("aws.logs.retention", {"logGroupName": "audit", "_coverage": {"retentionInDays": marker}}) == "UNKNOWN"


def test_retention_native_omission_and_empty_marker_fail():
    assert check("aws.logs.retention", {"logGroupName": "audit"}) == "FAIL"
    assert check("aws.logs.retention", {"logGroupName": "audit", "_coverage": {"retentionInDays": {"status": "empty", "source": "describe_log_groups"}}}) == "FAIL"


def test_versioning_unreadable_status_cannot_pass():
    config = marked({"Status": "Enabled"}, "Status", {"status": "denied"})
    assert check("aws.s3.versioning", {"Versioning": config}) == "UNKNOWN"


def test_versioning_unreadable_omission_cannot_fail():
    assert check("aws.s3.versioning", {"Versioning": {"_coverage": {"Status": None}}}) == "UNKNOWN"


def test_logging_unreadable_enabled_omission_cannot_fail():
    assert check("aws.s3.access_logging", {"Logging": {"_coverage": {"LoggingEnabled": {"status": "denied"}}}}) == "UNKNOWN"


def test_logging_unreadable_target_cannot_pass():
    enabled = marked({"TargetBucket": "audit"}, "TargetBucket", {"status": "denied"})
    assert check("aws.s3.access_logging", {"Logging": {"LoggingEnabled": enabled}}) == "UNKNOWN"


def test_acl_unreadable_uri_cannot_prove_public_or_private():
    for uri, expected_old in [("http://acs.amazonaws.com/groups/global/AllUsers", "MANUAL"), ("other", "PASS")]:
        grantee = marked({"URI": uri}, "URI", {"status": "denied"})
        assert check("aws.s3.no_public_acl", {"Acl": {"Grants": [{"Grantee": grantee}]}}) == "UNKNOWN"


def test_acl_known_public_grant_survives_unknown_peer():
    public = {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}
    uncertain = {"Grantee": {"_coverage": {"URI": {"status": "denied"}}}}
    for rows in ([uncertain, public], [public, uncertain]):
        assert check("aws.s3.no_public_acl", {"Acl": {"Grants": rows}}) == "MANUAL"


def test_kms_unreadable_applicability_fields_cannot_skip():
    metadata = {"KeyManager": "AWS", "Origin": "AWS_KMS", "KeySpec": "SYMMETRIC_DEFAULT",
                "_coverage": {"KeyManager": {"status": "denied"}}}
    assert check("aws.kms.rotation", {"Metadata": {"KeyMetadata": metadata}}) == "UNKNOWN"


def test_trail_unreadable_advanced_selectors_cannot_manual():
    selectors = marked({"AdvancedEventSelectors": [{"Name": "custom"}]}, "AdvancedEventSelectors", {"status": "denied"})
    assert check("aws.cloudtrail.management_events", {"EventSelectors": selectors}) == "UNKNOWN"


def test_trail_unreadable_read_write_cannot_pass():
    row = marked({"IncludeManagementEvents": True, "ReadWriteType": "All"}, "ReadWriteType", {"status": "denied"})
    assert check("aws.cloudtrail.management_events", {"EventSelectors": {"EventSelectors": [row]}}) == "UNKNOWN"


def test_trail_unreadable_exclusion_cannot_pass():
    row = marked({"IncludeManagementEvents": True, "ReadWriteType": "All", "ExcludeManagementEventSources": []},
                 "ExcludeManagementEventSources", {"status": "denied"})
    assert check("aws.cloudtrail.management_events", {"EventSelectors": {"EventSelectors": [row]}}) == "UNKNOWN"


def test_trail_complete_row_survives_unknown_peer():
    good = {"IncludeManagementEvents": True, "ReadWriteType": "All"}
    uncertain = marked(dict(good), "ReadWriteType", {"status": "denied"})
    for rows in ([uncertain, good], [good, uncertain]):
        assert check("aws.cloudtrail.management_events", {"EventSelectors": {"EventSelectors": rows}}) == "PASS"


def test_key_count_unreadable_status_cannot_prove_pass():
    key = marked({"Status": "Inactive"}, "Status", {"status": "denied"})
    assert check("aws.iam.access_key_count", {"AccessKeys": {"items": [key]}}) == "UNKNOWN"


def test_key_count_known_two_active_survive_uncertain_peer():
    unknown = marked({"Status": "Inactive"}, "Status", {"status": "denied"})
    for keys in ([unknown, {"Status": "Active"}, {"Status": "Active"}],
                 [{"Status": "Active"}, {"Status": "Active"}, unknown]):
        assert check("aws.iam.access_key_count", {"AccessKeys": {"items": keys}}) == "FAIL"


def test_frozen_defaults_and_global_gates():
    assert check("aws.s3.versioning", {"Versioning": {"_coverage": {"Status": {"status": "empty", "source": "api"}}}}) == "FAIL"
    assert check("aws.s3.access_logging", {"Logging": {"_coverage": {"LoggingEnabled": {"status": "empty", "source": "api"}}}}) == "FAIL"
    assert check("aws.s3.no_public_acl", {"Acl": {"Grants": [{"Grantee": {"ID": "private"}}]}}) == "PASS"
    assert check("aws.s3.versioning", {"Versioning": {"Status": "Enabled"}, "collection_status": "denied"}) == "UNKNOWN"
    assert check("aws.iam.access_key_count", {"AccessKeys": {"items": [{"Status": "Active"}, {"Status": "Active"}]}}) == "FAIL"


@pytest.mark.parametrize("field,value", [("Origin", "EXTERNAL"), ("KeySpec", "RSA_2048")])
def test_kms_other_unreadable_applicability_fields_cannot_skip(field, value):
    metadata = {"KeyManager": "CUSTOMER", "Origin": "AWS_KMS", "KeySpec": "SYMMETRIC_DEFAULT"}
    metadata[field] = value
    metadata["_coverage"] = {field: {"status": "denied"}}
    assert check("aws.kms.rotation", {"Metadata": {"KeyMetadata": metadata}}) == "UNKNOWN"


def test_trail_unreadable_exclusion_omission_cannot_pass():
    row = {"IncludeManagementEvents": True, "ReadWriteType": "All",
           "_coverage": {"ExcludeManagementEventSources": None}}
    assert check("aws.cloudtrail.management_events", {"EventSelectors": {"EventSelectors": [row]}}) == "UNKNOWN"


def test_key_count_unreadable_active_status_cannot_prove_failure():
    key = marked({"Status": "Active"}, "Status", {"status": "denied"})
    assert check("aws.iam.access_key_count", {"AccessKeys": {"items": [{"Status": "Active"}, key]}}) == "UNKNOWN"


def test_frozen_selected_valid_verdicts():
    assert check("aws.s3.versioning", {"Versioning": {"Status": "Enabled"}}) == "PASS"
    assert check("aws.s3.access_logging", {"Logging": {"LoggingEnabled": {"TargetBucket": "audit"}}}) == "PASS"
    assert check("aws.s3.no_public_acl", {"Acl": {"Grants": [{"Grantee": {
        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}}) == "MANUAL"
    metadata = {"KeyManager": "CUSTOMER", "Origin": "AWS_KMS", "KeySpec": "SYMMETRIC_DEFAULT"}
    assert check("aws.kms.rotation", {"Metadata": {"KeyMetadata": metadata},
        "Rotation": {"KeyRotationEnabled": True}}) == "PASS"
    assert check("aws.kms.rotation", {"Metadata": {"KeyMetadata": {**metadata, "Origin": "EXTERNAL"}}}) == "NOT_APPLICABLE"
    assert check("aws.cloudtrail.management_events", {"EventSelectors": {
        "AdvancedEventSelectors": [{"Name": "custom"}]}}) == "MANUAL"
    assert check("aws.cloudtrail.management_events", {"EventSelectors": {"EventSelectors": []}}) == "FAIL"
    assert check("aws.iam.access_key_count", {"AccessKeys": {"items": [{"Status": "Active"}]}}) == "PASS"
    assert check("aws.logs.retention", {"logGroupName": "audit", "retentionInDays": 90}) == "PASS"
