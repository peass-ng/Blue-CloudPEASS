"""Inert differential truth cases for individually reviewed invalid predicates.

These do not execute upstream SQL/check/runtime or call AWS. They express the
precise inspected CASE/JOIN/WHERE literals on benign typed synthetic facts.
"""
import pytest


@pytest.mark.parametrize("read_write", ["ReadOnly", "WriteOnly", "All"])
def test_s3_selector_source_can_pass_on_stopped_trail_and_different_bucket_prefix(read_write):
    destination = "arn:aws:s3:::audit"
    selector_value = "arn:aws:s3:::audit-other/"
    trail = {"IsMultiRegionTrail": True, "IsLogging": False,
        "EventSelector": {"ReadWriteType": read_write, "DataResources": [{"Type": "AWS::S3::Object", "Values": [selector_value]}]}}
    # Inspected SQL does not test IsLogging, and its JOIN is bucket_selector
    # LIKE bucket.arn||'%' rather than an exact bucket ARN boundary.
    joined = selector_value.startswith(destination)
    assert joined and trail["IsMultiRegionTrail"]
    assert not trail["IsLogging"]
    assert selector_value.split(":::", 1)[1].split("/", 1)[0] != destination.split(":::", 1)[1]


def test_readwrite_trail_source_accepts_data_only_selector_as_management_audit():
    selector = {"ReadWriteType": "All", "IncludeManagementEvents": False,
        "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::audit/"]}]}
    source_ok = True and True and selector["ReadWriteType"] == "All"  # logging, multi-region, selector type.
    assert source_ok
    assert selector["IncludeManagementEvents"] is False
    # The advanced branch similarly accepts Data eventCategory when readOnly
    # is absent, with no eventCategory=Management assertion.
    advanced = {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "eventName", "Equals": ["PutObject"]}]}
    import json
    assert "readOnly" not in json.dumps(advanced)


def test_support_role_where_filter_can_remove_the_account_before_count_zero():
    accounts = ["123456789012"]
    attached = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
    surviving = [policy for policy in attached if policy.split("/")[1] == "AWSSupportAccess" or policy is None]
    assert accounts and attached and surviving == []
    # GROUP BY on the filtered empty relation has no count0 account row, so the
    # inspected final CASE cannot emit its intended alarm for this account.
    grouped_accounts = {accounts[0]: len(surviving)} if surviving else {}
    assert grouped_accounts == {}
    counterfeit = "arn:aws:iam::123456789012:policy/AWSSupportAccess"
    assert counterfeit.split("/")[1] == "AWSSupportAccess"
    assert counterfeit != "arn:aws:iam::aws:policy/AWSSupportAccess"


def test_tag_policy_grouped_count_can_never_emit_the_source_alarm_branch():
    policies = [{"Type": "SERVICE_CONTROL_POLICY"}]
    filtered = [policy for policy in policies if policy["Type"] == "TAG_POLICY"]
    groups = {"123456789012": len(filtered)} if filtered else {}
    assert groups == {}
    assert all(count > 0 for count in groups.values())


def test_contact_sets_count_missing_contact_none_as_a_distinct_valid_contact():
    primary = {"Name": "primary", "Phone": "111"}
    billing = {"Name": "billing", "Phone": "222", "Email": "billing@example.invalid"}
    security = {"Name": "security", "Phone": "333", "Email": "security@example.invalid"}
    missing_operations = {"Name": None, "Phone": None, "Email": None}
    names = {row["Name"] for row in (primary, billing, security, missing_operations)}
    phones = {row["Phone"] for row in (primary, billing, security, missing_operations)}
    emails = {row["Email"] for row in (billing, security, missing_operations)}
    assert len(names) == len(phones) == 4 and len(emails) == 3
    assert missing_operations["Name"] is None


def test_analyzer_v1_validation_failure_is_not_zero_active_findings():
    analyzer = {"status": "ACTIVE", "type": "ACCOUNT_UNUSED_ACCESS", "findings": []}
    actual_v2_findings = [{"status": "ACTIVE", "findingType": "UnusedPermission"}]
    # Pinned service catches V1 ValidationException and leaves findings=[];
    # check then reports PASS. Current API docs require V2 for this analyzer.
    source_pass = analyzer["status"] == "ACTIVE" and not analyzer["findings"]
    assert source_pass and any(row["status"] == "ACTIVE" for row in actual_v2_findings)


def test_prowler_metric_alarm_helper_ignores_different_dimension_metric_identity():
    metric_filter = {"metric": "SecurityEvents", "namespace": "Audit", "region": "us-east-1", "dimensions": {}}
    alarm = {"metric": "SecurityEvents", "namespace": "Audit", "region": "us-east-1", "dimensions": {"Environment": "Unrelated"}}
    source_matches = (alarm["metric"] == metric_filter["metric"] and alarm["region"] == metric_filter["region"] and
        (not metric_filter["namespace"] or not alarm["namespace"] or alarm["namespace"] == metric_filter["namespace"]))
    assert source_matches
    assert alarm["dimensions"] != metric_filter["dimensions"]
    # CloudWatch does not aggregate custom metrics across dimensions: this
    # alarm is a different metric, even after source namespace/region fixes.


def test_access_key_aka_substring_join_confuses_username_prefix_and_omits_user_paths():
    import json
    prefix_user = "arn:aws:iam::123456789012:user/reviewer"
    key_akas = ["arn:aws:iam::123456789012:user/reviewer/accesskey/inertA",
        "arn:aws:iam::123456789012:user/reviewer-extra/accesskey/inertB"]
    assert sum(prefix_user in json.dumps([aka]) for aka in key_akas) == 2
    # Different users each have exactly one key, but LIKE '%userARN%' counts2
    # for the shorter username. The plugin AKA also omits the user's path.
    path_user = "arn:aws:iam::123456789012:user/team/reviewer"
    assert all(path_user not in json.dumps([aka]) for aka in key_akas)


def test_ssl_source_deny_unrelated_action_does_not_enforce_https_for_objects():
    statement = {"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteBucket", "Resource": "arn:aws:s3:::audit",
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
    # Pinned query enumerates Action/Resource but never restricts either alias.
    source_ok = statement["Effect"] == "Deny" and statement["Principal"] == "*" and statement["Condition"]["Bool"]["aws:SecureTransport"] == "false"
    assert source_ok
    assert statement["Action"] != "s3:GetObject" and statement["Resource"] != "arn:aws:s3:::audit/*"


def test_cancelled_macie_job_and_public_policy_only_trail_bucket_false_pass():
    job = {"jobStatus": "CANCELLED", "s3JobDefinition": {"bucketDefinitions": [{"accountId": "123456789012", "buckets": ["audit"]}]}}
    source_bucket_list = [bucket for definition in job["s3JobDefinition"]["bucketDefinitions"] for bucket in definition["buckets"]]
    assert "audit" in source_bucket_list and job["jobStatus"] == "CANCELLED"
    bucket = {"Acl": {"Grants": []}, "PolicyStatus": {"IsPublic": True}, "PublicAccessBlock": False}
    source_acl_only_pass = not any(grant.get("Grantee", {}).get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers" for grant in bucket["Acl"]["Grants"])
    assert source_acl_only_pass and bucket["PolicyStatus"]["IsPublic"]


def test_valid_macie_criteria_job_covering_bucket_is_missed_by_definitions_only_query():
    job = {"jobStatus": "RUNNING", "s3JobDefinition": {"bucketCriteria": {"includes": {"and": [{"simpleCriterion": {"comparator": "EQ", "key": "S3_BUCKET_NAME", "values": ["audit"]}}]}}}}
    criterion = job["s3JobDefinition"]["bucketCriteria"]["includes"]["and"][0]["simpleCriterion"]
    assert criterion["comparator"] == "EQ" and "audit" in criterion["values"]
    assert job["s3JobDefinition"].get("bucketDefinitions") is None
    # Official API allows criteria OR definitions, never both. The pinned SQL
    # expands only BucketDefinitions, so this complete valid job emits no row.


def test_security_trail_sql_null_basic_selectors_skips_management_conditions():
    selectors = None  # Advanced selectors and basic selectors are mutually exclusive.
    sql_not = lambda value: None if value is None else not value
    source_management_clause = sql_not(None if selectors is None else len(selectors) == 1)
    assert source_management_clause is None
    assert not bool(source_management_clause)  # SQL CASE WHEN unknown does not alarm.
    advanced = {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}]}
    assert advanced["FieldSelectors"][0]["Equals"] == ["Data"]


@pytest.mark.parametrize("family,denominator,threshold,action_count", [("enumeration",92,0.3,28),("llm_jacking",14,0.4,6),("privilege_escalation",51,0.2,11)])
def test_activity_region_and_dropped_page_can_hide_actor_above_exact_source_ratio(family,denominator,threshold,action_count):
    from peaso.collectors.aws import ACTIVITY_ACTIONS
    assert len(ACTIVITY_ACTIONS[family])==denominator
    observed={"us-east-1":{},"eu-west-1":{"inert-reviewer":set(range(action_count))}}
    first_multiregion_trail_region="us-east-1"
    assert all(len(actions)/denominator<=threshold for actions in observed[first_multiregion_trail_region].values())
    assert len(observed["eu-west-1"]["inert-reviewer"])/denominator>threshold
    first_page={"Events":[],"NextToken":"older-page"}
    second_page={"Events":[{"actor":"inert-reviewer"}]}
    assert first_page.get("Events")==[] and second_page["Events"]


def test_bedrock_data_type_without_all_field_constraints_is_not_logging_coverage():
    fields=[{"Field":"eventCategory","Equals":["Data"]},{"Field":"resources.type","Equals":["AWS::Bedrock::Model"]},{"Field":"eventName","Equals":["PutObject"]}]
    source_category=any(field["Field"]=="eventCategory" and "Data" in field["Equals"] for field in fields)
    source_type=any(field["Field"]=="resources.type" and "AWS::Bedrock::Model" in field["Equals"] for field in fields)
    assert source_category and source_type
    # Pinned Bedrock data branch ignores eventName, eventSource and resourceARN
    # constraints. PutObject is an S3 data event, not a Bedrock model event.
    emitted_bedrock_event={"eventCategory":"Data","resources.type":"AWS::Bedrock::Model","eventName":"InvokeModelWithBidirectionalStream"}
    assert emitted_bedrock_event["eventName"] not in fields[2]["Equals"]


def test_prowler_loggroup_public_policy_flags_deny_resources_and_misses_globs():
    import fnmatch
    actual="arn:aws:logs:us-east-1:123456789012:log-group:/aws/inert:*"
    pattern="arn:aws:logs:us-east-1:123456789012:log-group:/aws/*"
    assert fnmatch.fnmatchcase(actual,pattern)
    assert actual not in pattern and pattern!="*"
    statements=[{"Effect":"Allow","Principal":"*","Resource":"arn:aws:logs:us-east-1:123456789012:log-group:public:*"},
        {"Effect":"Deny","Principal":"*","Resource":actual}]
    whole_policy_is_public=True
    source_flags=whole_policy_is_public and any(actual in row["Resource"] or row["Resource"]=="*" for row in statements)
    assert source_flags and statements[1]["Effect"]=="Deny"
