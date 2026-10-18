"""CloudTrail SQL variants preserve home-region and captured-date semantics."""
from datetime import datetime, timedelta, timezone

from . import register, result, unknown, statements, array
from .facts import get, Unavailable, list_of_objects
from .fixtures import CASES
from .aws_a_facts import captured_clock, api_optional
from .aws_a_cloudwatch import LOG_PROVENANCE
from .aws_a_cloudtrail import trail_bucket

NATIVE_IDS = []
BASE = {"Name": "audit", "Region": "us-east-1", "HomeRegion": "us-east-1"}
COMPLETE = {"operation": "cloudtrail:DescribeTrails", "native_response_complete": True}
CLOCK = {"context": {"created_at": "2026-10-10T12:00:00+00:00"}}


def home(item):
    region, home_region = get(item, "Region", str), get(item, "HomeRegion", str)
    return region == home_region


@register("aws.a.cloudtrail.home_kms_encryption", "aws", "hardening", "cloudtrail", "Home-region CloudTrail trail declares KMS encryption",
    "medium", "SC-13", "Associate an approved KMS key with the trail and review key policy separately.")
def kms(item, index):
    if not home(item):
        return "NOT_APPLICABLE", {"reason": "Source home-region filter"}
    key = get(item, "KmsKeyId", str)
    return result(not bool(key), kms_key_declared=bool(key))
CASES["aws.a.cloudtrail.home_kms_encryption"] = {"pass": {**BASE, "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/inert"},
    "fail": {**BASE, "KmsKeyId": ""}, "missing": {}, "malformed": None,
    "not_applicable": {**BASE, "Region": "eu-west-1"}}
NATIVE_IDS.append("aws.a.cloudtrail.home_kms_encryption")


@register("aws.a.cloudtrail.home_logging_with_insights", "aws", "hardening", "cloudtrail", "Home-region CloudTrail trail logs with Insights selectors",
    "medium", "AU-6", "Review trail logging and appropriate Insights selectors together.")
def logging_insights(item, index):
    if not home(item):
        return "NOT_APPLICABLE", {"reason": "Source home-region filter"}
    logging = get(item, "Status.IsLogging", bool)
    if not logging:
        return result(True, logging=False)
    config = get(item, "InsightSelectors", dict)
    if config.get("collection_status") == "empty" and config.get("absent") is True:
        selectors = []
    else:
        selectors = get(config, "InsightSelectors", list)
        if any(not isinstance(row, dict) or not isinstance(row.get("InsightType"), str) for row in selectors):
            return unknown("malformed Insights selectors")
    return result(not logging or not bool(selectors), logging=logging, insight_selector_count=len(selectors))
INSIGHTS = {"InsightSelectors": [{"InsightType": "ApiCallRateInsight"}]}
CASES["aws.a.cloudtrail.home_logging_with_insights"] = {"pass": {**BASE, "Status": {"IsLogging": True}, "InsightSelectors": INSIGHTS},
    "fail": {**BASE, "Status": {"IsLogging": False}, "InsightSelectors": INSIGHTS}, "missing": {}, "malformed": None,
    "not_applicable": {**BASE, "Region": "eu-west-1"}}
NATIVE_IDS.append("aws.a.cloudtrail.home_logging_with_insights")


for multi in (False, True):
    def install(multi=multi):
        cid = "aws.a.cloudtrail.home_multiregion_cloudwatch_date" if multi else "aws.a.cloudtrail.home_cloudwatch_date"
        @register(cid, "aws", "hardening", "cloudtrail", "Home-region " + ("multi-region " if multi else "") + "trail delivers to CloudWatch after the captured previous date",
            "medium", "AU-2", "Review CloudWatch integration and latest delivery against the captured UTC date boundary.")
        def evaluate(item, index):
            if not home(item):
                return "NOT_APPLICABLE", {"reason": "Source home-region filter"}
            if multi and not get(item, "IsMultiRegionTrail", bool):
                return "NOT_APPLICABLE", {"reason": "Source multi-region-only filter"}
            # The collector projects successful optional omissions explicitly;
            # no response or denied detail cannot establish absence.
            if "CloudWatchLogsLogGroupArn" not in item:
                key = api_optional(item, "CloudWatchLogsLogGroupArn", str, "", operation="cloudtrail:DescribeTrails")
            else:
                key = get(item, "CloudWatchLogsLogGroupArn", str)
            if not key or key == "null":
                return result(True, integration_declared=False)
            status = get(item, "Status", dict)
            if "LatestCloudWatchLogsDeliveryTime" not in status:
                if status.get("collection_status") != "collected":
                    raise Unavailable("CloudWatch latest delivery omission not proven")
                return result(True, delivery="absent")
            delivered = datetime.fromisoformat(get(status, "LatestCloudWatchLogsDeliveryTime", str).replace("Z", "+00:00"))
            if delivered.tzinfo is None:
                raise Unavailable("delivery timestamp lacks timezone")
            cutoff = captured_clock(item, index).astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
            return result(not bool(key) or key == "null" or delivered <= cutoff, delivery_at=delivered.isoformat(), cutoff=cutoff.isoformat(), comparison=">", integration_declared=bool(key))
        good = {**BASE, "IsMultiRegionTrail": True, "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:audit", "Status": {"LatestCloudWatchLogsDeliveryTime": "2026-10-09T00:00:01+00:00"}}
        bad = {**good, "Status": {"LatestCloudWatchLogsDeliveryTime": "2026-10-09T00:00:00+00:00"}}
        CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None, "index": CLOCK,
            "not_applicable": {**BASE, "Region": "eu-west-1"}}
        NATIVE_IDS.append(cid)
    install()


@register("aws.a.cloudwatch.finite_retention_365", "aws", "hardening", "log_group", "CloudWatch log group has an explicit retention of at least 365 days",
    "medium", "AU-11", "Set an explicit retention of at least365days when required by this source policy.")
def finite_retention(item, index):
    get(item, "logGroupName", str)
    days = api_optional(item, "retentionInDays", int, None, operation="logs:DescribeLogGroups")
    if days is not None and days <= 0:
        return unknown("invalid native retention duration")
    return result(days is None or days < 365, retention_days=days, source_requires_explicit_retention=True)
CASES["aws.a.cloudwatch.finite_retention_365"] = {"pass": {"logGroupName": "audit", "retentionInDays": 365},
    "fail": {"logGroupName": "audit", "_provenance": LOG_PROVENANCE}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.cloudwatch.finite_retention_365")


@register("aws.a.cloudtrail.home_bucket_access_logging", "aws", "hardening", "cloudtrail", "Home-region trail's joined in-account bucket has access logging",
    "medium", "AU-2", "Review access logging of the verified trail destination bucket.", dependencies=["cloudtrail", "bucket"])
def bucket_access_logging(item, index):
    if not home(item):
        return "NOT_APPLICABLE", {"reason": "Source home-region filter"}
    bucket = trail_bucket(item, index)
    if bucket is None:
        return "NOT_APPLICABLE", {"reason": "Pinned INNER JOIN emits no destination bucket outside complete account inventory"}
    config = get(bucket, "Logging", dict)
    if "LoggingEnabled" not in config:
        if config.get("collection_status") != "collected":
            raise Unavailable("bucket logging absence not proven")
        return result(True, bucket_access_logging=False)
    get(config, "LoggingEnabled", dict)
    return result(False, bucket_access_logging=True)
BUCKET_GOOD = {"Name": "audit-bucket", "Logging": {"LoggingEnabled": {"TargetBucket": "access-logs"}}}
BUCKET_BAD = {"Name": "audit-bucket", "Logging": {"collection_status": "collected"}}
from .aws_a_facts import scope_fixture
CASES["aws.a.cloudtrail.home_bucket_access_logging"] = {"pass": {**BASE, "S3BucketName": "audit-bucket"}, "fail": {**BASE, "S3BucketName": "audit-bucket"},
    "missing": {}, "malformed": None, "index": {**scope_fixture("bucket", [BUCKET_GOOD]), "context": {"scope": "123456789012/us-east-1"}},
    "fail_index": {**scope_fixture("bucket", [BUCKET_BAD]), "context": {"scope": "123456789012/us-east-1"}},
    "not_applicable": {**BASE, "Region": "eu-west-1"}}
NATIVE_IDS.append("aws.a.cloudtrail.home_bucket_access_logging")


@register("aws.a.cloudtrail.joined_bucket_declared_public_grants", "aws", "exposure", "cloudtrail", "In-scope trail destination bucket avoids source-declared public ACL and policy principals",
    "high", "AC-3", "Review declared public ACL/policy grants and their separate preventive controls and conditions.", dependencies=["cloudtrail", "bucket"])
def bucket_public_grants(item, index):
    bucket = trail_bucket(item, index)
    if bucket is None:
        return "NOT_APPLICABLE", {"reason": "Pinned LEFT JOIN explicitly skips destination outside complete account bucket inventory"}
    acl_public, policy_public, unavailable = [], [], []
    try:
        for grant in list_of_objects(get(bucket, "Acl.Grants", list)):
            grantee = get(grant, "Grantee", dict)
            uri = grantee.get("URI")
            if uri is not None and not isinstance(uri, str):
                raise Unavailable("malformed ACL group URI")
            if uri and any(uri.endswith("acs.amazonaws.com/groups/global/" + group) for group in ("AllUsers", "AuthenticatedUsers")):
                acl_public.append(uri)
    except Unavailable as exc:
        unavailable.append(str(exc))
    try:
        policy = get(bucket, "Policy", dict)
        if not (policy.get("collection_status") == "empty" and policy.get("absent") is True):
            for statement in statements(get(policy, "Policy")):
                effect = get(statement, "Effect", str)
                if effect not in {"Allow", "Deny"}:
                    raise Unavailable("invalid source policy Effect")
                if effect != "Allow":
                    continue
                principal = statement.get("Principal")
                aws = principal.get("AWS", []) if isinstance(principal, dict) else principal if isinstance(principal, str) else []
                principals = array(aws)
                if any(not isinstance(value, str) for value in principals):
                    raise Unavailable("malformed AWS principals")
                if "*" in principals:
                    policy_public.append("AWS:*")
    except (Unavailable, ValueError, TypeError) as exc:
        unavailable.append(type(exc).__name__)
    if acl_public or policy_public:
        return result(True, public_acl_groups=acl_public, wildcard_allow_principals=policy_public,
            semantics="Exact declared source grants; conditions, denies and Block Public Access are not effective-access tests")
    if unavailable:
        return unknown("source grant inventories incomplete", unavailable=unavailable)
    return result(False, public_acl_groups=[], wildcard_allow_principals=[])
PRIVATE_BUCKET = {"Name": "audit-bucket", "Acl": {"Grants": []}, "Policy": {"collection_status": "empty", "absent": True}}
PUBLIC_BUCKET = {**PRIVATE_BUCKET, "Acl": {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}}]}}
CASES["aws.a.cloudtrail.joined_bucket_declared_public_grants"] = {"pass": {"S3BucketName": "audit-bucket"}, "fail": {"S3BucketName": "audit-bucket"}, "missing": {}, "malformed": None,
    "index": {**scope_fixture("bucket", [PRIVATE_BUCKET]), "context": {"scope": "123456789012/us-east-1"}},
    "fail_index": {**scope_fixture("bucket", [PUBLIC_BUCKET]), "context": {"scope": "123456789012/us-east-1"}}}
NATIVE_IDS.append("aws.a.cloudtrail.joined_bucket_declared_public_grants")


@register("aws.a.cloudtrail.home_bucket_mfa_join","aws","hardening","cloudtrail","Home-region trail destination has MFA Delete verified in the account bucket inventory",
    "medium","AU-9","Review account-scoped destination MFA Delete; a missing joined bucket needs owner verification rather than inferred remote configuration.",dependencies=["cloudtrail","bucket"])
def home_bucket_mfa_join(item,index):
    if not home(item):
        return "NOT_APPLICABLE",{"reason":"Pinned source home-region filter"}
    bucket_name=api_optional(item,"S3BucketName",str,None,operation="cloudtrail:DescribeTrails")
    if bucket_name is None:
        return result(True,reason="Pinned source explicit NULL destination alarm")
    bucket=trail_bucket(item,index)
    if bucket is None:
        return result(True,reason="Pinned source LEFT JOIN found no bucket in complete account inventory",remote_mfa_delete="unknown",semantics="Failure of source in-scope verification requirement; no assertion that a remote bucket's MFA is disabled")
    return mfa_delete_from_bucket(bucket)


def mfa_delete_from_bucket(bucket):
    config=get(bucket,"Versioning",dict)
    if "MFADelete" not in config:
        if config.get("collection_status")!="collected":
            raise Unavailable("MFA Delete absence not proven")
        return result(True,mfa_delete="not_reported")
    value=get(config,"MFADelete",str)
    if value not in {"Enabled","Disabled"}:
        return unknown("unrecognized MFA Delete state")
    return result(value!="Enabled",mfa_delete=value)
MFA_GOOD={"Name":"audit-bucket","Versioning":{"MFADelete":"Enabled"}}
MFA_BAD={"Name":"audit-bucket","Versioning":{"collection_status":"collected"}}
CASES["aws.a.cloudtrail.home_bucket_mfa_join"]={"pass":{**BASE,"S3BucketName":"audit-bucket"},"fail":{**BASE,"S3BucketName":"audit-bucket"},"missing":{},"malformed":None,
    "index":{**scope_fixture("bucket",[MFA_GOOD]),"context":{"scope":"123456789012/us-east-1"}},"fail_index":{**scope_fixture("bucket",[MFA_BAD]),"context":{"scope":"123456789012/us-east-1"}},"not_applicable":{**BASE,"Region":"eu-west-1"}}
NATIVE_IDS.append("aws.a.cloudtrail.home_bucket_mfa_join")
