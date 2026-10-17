"""claude2_aws_a CloudTrail predicates: trail delivery, joined buckets, account presence, Bedrock and activity heuristics."""
from __future__ import annotations

import copy

from .claude2_aws_a_common import (
    ABSENT, ACCOUNT, CREATED, P, Unavailable, collected, complete_items, detail, get, home_copy, idx, install, list_of_objects,
    midnight_cutoff, not_home, parse_time, policy_document, principal_aws_values, result, rows_for, scope_account,
    scope_region, scope_subject, trail_bucket, unknown)

ARN = "arn:aws:cloudtrail:us-east-1:" + ACCOUNT + ":trail/audit"
TRAIL = {"Name": "audit", "TrailARN": ARN, "HomeRegion": "us-east-1", "IsMultiRegionTrail": True, "IsOrganizationTrail": False,
         "S3BucketName": "audit-logs", "KmsKeyId": "arn:aws:kms:us-east-1:" + ACCOUNT + ":key/k", "LogFileValidationEnabled": True,
         "HasInsightSelectors": True, "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:" + ACCOUNT + ":log-group:trail:*",
         "Status": {"collection_status": "collected", "IsLogging": True, "LatestCloudWatchLogsDeliveryTime": "2026-10-10T08:00:00+00:00"},
         "EventSelectors": {"collection_status": "collected", "EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True}]},
         "InsightSelectors": {"collection_status": "collected", "InsightSelectors": [{"InsightType": "ApiCallRateInsight"}]}}
SHADOW = {**TRAIL, "HomeRegion": "eu-west-1", "TrailARN": "arn:aws:cloudtrail:eu-west-1:" + ACCOUNT + ":trail/audit"}
PRIVATE_ACL = {"collection_status": "collected", "Grants": [{"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"}]}
BUCKET = {"Name": "audit-logs", "Acl": PRIVATE_ACL, "Policy": ABSENT,
          "Versioning": {"collection_status": "collected", "Status": "Enabled", "MFADelete": "Enabled"},
          "Logging": {"collection_status": "collected", "LoggingEnabled": {"TargetBucket": "access-logs", "TargetPrefix": ""}}}
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
B_IDX = idx(bucket=[BUCKET])
CT_DOCS = ["https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeTrails.html",
           "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html"]
S3_DOCS = ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html",
           "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html"]


def _bucket(**changes):
    out = copy.deepcopy(BUCKET)
    out.update(changes)
    return out


def _trail(**changes):
    out = copy.deepcopy(TRAIL)
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict) and not value.get("_replace"):
            out[key] = {**out[key], **value}
        else:
            out[key] = {k: v for k, v in value.items() if k != "_replace"} if isinstance(value, dict) else value
    return out


# --- cloudtrail_trail_bucket_mfa_enabled -------------------------------------------------------
@install("cloudtrail.trail_bucket_mfa_delete", "cloudtrail", "CloudTrail trail S3 bucket has MFA Delete enabled", {
    "pass": TRAIL, "fail": TRAIL, "index": B_IDX,
    "fail_index": idx(bucket=[_bucket(Versioning={"collection_status": "collected", "Status": "Enabled", "MFADelete": "Disabled"})]),
    "not_applicable": SHADOW, "outside": TRAIL, "outside_expect": "MANUAL", "outside_index": idx(bucket=[]),
    "unset": TRAIL, "unset_expect": "FAIL", "unset_index": idx(bucket=[_bucket(Versioning={"collection_status": "collected"})]),
    }, rows=rows_for("cloudtrail_trail_bucket_mfa_enabled"), severity="medium", control="AU-9", dependencies=["cloudtrail", "bucket"],
    remediation="Enable versioning with MFA Delete on the CloudTrail log bucket (root credentials are required).",
    docs=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html"],
    note="Home-region trail rows, logging or not. Deviation: a bucket outside the audited account is MANUAL (upstream left join alarms on an unknown bucket).")
def trail_bucket_mfa(item, index):
    if not home_copy(item, index):
        return not_home(item, index)
    bucket = trail_bucket(item, index)
    if bucket is None:
        return "MANUAL", {"bucket": get(item, "S3BucketName", str), "reason": "Trail bucket outside the audited account; verify MFA Delete manually"}
    versioning = get(bucket, "Versioning", dict)
    if "MFADelete" not in versioning:
        collected(versioning, "Versioning")
        return result(True, bucket=bucket["Name"], mfa_delete="not_reported")
    state = get(versioning, "MFADelete", str)
    if state not in ("Enabled", "Disabled"):
        return unknown("unrecognized MFA Delete state")
    return result(state != "Enabled", bucket=bucket["Name"], mfa_delete=state)


# --- cloudtrail_trail_enabled_account ----------------------------------------------------------
IDENTITY = {"Account": ACCOUNT, "Arn": "arn:aws:iam::" + ACCOUNT + ":role/audit", "UserId": "AROAEXAMPLE", "AccountId": ACCOUNT}
INV_TRAIL = {**TRAIL, "SourceRegion": "us-east-1"}
INV_OFF = {**INV_TRAIL, "Status": {"collection_status": "collected", "IsLogging": False}}


def _account_trails(item, index):
    account = get(item, "Account", str)
    if account != scope_account(index):
        raise Unavailable("account identity does not match the audited scope")
    return complete_items(index, "cloudtrail_account_inventory", get(index, "context.scope", str))


@install("cloudtrail.account_has_logging_trail", "aws_account", "Account has at least one logging CloudTrail trail (home-region status)", {
    "pass": IDENTITY, "fail": IDENTITY, "index": idx(cloudtrail_account_inventory=[INV_TRAIL]),
    "fail_index": idx(cloudtrail_account_inventory=[INV_OFF]),
    "none": IDENTITY, "none_expect": "FAIL", "none_index": idx(cloudtrail_account_inventory=[]),
    "partial": IDENTITY, "partial_expect": "UNKNOWN", "partial_index": idx(cloudtrail_account_inventory="partial"),
    "status_denied": IDENTITY, "status_denied_expect": "UNKNOWN",
    "status_denied_index": idx(cloudtrail_account_inventory=[{**INV_TRAIL, "Status": {"collection_status": "denied"}}]),
    }, rows=rows_for("cloudtrail_trail_enabled_account"), severity="high", control="AU-2", dependencies=["aws_account", "cloudtrail_account_inventory"],
    remediation="Create a multi-Region CloudTrail trail and start logging.", docs=CT_DOCS,
    note="Account-wide trail inventory across all enabled regions (not collected with explicit region lists, so UNKNOWN). Counts trails whose home-region copy is logging, as home_region = region and is_logging.")
def account_logging(item, index):
    trails = _account_trails(item, index)
    logging, unavailable = [], []
    for trail in trails:
        if get(trail, "SourceRegion", str) != get(trail, "HomeRegion", str):
            continue
        try:
            if get(trail, "Status.IsLogging", bool):
                logging.append(get(trail, "TrailARN", str))
        except Unavailable:
            unavailable.append(trail.get("TrailARN"))
    if logging:
        return result(False, logging_trails=sorted(logging))
    if unavailable:
        return unknown("trail status unavailable", trails=unavailable)
    return result(True, logging_trails=[])


# --- prowler cloudtrail_multi_region_enabled ---------------------------------------------------
_REGIONAL = {"scope": "123456789012/us-east-1"}
_LOCAL_OFF = {**TRAIL, "IsMultiRegionTrail": False, "Status": {"collection_status": "collected", "IsLogging": False}}


@install("cloudtrail.region_has_logging_trail", "cloudtrail", "Every region is covered by a logging CloudTrail trail", {
    "pass": _REGIONAL, "fail": _REGIONAL, "pass_index": idx(cloudtrail=[_LOCAL_OFF, SHADOW]), "fail_index": idx(cloudtrail=[_LOCAL_OFF]),
    "empty_trails": _REGIONAL, "empty_trails_expect": "FAIL", "empty_trails_index": idx(cloudtrail=[]),
    "status_unknown": _REGIONAL, "status_unknown_expect": "UNKNOWN",
    "status_unknown_index": idx(cloudtrail=[_LOCAL_OFF, {**SHADOW, "Status": {"collection_status": "denied"}}]),
    }, rows=[P + "cloudtrail_multi_region_enabled"], severity="high", control="AU-2", target="scope", dependencies=["cloudtrail"],
    remediation="Create a multi-Region trail (or a trail in every region) and ensure it is logging.", docs=CT_DOCS,
    note="Per audited region: trails homed in the region or multi-Region trails (shadow copies) are considered; PASS when any is logging.")
def region_logging(item, index):
    scope = scope_subject(item)
    region = scope.split("/", 1)[1]
    trails = complete_items(index, "cloudtrail", scope)
    unavailable = []
    for trail in trails:
        if get(trail, "HomeRegion", str) != region and get(trail, "IsMultiRegionTrail", bool) is not True:
            continue
        try:
            if get(trail, "Status.IsLogging", bool):
                return result(False, region=region, logging_trail=get(trail, "TrailARN", str))
        except Unavailable:
            unavailable.append(trail.get("TrailARN"))
    if unavailable:
        return unknown("trail status unavailable", trails=unavailable)
    return result(True, region=region, reason="No CloudTrail trails enabled with logging were found")


# --- prowler cloudtrail_threat_detection_* -----------------------------------------------------
# Pinned prowler defaults (61d2cc55), duplicates included because the ratio divides by len(list).
ENUMERATION = ["CreateIndex", "DescribeAccessEntry", "DescribeAccountAttributes", "DescribeAvailabilityZones", "DescribeBundleTasks", "DescribeCarrierGateways",
    "DescribeClientVpnRoutes", "DescribeCluster", "DescribeDhcpOptions", "DescribeFlowLogs", "DescribeImages", "DescribeInstanceAttribute",
    "DescribeInstanceInformation", "DescribeInstanceTypes", "DescribeInstances", "DescribeInstances", "DescribeKeyPairs", "DescribeLogGroups",
    "DescribeLogStreams", "DescribeOrganization", "DescribeRegions", "DescribeSecurityGroups", "DescribeSnapshotAttribute", "DescribeSnapshotTierStatus",
    "DescribeSubscriptionFilters", "DescribeTransitGatewayMulticastDomains", "DescribeVolumes", "DescribeVolumesModifications",
    "DescribeVpcEndpointConnectionNotifications", "DescribeVpcs", "GetAccount", "GetAccountAuthorizationDetails", "GetAccountSendingEnabled",
    "GetBucketAcl", "GetBucketLogging", "GetBucketPolicy", "GetBucketReplication", "GetBucketVersioning", "GetCallerIdentity", "GetCertificate",
    "GetConsoleScreenshot", "GetCostAndUsage", "GetDetector", "GetEbsDefaultKmsKeyId", "GetEbsEncryptionByDefault", "GetFindings",
    "GetFlowLogsIntegrationTemplate", "GetIdentityVerificationAttributes", "GetInstances", "GetIntrospectionSchema", "GetLaunchTemplateData",
    "GetLaunchTemplateData", "GetLogRecord", "GetParameters", "GetPolicyVersion", "GetPublicAccessBlock", "GetQueryResults", "GetRegions",
    "GetSMSAttributes", "GetSMSSandboxAccountStatus", "GetSendQuota", "GetTransitGatewayRouteTableAssociations", "GetUserPolicy", "HeadObject",
    "ListAccessKeys", "ListAccounts", "ListAllMyBuckets", "ListAssociatedAccessPolicies", "ListAttachedUserPolicies", "ListClusters", "ListDetectors",
    "ListDomains", "ListFindings", "ListHostedZones", "ListIPSets", "ListIdentities", "ListInstanceProfiles", "ListObjects",
    "ListOrganizationalUnitsForParent", "ListOriginationNumbers", "ListPolicyVersions", "ListResources", "ListRoles", "ListRoles", "ListRules",
    "ListServiceQuotas", "ListSubscriptions", "ListTargetsByRule", "ListTopics", "ListUsers", "LookupEvents", "Search"]
LLM_JACKING = ["PutUseCaseForModelAccess", "PutFoundationModelEntitlement", "PutModelInvocationLoggingConfiguration", "CreateFoundationModelAgreement",
    "InvokeModel", "InvokeModelWithResponseStream", "GetUseCaseForModelAccess", "GetModelInvocationLoggingConfiguration", "GetFoundationModelAvailability",
    "ListFoundationModelAgreementOffers", "ListFoundationModels", "ListProvisionedModelThroughputs", "SearchAgreements", "AcceptAgreementRequest"]
PRIVILEGE_ESCALATION = ["AddPermission", "AddRoleToInstanceProfile", "AddUserToGroup", "AssociateAccessPolicy", "AssumeRole", "AttachGroupPolicy",
    "AttachRolePolicy", "AttachUserPolicy", "ChangePassword", "CreateAccessEntry", "CreateAccessKey", "CreateDevEndpoint", "CreateEventSourceMapping",
    "CreateFunction", "CreateGroup", "CreateJob", "CreateKeyPair", "CreateLoginProfile", "CreatePipeline", "CreatePolicyVersion", "CreateRole",
    "CreateStack", "DeleteRolePermissionsBoundary", "DeleteRolePolicy", "DeleteUserPermissionsBoundary", "DeleteUserPolicy", "DetachRolePolicy",
    "DetachUserPolicy", "GetCredentialsForIdentity", "GetId", "GetPolicyVersion", "GetUserPolicy", "Invoke", "ModifyInstanceAttribute", "PassRole",
    "PutGroupPolicy", "PutPipelineDefinition", "PutRolePermissionsBoundary", "PutRolePolicy", "PutUserPermissionsBoundary", "PutUserPolicy",
    "ReplaceIamInstanceProfileAssociation", "RunInstances", "SetDefaultPolicyVersion", "UpdateAccessKey", "UpdateAssumeRolePolicy", "UpdateDevEndpoint",
    "UpdateEventSourceMapping", "UpdateFunctionCode", "UpdateJob", "UpdateLoginProfile"]


def _events(names, count, actor="arn:aws:iam::" + ACCOUNT + ":user/mallory"):
    return [{"ActorArn": actor, "ActorType": "IAMUser", "EventName": name, "EventTime": "2026-10-10T10:00:00+00:00", "EventId": "e%d" % i,
             "WindowStart": "2026-10-09T12:00:00+00:00", "WindowEnd": CREATED} for i, name in enumerate(list(dict.fromkeys(names))[:count])]


def _threat(name, actions, threshold, label):
    distinct = len(dict.fromkeys(actions))
    over = int(threshold * len(actions)) + 1
    under = max(1, int(threshold * len(actions)) - 1)
    assert over <= distinct

    @install("cloudtrail.threat_detection_" + name, "aws_cloudtrail_activity", "No identity performed a burst of " + label + " API calls in the activity window", {
        "pass": _REGIONAL, "fail": _REGIONAL, "pass_index": idx(aws_cloudtrail_activity=_events(actions, under)),
        "fail_index": idx(aws_cloudtrail_activity=_events(actions, over)),
        "quiet": _REGIONAL, "quiet_expect": "PASS", "quiet_index": idx(aws_cloudtrail_activity=[]),
        "partial": _REGIONAL, "partial_expect": "UNKNOWN", "partial_index": idx(aws_cloudtrail_activity="partial"),
        }, rows=[P + "cloudtrail_threat_detection_" + name], severity="critical", category="iam_graph", control="SI-4", target="scope",
        dependencies=["aws_cloudtrail_activity"], remediation="Investigate the identity's recent " + label + " activity, rotate its credentials and restrict its permissions.",
        docs=["https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html"],
        note="Per (actor ARN, actor type), distinct pinned event names seen / len(pinned list, duplicates included) > %s, over the collector's activity window "
             "(default 1440 minutes, as upstream). Events without an actor ARN are ignored as upstream. Evaluated per audited region with full pagination "
             "(prowler reads the first page per name in one trail region)." % threshold)
    def evaluate(item, index):
        scope = scope_subject(item)
        events = complete_items(index, "aws_cloudtrail_activity", scope)
        wanted = set(actions)
        seen = {}
        for event in events:
            event_name = get(event, "EventName", str)
            if event_name not in wanted:
                continue
            key = (get(event, "ActorArn", str), get(event, "ActorType", str))
            seen.setdefault(key, set()).add(event_name)
        flagged = sorted(({"actor_arn": arn, "actor_type": kind, "ratio": round(len(names) / len(actions), 2)}
                          for (arn, kind), names in seen.items() if len(names) / len(actions) > threshold), key=lambda r: r["actor_arn"])
        windows = sorted({(e.get("WindowStart"), e.get("WindowEnd")) for e in events if isinstance(e.get("WindowStart"), str)})
        return result(bool(flagged), flagged_identities=flagged, threshold=threshold, actions_considered=len(actions),
                      window=[list(w) for w in windows[:1]])
    evaluate.__name__ = "threat_" + name
    return evaluate


_threat("enumeration", ENUMERATION, 0.3, "enumeration")
_threat("llm_jacking", LLM_JACKING, 0.4, "Bedrock LLM-jacking")
_threat("privilege_escalation", PRIVILEGE_ESCALATION, 0.2, "privilege-escalation")
