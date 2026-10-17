"""CloudTrail -> CloudWatch Logs metric filter -> alarm coverage (CIS 3.x/4.x monitoring family).

Upstream evaluators (Prowler ``cloudwatch_log_metric_filter_*`` / ``cloudwatch_changes_to_*``
and Steampipe ``log_metric_filter_*``) decide coverage with a regular expression over the
filter pattern text and join the alarm by metric name only (Steampipe) or by name, region
and optional namespace (Prowler). Both accept filters that do not match the events
(text order, ``!=`` vs ``=``, a commented clause) and alarms on another metric.

These natives evaluate the requirement instead:

1. a CloudTrail trail that is logging, records the probe events (management read/write
   selectors, no excluded event source, global service events where needed) and delivers to
   a CloudWatch Logs log group of this account;
2. a metric filter on that log group whose JSON filter pattern *semantically matches every
   probe event* built from the upstream event list (``FilterPattern`` below; an unsupported
   or ambiguous pattern is never coverage and leaves the result UNKNOWN);
3. a metric alarm in the log group Region watching exactly the filter's metric
   (MetricName + Namespace, no dimensions; or the single returned MetricStat query);
4. CIS / Steampipe variant only: the trail is multi-Region, the alarm's actions are enabled
   and an AlarmActions SNS topic has at least one confirmed subscription.

Facts: ``cloudtrail_account_inventory`` (DescribeTrails + GetTrailStatus + GetEventSelectors)
and ``metric_alarm_account_inventory`` (per Region: DescribeMetricFilters, DescribeAlarms,
ListSubscriptions). The checks evaluate once per account on ``aws_account_configuration``.
The alarm threshold/comparison is not evaluated (neither upstream does).
"""
from __future__ import annotations

import copy
import re

from . import result
from .facts import Unavailable, get, list_of_objects, optional
from .claude_aws_a_common import items
from .claude_aws_a_ec2 import w
from .aws_gap_core import install, logging_state, management_coverage, TRAIL, _global_index

NATIVE_IDS = []
ACCOUNT = "123456789012"
DOCS = "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html"


# =========================================================================== filter pattern semantics
class PatternError(Exception):
    """The pattern uses syntax this evaluator does not model; it is never treated as coverage."""


_TOKEN = re.compile(r"""\s*(?:(?P<brace>[{}])|(?P<paren>[()])|(?P<logic>&&|\|\|)|(?P<op>!=|<=|>=|=|<|>)
    |(?P<selector>\$(?:\.[A-Za-z0-9_@\-]+|\[[0-9]+\])+)|(?P<quoted>"(?:[^"\\]|\\.)*")|(?P<regex>%[^%]*%)
    |(?P<word>[^\s(){}&|"=!<>]+))""", re.X)
_MISSING = object()


def _tokens(text):
    out, pos = [], 0
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        match = _TOKEN.match(text, pos)
        if not match or match.end() == pos:
            raise PatternError("unsupported filter pattern token")
        kind = match.lastgroup
        value = match.group(kind)
        if kind == "regex":
            raise PatternError("regular expression filter values are not modelled")
        if kind == "quoted":
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        out.append((kind, value))
        pos = match.end()
    return out


class FilterPattern:
    """CloudWatch Logs JSON filter pattern: ``{ ... }`` with ``&&``/``||``, parentheses,
    ``$.a.b[0]`` selectors, ``= != < > <= >=`` (``*`` wildcards in strings), ``IS NULL``,
    ``NOT EXISTS``, ``IS TRUE`` and ``IS FALSE``. An empty pattern matches every event.

    The relative precedence of ``&&`` and ``||`` without parentheses is evaluated both ways
    (conventional and left to right); an event on which they disagree raises PatternError."""

    def __init__(self, text):
        if not isinstance(text, str):
            raise PatternError("filter pattern is not text")
        self.all_events = text.strip() == ""
        if self.all_events:
            return
        tokens = _tokens(text)
        if not tokens or tokens[0] != ("brace", "{") or tokens[-1] != ("brace", "}"):
            raise PatternError("only JSON filter patterns are modelled")
        self._tokens, self._pos = tokens[1:-1], 0
        self.tree = self._sequence()
        if self._pos != len(self._tokens):
            raise PatternError("trailing filter pattern tokens")

    def _peek(self):
        return self._tokens[self._pos] if self._pos < len(self._tokens) else (None, None)

    def _next(self):
        token = self._peek()
        self._pos += 1
        return token

    def _sequence(self):
        terms, ops = [self._atom()], []
        while self._peek()[0] == "logic":
            ops.append(self._next()[1])
            terms.append(self._atom())
        return ("seq", terms, ops)

    def _atom(self):
        kind, value = self._next()
        if (kind, value) == ("paren", "("):
            inner = self._sequence()
            if self._next() != ("paren", ")"):
                raise PatternError("unbalanced parentheses")
            return inner
        if kind != "selector":
            raise PatternError("expected a selector")
        path = re.findall(r"\.([A-Za-z0-9_@\-]+)|\[([0-9]+)\]", value)
        path = [name if name else int(number) for name, number in path]
        op_kind, op = self._next()
        if op_kind == "op":
            value_kind, operand = self._next()
            if value_kind not in ("quoted", "word"):
                raise PatternError("expected a comparison value")
            return ("cmp", path, op, operand, value_kind == "quoted")
        if (op_kind, op) == ("word", "IS"):
            word = self._next()[1]
            if word in ("NULL", "TRUE", "FALSE"):
                return ("is", path, word)
            raise PatternError("unsupported IS test")
        if (op_kind, op) == ("word", "NOT") and self._next() == ("word", "EXISTS"):
            return ("not_exists", path)
        raise PatternError("unsupported comparison")

    @staticmethod
    def _value(event, path):
        value = event
        for part in path:
            if isinstance(part, int):
                if not isinstance(value, list) or part >= len(value):
                    return _MISSING
                value = value[part]
            else:
                if not isinstance(value, dict) or part not in value:
                    return _MISSING
                value = value[part]
        return value

    @staticmethod
    def _number(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _compare(self, node, event):
        _, path, op, operand, quoted = node
        value = self._value(event, path)
        if value is _MISSING or isinstance(value, (dict, list)) or value is None:
            return False
        if op in ("<", ">", "<=", ">="):
            left, right = self._number(value), self._number(operand)
            if left is None or right is None or isinstance(value, bool):
                return False
            return {"<": left < right, ">": left > right, "<=": left <= right, ">=": left >= right}[op]
        if isinstance(value, bool):
            equal = operand == ("true" if value else "false")
        elif isinstance(value, (int, float)):
            number = self._number(operand)
            equal = number is not None and float(value) == number and not quoted
        else:
            regex = "".join(".*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", operand))
            equal = re.fullmatch(regex, value, re.S) is not None
        return equal if op == "=" else not equal

    def _eval(self, node, event, mode):
        tag = node[0]
        if tag == "cmp":
            return self._compare(node, event)
        if tag == "is":
            value = self._value(event, node[1])
            return {"NULL": value is None, "TRUE": value is True, "FALSE": value is False}[node[2]]
        if tag == "not_exists":
            return self._value(event, node[1]) is _MISSING
        _, terms, ops = node
        values = [self._eval(term, event, mode) for term in terms]
        if mode == "ltr":
            out = values[0]
            for op, value in zip(ops, values[1:]):
                out = (out and value) if op == "&&" else (out or value)
            return out
        groups, current = [], values[0]
        for op, value in zip(ops, values[1:]):
            if op == "&&":
                current = current and value
            else:
                groups.append(current)
                current = value
        groups.append(current)
        return any(groups)

    def matches(self, event):
        if self.all_events:
            return True
        conventional, ordered = self._eval(self.tree, event, "prec"), self._eval(self.tree, event, "ltr")
        if conventional != ordered:
            raise PatternError("pattern result depends on unparenthesized && / || precedence")
        return conventional


# =========================================================================== probe events
def api(source, name, **extra):
    event = {"eventVersion": "1.10", "eventSource": source, "eventName": name, "eventType": "AwsApiCall", "awsRegion": "us-east-1",
             "sourceIPAddress": "203.0.113.10", "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT}, "readOnly": False}
    for key, value in extra.items():
        target = event
        parts = key.split("__")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
    return event


def _names(source, names):
    return [api(source, name) for name in names]


EC2, IAM, SIGNIN = "ec2.amazonaws.com", "iam.amazonaws.com", "signin.amazonaws.com"
UNAUTHORIZED = [api(EC2, name, errorCode=code, readOnly=read) for code in ("Client.UnauthorizedOperation", "UnauthorizedOperation", "AccessDenied", "AccessDeniedException")
                for name, read in (("DescribeInstances", True), ("RunInstances", False))]
CONSOLE_NO_MFA = [api(SIGNIN, "ConsoleLogin", eventType="AwsConsoleSignIn", additionalEventData__MFAUsed="No", responseElements__ConsoleLogin="Success")]
ROOT_USAGE = [api("s3.amazonaws.com", "ListBuckets", userIdentity={"type": "Root", "accountId": ACCOUNT}, readOnly=True),
              api(EC2, "RunInstances", userIdentity={"type": "Root", "accountId": ACCOUNT}),
              api(SIGNIN, "ConsoleLogin", eventType="AwsConsoleSignIn", userIdentity={"type": "Root", "accountId": ACCOUNT},
                  responseElements__ConsoleLogin="Success", additionalEventData__MFAUsed="Yes")]
AUTH_FAILURE = [api(SIGNIN, "ConsoleLogin", eventType="AwsConsoleSignIn", errorMessage="Failed authentication", responseElements__ConsoleLogin="Failure")]
IAM_POLICY = ["DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy",
              "CreatePolicyVersion", "DeletePolicyVersion", "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy", "AttachGroupPolicy", "DetachGroupPolicy"]
VPC = ["CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection",
       "RejectVpcPeeringConnection", "AttachClassicLinkVpc", "DetachClassicLinkVpc", "DisableVpcClassicLink", "EnableVpcClassicLink"]
ROUTE = ["CreateRoute", "CreateRouteTable", "ReplaceRoute", "ReplaceRouteTableAssociation", "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable"]
GATEWAY = ["CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway", "CreateInternetGateway", "DeleteInternetGateway", "DetachInternetGateway"]
NACL = ["CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl", "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation"]
SG = ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup"]
CONFIG = ["StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel", "PutConfigurationRecorder"]
S3_POLICY = ["PutBucketAcl", "PutBucketPolicy", "PutBucketCors", "PutBucketLifecycle", "PutBucketReplication", "DeleteBucketPolicy", "DeleteBucketCors",
             "DeleteBucketLifecycle", "DeleteBucketReplication"]
KMS = ["DisableKey", "ScheduleKeyDeletion"]
TRAIL_CHANGES = ["CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging"]
ORG = ["AcceptHandshake", "AttachPolicy", "CreateAccount", "CreateOrganizationalUnit", "CreatePolicy", "DeclineHandshake", "DeleteOrganization",
       "DeleteOrganizationalUnit", "DeletePolicy", "DetachPolicy", "DisablePolicyType", "EnablePolicyType", "InviteAccountToOrganization", "LeaveOrganization",
       "MoveAccount", "RemoveAccountFromOrganization", "UpdatePolicy", "UpdateOrganizationalUnit"]
ORG_PROWLER = ORG + ["CancelHandshake", "CreateOrganization", "EnableAllFeatures"]


def _sources(source, names):
    return "{ ($.eventSource = %s) && (%s) }" % (source, " || ".join("($.eventName = %s)" % n for n in names))


def _names_only(names):
    return "{ %s }" % " || ".join("($.eventName = %s)" % n for n in names)


# key: (title, prowler check, steampipe query, global service events required, prowler probes, steampipe probes, reference pattern)
FAMILIES = {
    "unauthorized_api_calls": ("unauthorized API calls", "cloudwatch_log_metric_filter_unauthorized_api_calls", "log_metric_filter_unauthorized_api", False,
        UNAUTHORIZED, UNAUTHORIZED, '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") && ($.sourceIPAddress != "delivery.logs.amazonaws.com") && ($.eventName != "HeadBucket") }'),
    "console_sign_in_without_mfa": ("Management Console sign-in without MFA", "cloudwatch_log_metric_filter_sign_in_without_mfa", "log_metric_filter_console_login_mfa", True,
        CONSOLE_NO_MFA, CONSOLE_NO_MFA, '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }'),
    "root_account_usage": ("root account usage", "cloudwatch_log_metric_filter_root_usage", "log_metric_filter_root_login", True,
        ROOT_USAGE, ROOT_USAGE, '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'),
    "iam_policy_changes": ("IAM policy changes", "cloudwatch_log_metric_filter_policy_changes", "log_metric_filter_iam_policy", True,
        _names(IAM, IAM_POLICY), _names(IAM, IAM_POLICY), _names_only(IAM_POLICY)),
    "cloudtrail_configuration_changes": ("CloudTrail configuration changes", "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled",
        "log_metric_filter_cloudtrail_configuration", False, _names("cloudtrail.amazonaws.com", TRAIL_CHANGES), _names("cloudtrail.amazonaws.com", TRAIL_CHANGES), _names_only(TRAIL_CHANGES)),
    "console_authentication_failures": ("Management Console authentication failures", "cloudwatch_log_metric_filter_authentication_failures",
        "log_metric_filter_console_authentication_failure", True, AUTH_FAILURE, AUTH_FAILURE, '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'),
    "cmk_disable_or_scheduled_deletion": ("disabling or scheduled deletion of customer managed KMS keys", "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk",
        "log_metric_filter_disable_or_delete_cmk", False, _names("kms.amazonaws.com", KMS), _names("kms.amazonaws.com", KMS), _sources("kms.amazonaws.com", KMS)),
    "s3_bucket_policy_changes": ("S3 bucket policy changes", "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes", "log_metric_filter_bucket_policy", False,
        _names("s3.amazonaws.com", S3_POLICY), _names("s3.amazonaws.com", S3_POLICY), _sources("s3.amazonaws.com", S3_POLICY)),
    "config_configuration_changes": ("AWS Config configuration changes", "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
        "log_metric_filter_config_configuration", False, _names("config.amazonaws.com", CONFIG), _names("config.amazonaws.com", CONFIG), _sources("config.amazonaws.com", CONFIG)),
    "security_group_changes": ("security group changes", "cloudwatch_log_metric_filter_security_group_changes", "log_metric_filter_security_group", False,
        _names(EC2, SG), _names(EC2, SG + ["ModifySecurityGroupRules"]), _names_only(SG + ["ModifySecurityGroupRules"])),
    "network_acl_changes": ("network ACL changes", "cloudwatch_changes_to_network_acls_alarm_configured", "log_metric_filter_network_acl", False,
        _names(EC2, NACL), _names(EC2, NACL), _names_only(NACL)),
    "network_gateway_changes": ("network gateway changes", "cloudwatch_changes_to_network_gateways_alarm_configured", "log_metric_filter_network_gateway", False,
        _names(EC2, GATEWAY), _names(EC2, GATEWAY), _names_only(GATEWAY)),
    "route_table_changes": ("route table changes", "cloudwatch_changes_to_network_route_tables_alarm_configured", "log_metric_filter_route_table", False,
        _names(EC2, ROUTE), _names(EC2, ROUTE), _sources(EC2, ROUTE)),
    "vpc_changes": ("VPC changes", "cloudwatch_changes_to_vpcs_alarm_configured", "log_metric_filter_vpc", False, _names(EC2, VPC), _names(EC2, VPC), _names_only(VPC)),
    "organizations_changes": ("AWS Organizations changes", "cloudwatch_log_metric_filter_aws_organizations_changes", "log_metric_filter_organization", True,
        _names("organizations.amazonaws.com", ORG_PROWLER), _names("organizations.amazonaws.com", ORG), _sources("organizations.amazonaws.com", ORG_PROWLER)),
}


# =========================================================================== coverage evaluation
def _status(listing, what):
    if not isinstance(listing, dict) or listing.get("collection_status") not in ("collected", "empty"):
        raise Unavailable(what + " not collected")
    return list_of_objects(get(listing, "items", list))


def _records(trail, probes):
    """True when the trail's selectors record every probe event (None: not decidable)."""
    read, write, excluded = management_coverage(trail)
    for event in probes:
        if not (read if event.get("readOnly") else write):
            return False
        source = event["eventSource"]
        if any(source == value or source.startswith(value) for value in excluded):
            return False
    return True


def _dimension_keys(value):
    if isinstance(value, dict):
        if any(not isinstance(key, str) or not key or not isinstance(expression, str)
               for key, expression in value.items()):
            raise Unavailable("malformed metric dimensions")
        return frozenset(value)
    return frozenset(get(dimension, "Name", str) for dimension in list_of_objects(value))


def _same_dimensions(alarm_dims, filter_keys):
    """True: both dimensionless; None: same dimension names (values come from events, not modelled); False otherwise.

    Dimensions are part of a CloudWatch metric's identity, so an alarm on a dimension set
    the filter never emits watches a different metric.
    """
    keys = _dimension_keys(alarm_dims)
    if keys != filter_keys:
        return False
    return True if not keys else None


def _metric_identity(alarm, name, namespace, filter_keys=frozenset()):
    """True: alarm watches exactly this metric; None: references it in a form not modelled; False otherwise."""
    if "MetricName" in alarm or "MetricName" in alarm.get("_coverage", {}):
        if get(alarm, "MetricName", str) != name or get(alarm, "Namespace", str) != namespace:
            return False
        return _same_dimensions(optional(alarm, "Dimensions", [], list), filter_keys)
    queries = list_of_objects(get(alarm, "Metrics", list))
    hits = []
    returned = []
    for query in queries:
        direct = "Metric" in query or "Metric" in query.get("_coverage", {})
        expression = optional(query, "ExpressionPresent", False, bool)
        watched = None
        if direct:
            metric = get(query, "Metric", dict)
            metric_name = get(metric, "MetricName", str)
            metric_namespace = get(metric, "Namespace", str)
            dimensions = optional(metric, "Dimensions", [], list)
            if metric_name == name and metric_namespace == namespace:
                watched = _same_dimensions(dimensions, filter_keys)
                if watched is not False:
                    hits.append(query)
        elif not expression:
            raise Unavailable("alarm metric query has no MetricStat or expression")
        if optional(query, "ReturnData", True, bool):
            returned.append((query, watched, expression))
    if not hits:
        return False
    if len(returned) == 1 and returned[0][0] in hits and not returned[0][2]:
        return returned[0][1]
    return None


def _notifies(alarm, row, region, account):
    """CIS: enabled actions and an AlarmActions SNS topic with a confirmed subscription."""
    if not get(alarm, "ActionsEnabled", bool):
        return False
    actions = get(alarm, "AlarmActions", list)
    if any(not isinstance(action, str) for action in actions):
        raise Unavailable("malformed alarm actions")
    topics = [action for action in actions if action.split(":")[2:3] == ["sns"]]
    if not topics:
        return False
    subscriptions = _status(get(row, "Subscriptions", dict), "SNS subscriptions")
    unknown = False
    for topic in topics:
        parts = topic.split(":")
        if len(parts) < 6 or parts[3] != region or parts[4] != account:
            unknown = True  # subscriptions of another account's or Region's topic are not listed here
            continue
        for subscription in subscriptions:
            try:
                if get(subscription, "TopicArn", str) != topic:
                    continue
                subscription_arn = get(subscription, "SubscriptionArn", str)
            except Unavailable:
                unknown = True
                continue
            if subscription_arn.startswith("arn:"):
                return True
    return None if unknown else False


def _log_group_covered(row, region, account, group, probes, strict):
    """True/False for one trail log group; Unavailable when the facts cannot decide."""
    filters = _status(get(row, "MetricFilters", dict), "metric filters")
    alarms = None
    unknown = []
    for metric_filter in filters:
        try:
            if get(metric_filter, "logGroupName", str) != group:
                continue
            if optional(metric_filter, "applyOnTransformedLogs", False, bool):
                raise PatternError("filter applies to transformed log events")
            pattern = FilterPattern(get(metric_filter, "filterPattern", str))
            if not all(pattern.matches(event) for event in probes):
                continue
            transformations = list_of_objects(get(metric_filter, "metricTransformations", list))
        except (PatternError, Unavailable) as exc:
            unknown.append(str(exc))
            continue
        if alarms is None:
            alarms = _status(get(row, "MetricAlarms", dict), "metric alarms")
        for transformation in transformations:
            try:
                name = get(transformation, "metricName", str)
                namespace = get(transformation, "metricNamespace", str)
                filter_keys = _dimension_keys(optional(transformation, "dimensions", {}, dict))
            except Unavailable as exc:
                unknown.append(str(exc))
                continue
            for alarm in alarms:
                try:
                    watches = _metric_identity(alarm, name, namespace, filter_keys)
                except Unavailable as exc:
                    unknown.append(str(exc))
                    continue
                if watches is False:
                    continue
                if watches is None:
                    unknown.append("alarm metric form not modelled (dimensions or metric math)")
                    continue
                if not strict:
                    return True
                try:
                    notified = _notifies(alarm, row, region, account)
                except Unavailable as exc:
                    unknown.append(str(exc))
                    continue
                if notified:
                    return True
                if notified is None:
                    unknown.append("alarm notification target not verifiable")
    if unknown:
        raise Unavailable("; ".join(sorted(set(unknown))))
    return False


def coverage(index, probes, global_events, strict):
    trails = items(index, "cloudtrail_account_inventory")
    rows = {}
    for row in items(index, "metric_alarm_account_inventory"):
        rows[get(row, "SourceRegion", str)] = row
    unknown, considered = [], 0
    for trail in trails:
        arn = trail.get("CloudWatchLogsLogGroupArn")
        if not arn:
            continue
        try:
            if not isinstance(arn, str):
                raise Unavailable("malformed trail log group ARN")
            multi = get(trail, "IsMultiRegionTrail", bool)
            if strict and not multi:
                continue
            if global_events and not get(trail, "IncludeGlobalServiceEvents", bool):
                continue
            logging = logging_state(trail)
            if logging is False:
                continue
            if not _records(trail, probes):
                continue
            parts = arn.split(":")
            if len(parts) < 7 or parts[2] != "logs" or parts[5] != "log-group":
                raise Unavailable("malformed trail log group ARN")
            region, account, group = parts[3], parts[4], parts[6]
            considered += 1
            row = rows.get(region)
            if row is None:
                raise Unavailable("metric filters of log group Region %s not collected" % region)
            row_account = get(row, "id", str).split("/")[1:2]
            if row_account != [account]:
                raise Unavailable("trail log group belongs to another account")
            if _log_group_covered(row, region, account, group, probes, strict):
                if logging is True:
                    return result(False, trail=trail.get("TrailARN"), log_group=group, region=region)
                unknown.append("trail logging status unavailable")
        except Unavailable as exc:
            unknown.append(str(exc))
    if unknown:
        raise Unavailable("; ".join(sorted(set(unknown))))
    return result(True, trails_with_log_groups=considered)


# =========================================================================== fixtures
GROUP = "CloudTrail/audit"
GROUP_ARN = "arn:aws:logs:us-east-1:%s:log-group:%s:*" % (ACCOUNT, GROUP)
TOPIC = "arn:aws:sns:us-east-1:%s:security-alerts" % ACCOUNT
LOGGED = w(TRAIL, CloudWatchLogsLogGroupArn=GROUP_ARN)


def _row(pattern, region="us-east-1", alarm=None, subscriptions=None, filters_status="collected", namespace="CISBenchmark", group=GROUP):
    alarm = alarm if alarm is not None else {"AlarmName": "a", "AlarmArn": "arn:aws:cloudwatch:%s:%s:alarm:a" % (region, ACCOUNT),
                                             "MetricName": "m", "Namespace": "CISBenchmark", "Dimensions": [], "ActionsEnabled": True, "AlarmActions": [TOPIC]}
    subscriptions = subscriptions if subscriptions is not None else [{"SubscriptionArn": TOPIC + ":1111", "TopicArn": TOPIC, "Protocol": "email", "id": TOPIC + ":1111"}]
    filters = {"collection_status": filters_status, "items": [] if filters_status != "collected" else [
        {"id": group + "/f", "filterName": "f", "logGroupName": group, "filterPattern": pattern,
         "metricTransformations": [{"metricName": "m", "metricNamespace": namespace}]}]}
    return {"id": "metric-alarm-coverage/%s/%s" % (ACCOUNT, region), "SourceRegion": region, "MetricFilters": filters,
            "MetricAlarms": {"collection_status": "collected", "items": [alarm] if alarm else []},
            "Subscriptions": {"collection_status": "collected", "items": subscriptions}}


def _index(trail=LOGGED, *rows):
    return _global_index(cloudtrail_account_inventory=[trail], metric_alarm_account_inventory=list(rows))


def _weaken(pattern, probes):
    """Reference pattern that misses one required probe event (or negates its first condition)."""
    required = {event["eventName"] for event in probes}
    names = [n for n in re.findall(r"\$\.eventName = ([A-Za-z]+)\)", pattern) if n in required]
    if len(names) > 1:
        return pattern.replace(" || ($.eventName = %s)" % names[-1], "")
    return pattern.replace(" = ", " != ", 1)


ACCT = {"id": "account-configuration", "Partition": "aws"}
DEPS = ["aws_account_configuration", "cloudtrail_account_inventory", "metric_alarm_account_inventory"]


def _install_family(key, spec, strict):
    title, prowler, query, global_events, prowler_probes, turbot_probes, reference = spec
    probes = turbot_probes if strict else prowler_probes
    cid = ("aws.gap.cloudwatch.cis_alarm." if strict else "aws.gap.cloudwatch.metric_alarm.") + key
    weak = _weaken(reference, probes)
    base = _row(reference)
    no_subscriber = _row(reference, subscriptions=[{"SubscriptionArn": "PendingConfirmation", "TopicArn": TOPIC, "Protocol": "email", "id": TOPIC + "/pending/x"}])
    single = w(LOGGED, IsMultiRegionTrail=False)
    variants = [
        ("FAIL", ACCT, _index(w(LOGGED, Status__IsLogging=False), base)),
        ("FAIL", ACCT, _index(w(LOGGED, CloudWatchLogsLogGroupArn=""), base)),
        ("FAIL", ACCT, _index(LOGGED, _row(reference, group="other-group"))),
        ("FAIL", ACCT, _index(LOGGED, _row(reference, namespace="Other"))),
        ("FAIL", ACCT, _index(LOGGED, _row(reference, alarm={}))),
        # Same name and namespace but a dimension the filter never emits: a different metric.
        ("FAIL", ACCT, _index(LOGGED, _row(reference, alarm=w(base["MetricAlarms"]["items"][0], Dimensions=[{"Name": "Environment", "Value": "Unrelated"}])))),
        ("FAIL", ACCT, _index(w(LOGGED, EventSelectors__EventSelectors=[{"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True}]), base)),
        ("FAIL", ACCT, _index(w(LOGGED, EventSelectors__EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True,
                                                                        "ExcludeManagementEventSources": [probes[0]["eventSource"]]}]), base)),
        ("UNKNOWN", ACCT, _index(LOGGED, _row(reference, filters_status="denied"))),
        ("UNKNOWN", ACCT, _index(LOGGED, _row("%Root%"))),
        ("UNKNOWN", ACCT, _index(LOGGED)),
        ("UNKNOWN", ACCT, _index(w(LOGGED, Status={"collection_status": "denied"}), base)),
        ("PASS", ACCT, _index(LOGGED, _row(""))),
    ]
    if strict:
        variants += [("FAIL", ACCT, _index(LOGGED, no_subscriber)), ("FAIL", ACCT, _index(single, base)),
                     ("FAIL", ACCT, _index(LOGGED, _row(reference, alarm=w(base["MetricAlarms"]["items"][0], ActionsEnabled=False))))]
    else:
        variants += [("PASS", ACCT, _index(LOGGED, no_subscriber)), ("PASS", ACCT, _index(w(single, IncludeGlobalServiceEvents=True), base))]
        if global_events:
            variants.append(("FAIL", ACCT, _index(w(single, IncludeGlobalServiceEvents=False), base)))
    upstream = "Steampipe %s" % query if strict else "Prowler %s" % prowler
    suffix = " (multi-Region trail, alarm notifies a subscribed SNS topic)" if strict else ""

    @install(cid, "aws_account_configuration", "A CloudWatch metric filter and alarm detect %s%s" % (title, suffix), "medium", "SI-4",
        "Deliver a logging CloudTrail trail to CloudWatch Logs, add a metric filter matching %s and an alarm on its metric%s." % (
            title, " that notifies a subscribed SNS topic" if strict else ""),
        dependencies=DEPS, ids=NATIVE_IDS,
        cases={"pass": ACCT, "index": _index(LOGGED, base), "fail": ACCT, "fail_index": _index(LOGGED, _row(weak)), "variants": variants})
    def evaluate(item, index):
        get(item, "id", str)
        return coverage(index, probes, global_events, strict)
    evaluate.__doc__ = "Requirement of %s, evaluated semantically." % upstream
    return cid


PROWLER_NATIVES = {spec[1]: _install_family(key, spec, False) for key, spec in FAMILIES.items()}
STEAMPIPE_NATIVES = {spec[2]: _install_family(key, spec, True) for key, spec in FAMILIES.items()}
