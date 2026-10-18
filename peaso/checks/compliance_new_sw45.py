"""Signed AWS WAF, finding-alert, and EC2 compliance checks (sw45)."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import replace

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard

SPECS = {'aws_cis_ec2_instance_approved_ami': {'category': 'hardening',
                                       'kind': 'instance',
                                       'provider': 'aws',
                                       'remediation': 'Maintain approved AMI IDs or owners and replace '
                                                      'instances using unapproved images.',
                                       'severity': 'high',
                                       'sha': 'cc841e1b4fc82534af019c34f30eca414da629eaf96c5a00c74c0105de149115',
                                       'title': 'EC2 instances use approved AMIs'},
 'aws_cis_ec2_userdata_embedded_secrets': {'category': 'hardening',
                                           'kind': 'instance',
                                           'provider': 'aws',
                                           'remediation': 'Remove literals from user data and retrieve '
                                                          'secrets at runtime from Secrets Manager.',
                                           'severity': 'high',
                                           'sha': '5da28c4405c738c8e677f687f52a23939323977fd4a7cce49510fe668f424422',
                                           'title': 'EC2 user data contains no embedded secrets'},
 'aws_ecr_scan_findings_metric_export': {'category': 'hardening',
                                         'kind': 'event_rule',
                                         'provider': 'aws',
                                         'remediation': 'Create an EventBridge rule matching ECR scan '
                                                        'findings and target the approved central metric '
                                                        'ingestion pipeline.',
                                         'severity': 'medium',
                                         'sha': '95cbb52de0d5ac56f1362879787de9fef0635b18c9537b91ca58620dece29883',
                                         'title': 'Export scan results as metrics in centralized collector '
                                                  '(ECR)'},
 'aws_eventbridge_iam_user_change_alert': {'category': 'hardening',
                                           'kind': 'event_rule',
                                           'provider': 'aws',
                                           'remediation': 'Create an enabled EventBridge rule matching IAM '
                                                          'user create, delete and credential-change '
                                                          'CloudTrail events with an SNS or SIEM target.',
                                           'severity': 'medium',
                                           'sha': 'a2eb6475438122ed98ece7e9f03fd17cc4e8c81c825b7b3f527f4645efb78a46',
                                           'title': 'Alert on IAM user changes'},
 'aws_eventbridge_snapshot_change_alert': {'category': 'hardening',
                                           'kind': 'event_rule',
                                           'provider': 'aws',
                                           'remediation': 'Create an enabled EventBridge rule matching EBS '
                                                          'snapshot create, modify and delete events with an '
                                                          'alert target.',
                                           'severity': 'medium',
                                           'sha': '3074246c2dd184fbff022ed804ce6993402f53235e0379a0a331aa2a6051f919',
                                           'title': 'Alert on snapshot manipulations'},
 'aws_inspector_critical_image_findings_alert': {'category': 'hardening',
                                                 'kind': 'event_rule',
                                                 'provider': 'aws',
                                                 'remediation': 'Create an enabled EventBridge rule for '
                                                                'Inspector2 CRITICAL EC2 and ECR findings '
                                                                'with an alert target.',
                                                 'severity': 'medium',
                                                 'sha': '39e9face6d61fc7878a86b49dd16256554ce8b0d57f1b310e9bc3b094b7ed46b',
                                                 'title': 'Alert on critical vulnerabilities in AMIs/Images'},
 'aws_route53resolver_blocked_query_alert': {'category': 'hardening',
                                             'kind': 'event_rule',
                                             'provider': 'aws',
                                             'remediation': 'Create a CloudWatch alarm on DNS Firewall '
                                                            'blocked-query metrics for each protected VPC '
                                                            'and attach a notification action.',
                                             'severity': 'medium',
                                             'sha': '1b81522e714646725702b30ac942b1f5580ffa08f2b43b6406c1cc93189012ee',
                                             'title': 'Alert on blocked DNS query'},
 'aws_securityhub_findings_alerted': {'category': 'hardening',
                                      'kind': 'event_rule',
                                      'provider': 'aws',
                                      'remediation': 'Connect Security Hub high severity findings to '
                                                     'EventBridge alert targets.',
                                      'severity': 'high',
                                      'sha': 'd33a4a2e8c0b16806326e3e1a3c5ffa230637d8c59542d366d72c3300f58f4fb',
                                      'title': 'High severity security findings trigger alerts'},
 'aws_securityhub_medium_findings_alert': {'category': 'hardening',
                                           'kind': 'event_rule',
                                           'provider': 'aws',
                                           'remediation': 'Create an enabled EventBridge rule matching '
                                                          'Security Hub imported MEDIUM and lower findings '
                                                          'with a notification target.',
                                           'severity': 'medium',
                                           'sha': 'ee6d1c30885e8392d7b3c8bb6cac59a7ae00dbe20da49686dd17daefdc0e6242',
                                           'title': 'Alerts based on aggregated findings with severity '
                                                    'Medium and below'},
 'aws_wafv2_global_allow_block_lists': {'category': 'hardening',
                                        'kind': 'wafv2_web_acl',
                                        'provider': 'aws',
                                        'remediation': 'Create WAFv2 Allow and Block IP-set rules using the '
                                                       'approved CIDRs and unique approved Priority values.',
                                        'severity': 'medium',
                                        'sha': 'ea2ad85e7c1cbccdc26ebcc73bb670f908b6422f9031e6951849ff6426bae485',
                                        'title': 'WAF global allow and block lists'},
 'aws_wafv2_managed_block_alarm': {'category': 'hardening',
                                   'kind': 'wafv2_web_acl',
                                   'provider': 'aws',
                                   'remediation': 'Enable rule CloudWatch metrics and create a '
                                                  'blocked-request CloudWatch alarm with the approved '
                                                  'threshold and an action.',
                                   'severity': 'medium',
                                   'sha': 'e70cd0cbde16af686e099c02d0c2514d366a6431569f31ed5529e679fffa6e3a',
                                   'title': 'Alerts based on high amount of blocked requests by managed '
                                            'rules'},
 'aws_wafv2_monitoring_rate_rule': {'category': 'compliance',
                                    'kind': 'wafv2_web_acl',
                                    'provider': 'aws',
                                    'remediation': 'Add a scoped WAFv2 rate-based Block rule with enabled '
                                                   'metrics and an alarm targeting the rule MetricName.',
                                    'severity': 'medium',
                                    'sha': '17b4fd93966695bfd7262d510ba464bde0ad31913cac887b4245d78877732d2c',
                                    'title': 'Monitoring endpoint rate limiting and alerting'},
 'aws_wafv2_rate_rule_alarm': {'category': 'hardening',
                               'kind': 'wafv2_web_acl',
                               'provider': 'aws',
                               'remediation': 'Create a CloudWatch alarm on each WAFv2 rate rule MetricName '
                                              'with ActionsEnabled=true and a notification action.',
                               'severity': 'medium',
                               'sha': 'bc537977f567e3e31a9e9096525e9e1da810384c464d6d90cb0cba448677ba83',
                               'title': 'Alerts based on rate-based rules'},
 'aws_wafv2_redacted_siem_logging': {'category': 'hardening',
                                     'kind': 'wafv2_web_acl',
                                     'provider': 'aws',
                                     'remediation': 'Set WAFv2 logging RedactedFields for approved headers '
                                                    'and query fields and route LogDestinationConfigs to the '
                                                    'SIEM.',
                                     'severity': 'medium',
                                     'sha': '31b79f71ac796f64d442fedadc4b3d9e7e9f5fbcf7e53c606c80af733d269f20',
                                     'title': 'Configure sensitive fields redaction and send WAF logs to '
                                              'SIEM'},
 'aws_wafv2_request_validation_rules': {'category': 'hardening',
                                        'kind': 'wafv2_web_acl',
                                        'provider': 'aws',
                                        'remediation': 'Associate the public ALB with a WAFv2 web ACL '
                                                       'containing AWSManagedRulesCommonRuleSet without a '
                                                       'Count override.',
                                        'severity': 'medium',
                                        'sha': 'b4aaaa0a117fa83201409cb6401e838bd4d7b56ecbe4db6672aa0053b217ad20',
                                        'title': 'Public application has request validation WAF rules'}}

_SCOPE = re.compile(r"^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$")
_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12}):(.+)$")


def _context(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS provider authority unavailable")
    scope = get(context, "scope", str)
    match = _SCOPE.fullmatch(scope)
    if not match:
        raise Unavailable("regional AWS scope unavailable")
    return context, scope, match.group(1), match.group(2)


def _inventory(index, kind, item=None):
    from .facts import memoized
    _, scope, _, _ = _context(index)
    rows = list(memoized(index, (__name__, 'validated_inventory', scope, kind),
                         lambda: _validated_inventory(index, kind)))
    # Subject membership remains per-resource; caching inventory authority
    # cannot certify a different or modified item.
    if item is not None and sum(row == item for row in rows) != 1:
        raise Unavailable("resource absent or duplicated in collection: " + kind)
    return rows


def _validated_inventory(index, kind):
    _, scope, account, region = _context(index)
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("complete collection envelope unavailable: " + kind)
    envelope = envelopes[0]
    if not isinstance(envelope, dict) or envelope.get("type") != kind or envelope.get("scope") != scope:
        raise Unavailable("foreign collection envelope: " + kind)
    if envelope.get("status") not in ("collected", "empty"):
        raise Unavailable("incomplete collection: " + kind)
    expected = get(envelope, "items", list)
    if any(not isinstance(row, dict) for row in expected):
        raise Unavailable("malformed collection items: " + kind)
    wrappers = get(index, kind, list)
    if any(not isinstance(w, dict) or w.get("type") != kind or w.get("scope") != scope
           or w.get("data") not in expected for w in wrappers):
        raise Unavailable("foreign or mismatched resource wrapper: " + kind)
    rows = complete_items(index, kind)
    if (len(rows) != len(expected) or len(rows) != len(wrappers) or
            envelope["status"] == "empty" and rows or
            any(sum(row == candidate for candidate in expected) != 1 for row in rows) or
            any(sum(row == candidate for candidate in rows) != 1 for row in expected)):
        raise Unavailable("ambiguous collection membership: " + kind)
    return rows


def _arn(value, service, account, region):
    if not isinstance(value, str):
        raise Unavailable("missing native ARN")
    parsed = _ARN.fullmatch(value)
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    if (not parsed or parsed.group(1) != partition or parsed.group(2) != service or
            parsed.group(3) != region or parsed.group(4) != account):
        raise Unavailable("foreign native ARN")
    return value


def _objects(value):
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise Unavailable("malformed object list")
    for row in value:
        guard(row)
    return value


def _strings(value, *, nonempty=False):
    if not isinstance(value, list) or any(not isinstance(s, str) or not s for s in value):
        raise Unavailable("malformed string list")
    if nonempty and not value:
        raise Unavailable("required list is empty")
    return value


def _policy(index, key, expected):
    context, _, _, _ = _context(index)
    metadata = get(context, "metadata", dict)
    source = metadata if key in metadata else get(metadata, "parameters", dict)
    return get(source, key, expected)


def _waf(item, index):
    _inventory(index, "wafv2_web_acl", item)
    _, _, account, region = _context(index)
    arn = _arn(get(item, "ARN", str), "wafv2", account, region)
    web = get(item, "WebACL", dict)
    if get(web, "ARN", str) != arn or get(web, "Id", str) != get(item, "Id", str):
        raise Unavailable("WAF detail identity mismatch")
    scope = get(item, "Scope", str)
    prefix = "regional" if scope == "REGIONAL" else "global" if scope == "CLOUDFRONT" else None
    if not prefix or f":{prefix}/webacl/" not in arn or not arn.endswith("/" + web["Id"]):
        raise Unavailable("WAF scope or identifier mismatch")
    return arn, web, _objects(get(web, "Rules", list))


def _alarms(index):
    rows = _inventory(index, "cloudwatch_alarm")
    _, _, account, region = _context(index)
    for row in rows:
        _arn(get(row, "AlarmArn", str), "cloudwatch", account, region)
    return rows


def _alarm_matches(row, *, metric, namespace, dimensions, threshold=None):
    if get(row, "MetricName", str) != metric or get(row, "Namespace", str) != namespace:
        return False
    dims = _objects(get(row, "Dimensions", list))
    actual = {get(d, "Name", str): get(d, "Value", str) for d in dims}
    if len(actual) != len(dims) or actual != dimensions:
        return False
    if get(row, "ActionsEnabled", bool) is not True:
        return False
    actions = _strings(get(row, "AlarmActions", list))
    if not actions:
        return False
    if threshold is not None:
        value = get(row, "Threshold")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise Unavailable("malformed alarm threshold")
        return value <= threshold
    return True


def _waf_alarm(item, index, statement_key, *, threshold=False):
    arn, web, rules = _waf(item, index)
    alarms = _alarms(index)
    limit = _policy(index, "approved_blocked_request_threshold", int) if threshold else None
    if threshold and limit < 0:
        raise Unavailable("invalid approved blocked request threshold")
    failing, applicable = [], []
    for rule in rules:
        name = get(rule, "Name", str)
        statement = get(rule, "Statement", dict)
        if statement_key not in statement:
            continue
        get(statement, statement_key, dict)
        applicable.append(name)
        visibility = get(rule, "VisibilityConfig", dict)
        enabled = get(visibility, "CloudWatchMetricsEnabled", bool)
        metric_name = get(visibility, "MetricName", str)
        if not metric_name:
            raise Unavailable("empty rule metric name")
        dimensions = {"WebACL": get(get(web, "VisibilityConfig", dict), "MetricName", str), "Rule": metric_name}
        # The signed rate rule spec names its rule metric; the managed rule
        # spec names BlockedRequests. Both also require the exact ACL/rule dimensions.
        alarm_metric = "BlockedRequests" if threshold else metric_name
        if not enabled or not any(_alarm_matches(a, metric=alarm_metric, namespace="AWS/WAFV2",
                  dimensions=dimensions, threshold=limit) for a in alarms):
            failing.append(name)
    if not applicable:
        return "NOT_APPLICABLE", {"web_acl_arn": arn, "reason": "no matching WAF rules"}
    return result(bool(failing), web_acl_arn=arn, checked_rules=applicable, rules_without_alarm=failing)


def _register(check_id, dependencies):
    spec = SPECS[check_id]
    # The native decorator currently excludes the signed 'compliance' category.
    # Preserve its checked wrapper and replace only immutable public metadata.
    category = spec["category"] if spec["category"] != "compliance" else "hardening"
    def decorate(function):
        target = "scope" if spec["kind"] == "event_rule" else "resource"
        registered = register(check_id, "aws", category, spec["kind"], spec["title"],
            spec["severity"], "CM-6", spec["remediation"], target=target,
            dependencies=dependencies)(function)
        if spec["category"] == "compliance":
            CHECKS[-1] = replace(CHECKS[-1], category="compliance")
        return registered
    return decorate


@_register("aws_wafv2_global_allow_block_lists", ["wafv2_web_acl", "wafv2_ip_set"])
def global_allow_block_lists(item, index):
    arn, _, rules = _waf(item, index)
    ipsets = _inventory(index, "wafv2_ip_set")
    _, _, account, region = _context(index)
    by_arn = {}
    for row in ipsets:
        key = _arn(get(row, "ARN", str), "wafv2", account, region)
        if key in by_arn:
            raise Unavailable("duplicate WAF IP set")
        by_arn[key] = row
    approved = {}
    for action in ("Allow", "Block"):
        raw = _strings(_policy(index, "approved_" + action.lower() + "_cidrs", list))
        try:
            cidrs = {str(ipaddress.ip_network(v, strict=True)) for v in raw}
        except ValueError as exc:
            raise Unavailable("malformed approved CIDR") from exc
        if len(cidrs) != len(raw):
            raise Unavailable("duplicate approved CIDR")
        priority = _policy(index, "approved_" + action.lower() + "_priority", int)
        if priority < 0:
            raise Unavailable("invalid approved priority")
        approved[action] = (cidrs, priority)
    if approved["Allow"][1] == approved["Block"][1]:
        raise Unavailable("ambiguous approved rule order")
    matched = {"Allow": False, "Block": False}
    for rule in rules:
        action = get(rule, "Action", dict) if "Action" in rule else {}
        if not isinstance(action, dict):
            raise Unavailable("malformed WAF action")
        statement = get(rule, "Statement", dict)
        if "IPSetReferenceStatement" not in statement:
            continue
        reference = get(statement, "IPSetReferenceStatement", dict)
        ref = get(reference, "ARN", str)
        if ref not in by_arn:
            raise Unavailable("referenced IP set missing from complete inventory")
        ipset = by_arn[ref]
        addresses = _strings(get(ipset, "Addresses", list))
        try:
            cidrs = {str(ipaddress.ip_network(v, strict=True)) for v in addresses}
        except ValueError as exc:
            raise Unavailable("malformed WAF IP set CIDR") from exc
        if len(cidrs) != len(addresses):
            raise Unavailable("duplicate WAF IP set CIDR")
        priority = get(rule, "Priority", int)
        for name, (wanted, wanted_priority) in approved.items():
            if name in action and cidrs == wanted and priority == wanted_priority:
                matched[name] = True
    return result(not all(matched.values()), web_acl_arn=arn, approved_lists_matched=matched)


@_register("aws_wafv2_managed_block_alarm", ["wafv2_web_acl", "cloudwatch_alarm"])
def managed_block_alarm(item, index):
    return _waf_alarm(item, index, "ManagedRuleGroupStatement", threshold=True)


@_register("aws_wafv2_rate_rule_alarm", ["wafv2_web_acl", "cloudwatch_alarm"])
def rate_rule_alarm(item, index):
    return _waf_alarm(item, index, "RateBasedStatement")

@_register("aws_wafv2_monitoring_rate_rule", ["wafv2_web_acl", "cloudwatch_alarm"])
def monitoring_rate_rule(item, index):
    arn, web, rules = _waf(item, index)
    association_read = get(item, "ResourceArns", dict)
    if get(association_read, "collection_status", str) != "collected":
        raise Unavailable("WAF resource association inventory unavailable")
    associated = set(_strings(get(association_read, "ResourceArns", list)))
    endpoints = _objects(_policy(index, "monitoring_endpoints", list))
    designated = []
    for endpoint in endpoints:
        resource = get(endpoint, "ResourceArn", str)
        threshold = get(endpoint, "ApprovedRequestThreshold", int)
        scope_down = get(endpoint, "ScopeDownStatement", dict)
        if threshold <= 0 or not resource or not scope_down:
            raise Unavailable("invalid monitoring endpoint policy")
        if resource in associated:
            designated.append((resource, threshold, scope_down))
    if not designated:
        return "NOT_APPLICABLE", {"web_acl_arn": arn, "reason": "no designated monitoring endpoint associated"}
    alarms = _alarms(index)
    missing = []
    for resource, threshold, scope_down in designated:
        covered = False
        for rule in rules:
            statement = get(rule, "Statement", dict)
            if "RateBasedStatement" not in statement:
                continue
            rate = get(statement, "RateBasedStatement", dict)
            if get(rate, "ScopeDownStatement", dict) != scope_down:
                continue
            limit = get(rate, "Limit", int)
            if limit <= 0:
                raise Unavailable("invalid rate rule limit")
            action = get(rule, "Action", dict)
            visibility = get(rule, "VisibilityConfig", dict)
            metric = get(visibility, "MetricName", str)
            if (limit <= threshold and "Block" in action and
                    get(visibility, "CloudWatchMetricsEnabled", bool) and metric and
                    any(_alarm_matches(alarm, metric=metric, namespace="AWS/WAFV2",
                        dimensions={"WebACL": get(get(web, "VisibilityConfig", dict), "MetricName", str),
                                    "Rule": metric}) for alarm in alarms)):
                covered = True
        if not covered:
            missing.append(resource)
    return result(bool(missing), web_acl_arn=arn, endpoints_without_rate_alert=missing)


@_register("aws_wafv2_redacted_siem_logging", ["wafv2_web_acl", "log_subscription_filter"])
def redacted_siem_logging(item, index):
    arn, _, _ = _waf(item, index)
    configured_headers = set(_strings(_policy(index, "approved_sensitive_headers", list)))
    redact_query = _policy(index, "require_query_string_redaction", bool)
    siem_arns = set(_strings(_policy(index, "approved_siem_destination_arns", list), nonempty=True))
    if not configured_headers and not redact_query:
        raise Unavailable("no configured sensitive fields")
    logging_read = get(item, "LoggingConfiguration", dict)
    if get(logging_read, "collection_status", str) not in ("collected", "empty"):
        raise Unavailable("WAF logging configuration unavailable")
    if logging_read["collection_status"] == "empty":
        return result(True, web_acl_arn=arn, reason="no logging configuration")
    config = get(logging_read, "LoggingConfiguration", dict)
    if get(config, "ResourceArn", str) != arn:
        raise Unavailable("WAF logging identity mismatch")
    fields = _objects(get(config, "RedactedFields", list) if
        "RedactedFields" in config or "RedactedFields" in config.get("_coverage", {}) else [])
    actual_headers, query = set(), False
    for field in fields:
        if "SingleHeader" in field:
            actual_headers.add(get(get(field, "SingleHeader", dict), "Name", str).lower())
        elif "QueryString" in field:
            get(field, "QueryString", dict)
            query = True
        else:
            raise Unavailable("unrecognized redaction field")
    destinations = _strings(get(config, "LogDestinationConfigs", list))
    subscriptions = _inventory(index, "log_subscription_filter")
    forwarding = set()
    for row in subscriptions:
        forwarding.add((get(row, "LogGroupArn", str), get(row, "DestinationArn", str)))
    siem = any(destination in siem_arns or
               any((destination, target) in forwarding for target in siem_arns)
               for destination in destinations)
    redacted = configured_headers <= actual_headers and (not redact_query or query)
    return result(not (redacted and siem), web_acl_arn=arn,
                  missing_headers=sorted(configured_headers - actual_headers),
                  query_redacted=query, siem_forwarding=siem)


@_register("aws_wafv2_request_validation_rules", ["wafv2_web_acl", "load_balancer_v2"])
def request_validation_rules(item, index):
    arn, _, _ = _waf(item, index)
    acl_rows = _inventory(index, "wafv2_web_acl")
    lbs = _inventory(index, "load_balancer_v2")
    _, _, account, region = _context(index)
    acls = {}
    for row in acl_rows:
        key = _arn(get(row, "ARN", str), "wafv2", account, region)
        if key in acls:
            raise Unavailable("duplicate WAF ACL identity")
        acls[key] = row
    failed, public = [], []
    for lb in lbs:
        lbarn = _arn(get(lb, "LoadBalancerArn", str), "elasticloadbalancing", account, region)
        lb_type = get(lb, "Type", str)
        if lb_type not in ("application", "network", "gateway"):
            raise Unavailable("unrecognized load balancer type")
        if lb_type != "application":
            continue
        scheme = get(lb, "Scheme", str)
        if scheme not in ("internet-facing", "internal"):
            raise Unavailable("unrecognized load balancer scheme")
        if scheme == "internal":
            continue
        public.append(lbarn)
        association = get(lb, "WAFWebACLArn", str)  # empty string is a proven absent association
        if association:
            _arn(association, "wafv2", account, region)
            if association not in acls:
                raise Unavailable("associated WAF ACL absent from complete inventory")
            _, _, rules = _waf(acls[association], index)
            good = any(get(get(rule, "Statement", dict), "ManagedRuleGroupStatement", dict).get("VendorName") == "AWS"
                and get(rule["Statement"]["ManagedRuleGroupStatement"], "Name", str) == "AWSManagedRulesCommonRuleSet"
                and get(rule, "OverrideAction", dict) == {"None": {}}
                for rule in rules if "ManagedRuleGroupStatement" in get(rule, "Statement", dict))
        else:
            good = False
        if not good:
            failed.append(lbarn)
    if not public:
        return "NOT_APPLICABLE", {"web_acl_arn": arn, "reason": "no internet-facing ALB"}
    return result(bool(failed), web_acl_arn=arn, public_albs=public, unprotected_albs=failed)

def _events(item, index):
    context, scope, _, _ = _context(index)
    if isinstance(item, dict) and item.get("provider") == "aws" and item.get("scope") == scope:
        rows = _inventory(index, "event_rule")
    else:
        rows = _inventory(index, "event_rule", item)
    _, _, account, region = _context(index)
    for row in rows:
        _arn(get(row, "Arn", str), "events", account, region)
        if get(row, "EventBusName", str) != "default":
            raise Unavailable("event rule outside default bus")
    return rows


def _pattern(row):
    value = get(row, "EventPattern")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise Unavailable("malformed event pattern JSON") from exc
    if not isinstance(value, dict):
        raise Unavailable("malformed event pattern")
    return value


def _literal_selector_relevance(pattern, field, expected):
    """True/False for readable literal selectors; None if they might match."""
    try:
        values = get(pattern, field, list)
    except Unavailable:
        return None
    if not values or any(not isinstance(value, str) or not value for value in values):
        return None
    return expected in values


def _event_relevance(pattern, source, detail_type):
    # Either complete literal selector can independently exclude the event.
    source_match = _literal_selector_relevance(pattern, "source", source)
    type_match = _literal_selector_relevance(pattern, "detail-type", detail_type)
    if source_match is False or type_match is False:
        return False
    if source_match is None or type_match is None:
        raise Unavailable("event source or detail type may match but is unresolved")
    return True


def _native_scheduled_only(row):
    if "EventPattern" in row:
        return False  # A rule can trigger on both a schedule and matching events.
    marker = get(get(row, "_coverage", dict), "EventPattern", dict)
    provenance = get(row, "_provenance", dict)
    schedule = get(row, "ScheduleExpression", str)
    if (marker.get("status") != "empty" or marker.get("source_operation") != "events:ListRules"
            or marker.get("rule_arn") != get(row, "Arn", str)
            or marker.get("rule_name") != get(row, "Name", str)
            or marker.get("schedule_expression") != schedule
            or marker.get("event_bus_name") != "default"
            or provenance.get("source_operation") != "events:ListRules" or provenance.get("read_only") is not True
            or "ManagedBy" in row):
        raise Unavailable("native scheduled-only rule proof unavailable")
    if not schedule or schedule != schedule.strip():
        raise Unavailable("native scheduled-only rule schedule malformed")
    return True


def _event_match(row, source, detail_type, detail, *, allowed_detail=None):
    """Return covered literal values only for exact, unnarrowed event patterns."""
    pattern = _pattern(row)
    if not _event_relevance(pattern, source, detail_type):
        return set()
    if set(pattern) - {"source", "detail-type", "detail"}:
        raise Unavailable("event pattern has unreviewed narrowing clauses")
    body = get(pattern, "detail", dict)
    if set(body) - {key.split(".")[0] for key in detail}:
        raise Unavailable("event detail has unreviewed narrowing clauses")
    values_for_field = set()
    for path, expected in detail.items():
        parts = path.split(".")
        node = body
        for part in parts[:-1]:
            if set(node) != {part}:
                raise Unavailable("nested event detail has unreviewed narrowing clauses")
            node = get(node, part, dict)
        if len(parts) > 1 and set(node) != {parts[-1]}:
            raise Unavailable("event detail has unreviewed narrowing clauses")
        values = set(_strings(get(node, parts[-1], list)))
        if path == allowed_detail:
            values_for_field = values
        elif expected not in values:
            return set()
    return values_for_field if allowed_detail else {True}


def _targets(row):
    targets = get(row, "Targets", dict)
    if get(targets, "collection_status", str) not in ("collected", "empty"):
        raise Unavailable("event targets incomplete")
    values = _objects(get(targets, "items", list))
    return [get(target, "Arn", str) for target in values]


def _event_coverage(item, index, source, detail_type, detail, field, required, *, single_rule=False):
    rows = _events(item, index)
    covered = set()
    unresolved = 0
    complete_witness = False
    for row in rows:
        try:
            state = get(row, "State", str)
            if state not in ("ENABLED", "DISABLED", "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"):
                raise Unavailable("unrecognized EventBridge state")
            if state == "DISABLED":
                continue
            if _native_scheduled_only(row):
                continue
            pattern_covered = _event_match(row, source, detail_type, detail, allowed_detail=field)
            if pattern_covered and state != "DISABLED" and any(_targets(row)):
                covered.update(pattern_covered & required)
                if required <= pattern_covered:
                    complete_witness = True
        except Unavailable:
            unresolved += 1
    satisfied = complete_witness if single_rule else covered == required
    if not satisfied and unresolved:
        return unknown('event pattern or notification target evidence unresolved', covered_values=sorted(covered), missing_values=sorted(required-covered), unresolved_rules=unresolved)
    return result(not satisfied, covered_values=sorted(covered), missing_values=sorted(required - covered))


@_register("aws_eventbridge_iam_user_change_alert", ["event_rule"])
def iam_user_change_alert(item, index):
    required = {"CreateUser", "DeleteUser", "UpdateUser", "CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey"}
    return _event_coverage(item, index, "aws.iam", "AWS API Call via CloudTrail",
        {"eventSource": "iam.amazonaws.com", "eventName": required}, "eventName", required)


@_register("aws_eventbridge_snapshot_change_alert", ["event_rule"])
def snapshot_change_alert(item, index):
    required = {"CreateSnapshot", "ModifySnapshotAttribute", "DeleteSnapshot"}
    return _event_coverage(item, index, "aws.ec2", "AWS API Call via CloudTrail",
        {"eventSource": "ec2.amazonaws.com", "eventName": required}, "eventName", required)


@_register("aws_securityhub_findings_alerted", ["event_rule"])
def securityhub_findings_alerted(item, index):
    required = {"HIGH", "CRITICAL"}
    return _event_coverage(item, index, "aws.securityhub", "Security Hub Findings - Imported",
        {"findings.Severity.Label": required}, "findings.Severity.Label", required, single_rule=True)


@_register("aws_securityhub_medium_findings_alert", ["event_rule"])
def securityhub_medium_findings_alert(item, index):
    required = {"MEDIUM", "LOW", "INFORMATIONAL"}
    return _event_coverage(item, index, "aws.securityhub", "Security Hub Findings - Imported",
        {"findings.Severity.Label": required}, "findings.Severity.Label", required)


@_register("aws_inspector_critical_image_findings_alert", ["event_rule"])
def inspector_critical_image_findings_alert(item, index):
    rows = _events(item, index)
    required = {"AWS_EC2_INSTANCE", "AWS_ECR_CONTAINER_IMAGE"}
    covered = set()
    unresolved = 0
    for row in rows:
        try:
            state = get(row, "State", str)
            if state not in ("ENABLED", "DISABLED", "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"):
                raise Unavailable("unrecognized EventBridge state")
            if state == "DISABLED":
                continue
            if _native_scheduled_only(row):
                continue
            pattern = _pattern(row)
            if not _event_relevance(pattern, "aws.inspector2", "Inspector2 Finding"):
                continue
            if set(pattern) - {"source", "detail-type", "detail"}:
                raise Unavailable("unreviewed Inspector event pattern")
            detail = get(pattern, "detail", dict)
            if set(detail) != {"severity", "resources"} or "CRITICAL" not in _strings(get(detail, "severity", list)):
                raise Unavailable("Inspector finding filters cannot prove severity and resource coverage")
            resources = get(detail, "resources", dict)
            if set(resources) != {"type"}:
                raise Unavailable("unreviewed Inspector resource filter")
            kinds = set(_strings(get(resources, "type", list)))
            if state != "DISABLED" and any(_targets(row)):
                covered.update(kinds & required)
        except Unavailable:
            unresolved += 1
    if covered != required and unresolved:
        return unknown('event pattern or notification target evidence unresolved', covered_values=sorted(covered), missing_values=sorted(required-covered), unresolved_rules=unresolved)
    return result(covered != required, covered_resource_types=sorted(covered), missing_resource_types=sorted(required - covered))


@_register("aws_ecr_scan_findings_metric_export", ["event_rule", "cloudwatch_metric"])
def ecr_scan_findings_metric_export(item, index):
    rows = _events(item, index)
    metrics = _inventory(index, "cloudwatch_metric")
    target = _policy(index, "metric_ingestion_target_arn", str)
    namespace = _policy(index, "ecr_scan_metric_namespace", str)
    metric_name = _policy(index, "ecr_scan_metric_name", str)
    if not all((target, namespace, metric_name)):
        raise Unavailable("metric ingestion policy incomplete")
    present = any(get(m, "Namespace", str) == namespace and get(m, "MetricName", str) == metric_name for m in metrics)
    forwarded = False
    for row in rows:
        state = get(row, "State", str)
        if state not in ("ENABLED", "DISABLED", "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"):
            raise Unavailable("unrecognized EventBridge state")
        pattern = _pattern(row)
        if set(pattern) - {"source", "detail-type", "detail"}:
            raise Unavailable("unreviewed scan event pattern")
        sources = _strings(get(pattern, "source", list))
        types = _strings(get(pattern, "detail-type", list))
        if not ({"aws.ecr", "aws.inspector2"} & set(sources)):
            continue
        if ("ECR Image Scan" in types or "Inspector2 Finding" in types) and state != "DISABLED":
            if set(pattern.get("detail", {})):
                raise Unavailable("scan event pattern has unreviewed narrowing clauses")
            forwarded |= target in _targets(row)
    return result(not (present and forwarded), metric_present=present, forwarded_to_metric_ingestion=forwarded)


@_register("aws_route53resolver_blocked_query_alert", ["event_rule", "resolver_firewall_association", "cloudwatch_alarm"])
def resolver_blocked_query_alert(item, index):
    _events(item, index)
    associations = _inventory(index, "resolver_firewall_association")
    alarms = _alarms(index)
    protected = set()
    for row in associations:
        if get(row, "Status", str) != "COMPLETE":
            raise Unavailable("DNS firewall association not stable")
        protected.add(get(row, "VpcId", str))
    if not protected:
        return "NOT_APPLICABLE", {"reason": "no protected VPC associations"}
    missing = []
    for vpc in sorted(protected):
        if not any(_alarm_matches(alarm, metric="BlockedQueries", namespace="AWS/Route53Resolver",
                    dimensions={"VpcId": vpc}) for alarm in alarms):
            missing.append(vpc)
    return result(bool(missing), protected_vpcs=sorted(protected), vpcs_without_blocked_query_alarm=missing)

@_register("aws_cis_ec2_instance_approved_ami", ["instance", "ec2_instance_image"])
def instance_approved_ami(item, index):
    _inventory(index, "instance", item)
    state = get(get(item, "State", dict), "Name", str)
    if state not in {"pending", "running", "shutting-down", "terminated", "stopping", "stopped"}:
        raise Unavailable("unrecognized instance state")
    instance_id = get(item, "InstanceId", str)
    if state != "running":
        return "NOT_APPLICABLE", {"instance_id": instance_id, "reason": "instance is not running"}
    image_id = get(item, "ImageId", str)
    rows = _inventory(index, "ec2_instance_image")
    image = [row for row in rows if get(row, "ImageId", str) == image_id]
    if len(image) != 1:
        raise Unavailable("AMI metadata missing or ambiguous")
    owner = get(image[0], "OwnerId", str)
    approved_ids = set(_strings(_policy(index, "approved_image_ids", list)))
    approved_owners = set(_strings(_policy(index, "approved_owner_ids", list)))
    return result(image_id not in approved_ids or owner not in approved_owners,
                  instance_id=instance_id, image_id=image_id, image_owner_id=owner)


@_register("aws_cis_ec2_userdata_embedded_secrets", ["instance"])
def userdata_embedded_secrets(item, index):
    _inventory(index, "instance", item)
    instance_id = get(item, "InstanceId", str)
    indicators = get(item, "UserDataSecretIndicators", dict)
    if get(indicators, "collection_status", str) != "collected":
        raise Unavailable("high-confidence user-data projection unavailable")
    if get(indicators, "InstanceId", str) != instance_id:
        raise Unavailable("user-data projection identity mismatch")
    present = get(indicators, "Present", bool)
    secret = get(indicators, "HighConfidenceSecretPresent", bool)
    categories = _strings(get(indicators, "MatchedCategories", list))
    if any(category not in {"private_key", "cloud_credential", "password_assignment"} for category in categories):
        raise Unavailable("unrecognized secret category")
    if (not present and secret) or (secret != bool(categories)):
        raise Unavailable("contradictory user-data secret projection")
    return result(secret, instance_id=instance_id, matched_categories=sorted(categories))
