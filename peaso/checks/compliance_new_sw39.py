"""Signed AWS compliance predicates over complete, scoped snapshot facts.

Operator decisions live in context.metadata.compliance_policy. Missing policy or
collector facts are UNKNOWN; these evaluators make no live AWS calls.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime
import json
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects


SPECS = {
    "aws_nist_waf_web_acl_resource_associated": ("wafregional_web_acl", "medium", "compliance", "WAF web ACL should be associated with an Application Load Balancer, API Gateway stage, or CloudFront distributions", "4cbf1ad6f95f9e8a2969b4589f78f004bd5fed2628ab9d7c2330e4ddf3c22994"),
    "aws_detective_ai_account_graph_enabled": ("detective_graph", "medium", "compliance", "AI Incident Investigation", "b73dd483bc4f869d15c18a8abd85c5a8c512d8af4f2f6b114f34ca31c976bb2b"),
    "aws_sagemaker_approved_image_restriction": ("sagemaker_domain", "medium", "compliance", "SageMaker domain restricts image selection", "d3141aac7b9c407f59d70e5edc27c677730683d95639a4fbf5fd85c114e5aaa5"),
    "aws_budgets_stop_action": ("budget_action", "medium", "hardening", "Configure Budgets Actions to stop services in cases of big unexpected spendings", "d356e89b7c48d80c5351777b290542a55b4d46e4b82f0acef286c4199a3e0e81"),
    "aws_service_transport_peer_authentication": ("elbv2_listener", "medium", "hardening", "Service communications authenticate peers", "5f57ec2bed1d77a1836d757df4334e88d29fb576780de99fdea20d02290067cb"),
    "aws_siem_log_delivery": ("log_destination", "medium", "hardening", "Security logs reach the approved SIEM", "12039e21eff44922f17d6a034e2be9e548656d706b946004e8cce7358fb2c614"),
    "aws_development_backup_assignment": ("backup_selection", "medium", "hardening", "Development resources have backup assignments", "34107af20e6d724e17d79fdca0bbda5641c8d4f8a87136c5aa877e39d0e57d97"),
    "aws.pci.codecommit.pr_review_approval": ("codecommit_pull_request", "medium", "secure_development", "CodeCommit changes receive independent review", "8c39f2a50cae436d98c79d133fa919dd4ea23d2fd45638b685154916509529bb"),
    "aws_cis_aws_resource_policy_unrestricted_principal": ("aws_resource_policy", "high", "exposure", "AWS resource policies reject unrestricted principals", "e0834b378a442a704132024131da2924fd30db30f594abf551c97a51ec7ff2a1"),
}


def _signed(check_id, dependencies, *, target="resource"):
    kind, severity, category, title, _ = SPECS[check_id]

    def decorate(function):
        register(check_id, "aws", category if category in {"hardening", "exposure", "least_privilege", "iam_graph", "network"} else "hardening",
                 kind, title, severity, "CM-6", "Review the observed configuration and approved workload policy.",
                 target=target, dependencies=dependencies)(function)
        CHECKS[-1] = replace(CHECKS[-1], category=category)
        return function
    return decorate


def _scope(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS provider authority unavailable")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]", scope):
        raise Unavailable("AWS account/Region scope unavailable")
    return scope


def _rows(index, kind, scope):
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("complete collection unavailable: " + kind)
    envelope = get({"value": envelopes[0]}, "value", dict)
    if (get(envelope, "type", str) != kind or get(envelope, "scope", str) != scope or
            get(envelope, "status", str) not in ("collected", "empty") or
            envelope.get("coverage_status", "collected") not in ("collected", "empty")):
        raise Unavailable("foreign or incomplete collection: " + kind)
    rows = complete_items(index, kind)
    displayed = list_of_objects(get(envelope, "items", list))
    encode = lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"), default=str)
    if Counter(map(encode, rows)) != Counter(map(encode, displayed)) or envelope["status"] == "empty" and rows:
        raise Unavailable("collection projection differs from scoped items: " + kind)
    for projected in get(index, kind, list):
        if get(projected, "type", str) != kind or get(projected, "scope", str) != scope or projected.get("provider", "aws") != "aws":
            raise Unavailable("foreign resource in collection: " + kind)
    return rows


def _item(item, index, kind, identity):
    scope = _scope(index)
    rows = _rows(index, kind, scope)
    found = []
    for row in rows:
        key = get(row, identity, str)
        if not key or key in found:
            raise Unavailable("missing or duplicate " + kind + " identity")
        found.append(key)
    key = get(item, identity, str)
    if found.count(key) != 1 or rows[found.index(key)] != item:
        raise Unavailable("resource is absent from complete scoped inventory")
    return scope


def _policy(index, scope):
    policy = get(get(get(index, "context", dict), "metadata", dict), "compliance_policy", dict)
    if get(policy, "status", str) != "collected" or get(policy, "scope", str) != scope:
        raise Unavailable("approved scope-bound compliance policy unavailable")
    return policy


def _strings(value, *, empty=True):
    if not isinstance(value, list) or (not empty and not value) or any(not isinstance(x, str) or not x for x in value) or len(value) != len(set(value)):
        raise Unavailable("malformed approved or collected string list")
    return set(value)


def _timestamp(value):
    if not isinstance(value, str):
        raise Unavailable("timestamp unavailable")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("malformed timestamp") from exc
    if parsed.tzinfo is None:
        raise Unavailable("timestamp missing timezone")
    return parsed


def _arn_scope(arn, scope, service=None):
    account, region = scope.split("/", 1)
    match = re.fullmatch(r"arn:(aws(?:-[a-z0-9-]+)?):([a-z0-9-]+):([a-z0-9-]*):([0-9]{12}):(.+)", arn)
    if not match or match.group(4) != account or match.group(3) not in (region, "") or service and match.group(2) != service:
        raise Unavailable("malformed or foreign AWS ARN")
    return match


def _arn(value):
    if not isinstance(value, str) or not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:[a-z0-9-]+:[^:]*:[^:]*:.+", value):
        raise Unavailable("malformed AWS ARN")
    return value


@_signed("aws_nist_waf_web_acl_resource_associated", ["wafregional_web_acl"])
def waf_associated(item, index):
    scope = _item(item, index, "wafregional_web_acl", "WebACLId")
    acl_id = get(item, "WebACLId", str)
    if not acl_id:
        raise Unavailable("empty Web ACL ID")
    if get(item, "WebACL.WebACLId", str) != acl_id:
        raise Unavailable("Web ACL detail identity mismatch")
    association = get(item, "ResourceArns", dict)
    if get(association, "collection_status", str) != "collected":
        raise Unavailable("Web ACL association inventory incomplete")
    by_type = get(association, "ByResourceType", dict)
    if set(by_type) != {"APPLICATION_LOAD_BALANCER", "API_GATEWAY"} or any(value not in ("collected", "not_applicable") for value in by_type.values()):
        raise Unavailable("Web ACL association resource-type coverage incomplete")
    resources = _strings(get(association, "ResourceArns", list))
    for arn in resources:
        _arn_scope(arn, scope)
    return result(not resources, web_acl_id=acl_id, associated_resource_arns=sorted(resources),
                  semantics="Regional Classic WAF ALB and API Gateway associations; global and WAFv2 ACLs require their own inventory")


@_signed("aws_detective_ai_account_graph_enabled", ["detective_graph"], target="scope")
def detective_graph(item, index):
    scope = _scope(index)
    if get(item, "scope", str) != scope:
        raise Unavailable("Detective subject is foreign to scope")
    policy = _policy(index, scope)
    if get(policy, "ai_workload", bool) is False:
        return "NOT_APPLICABLE", {"reason": "account/Region is not designated as an AI workload"}
    graphs = _rows(index, "detective_graph", scope)
    arns = set()
    for graph in graphs:
        arn = get(graph, "Arn", str)
        _arn_scope(arn, scope, "detective")
        if arn in arns:
            raise Unavailable("duplicate Detective graph ARN")
        arns.add(arn)
        _timestamp(get(graph, "CreatedTime", str))
    return result(not arns, graph_arns=sorted(arns))


@_signed("aws_sagemaker_approved_image_restriction", ["sagemaker_domain"])
def sagemaker_images(item, index):
    scope = _item(item, index, "sagemaker_domain", "DomainArn")
    _arn_scope(get(item, "DomainArn", str), scope, "sagemaker")
    approved = _strings(get(_policy(index, scope), "approved_sagemaker_image_names", list))
    names = []
    for path in ("DefaultUserSettings.CustomImages", "DefaultUserSettings.JupyterLabAppSettings.CustomImages",
                 "DefaultSpaceSettings.JupyterLabAppSettings.CustomImages"):
        for row in list_of_objects(get(item, path, list)):
            names.append(get(row, "ImageName", str))
    if any(not name for name in names):
        raise Unavailable("empty SageMaker custom image name")
    return result(bool(set(names) - approved), domain_arn=item["DomainArn"],
                  unapproved_image_names=sorted(set(names) - approved))


def _native_budget_stop(item, index):
    from peaso.aws_budget_policy import normalize_value, definition, execution, timestamp, STATUSES
    from datetime import timezone
    context = get(index, "context", dict)
    scope = get(context, "scope", str)
    if context.get('provider') != 'aws' or not re.fullmatch(r'[0-9]{12}/global', scope):
        raise Unavailable('native Budgets account scope unavailable')
    account = scope.split('/')[0]
    rows = _rows(index, 'budget_action', scope)
    ids = [get(row, 'ActionId', str) for row in rows]
    if len(set(ids)) != len(ids) or ids.count(get(item, 'ActionId', str)) != 1 or item != rows[ids.index(item['ActionId'])]:
        raise Unavailable('native budget action identity ambiguous')
    try:
        metadata = get(context, 'metadata', dict)
        callers = [c for c in get(metadata,'caller_identities',list) if isinstance(c,dict) and c.get('Account') == account]
        if len(callers) != 1:raise ValueError('native Budgets caller identity unavailable')
        caller = re.fullmatch(r'arn:(aws(?:-[a-z0-9-]+)?):(?:sts|iam)::'+re.escape(account)+r':.+',get(callers[0],'Arn',str))
        if not caller:raise ValueError('native Budgets caller partition unavailable')
        raw = get(metadata, 'parameters', dict).get('aws_budget_stop')
        policy = normalize_value(raw)
        if policy['scope'] != scope or not timestamp(policy['observed_at']) <= datetime.now(timezone.utc) <= timestamp(policy['expires_at']):
            raise ValueError('native budget obligation is foreign or expired')
        name = get(item, 'BudgetName', str)
        approved = policy['budgets'].get(name)
        if approved is None:raise ValueError('explicit native budget obligation missing')
        suitable = []
        for action in rows:
            provenance = get(action, '_provenance', dict)
            partition = provenance.get('partition')
            if (partition != caller.group(1) or
                    not re.fullmatch(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}',get(action,'ActionId',str)) or
                    action.get('AccountId') != account or type(provenance.get('native_budget_action_schema')) is not int or provenance['native_budget_action_schema'] != 1 or
                    provenance.get('source_operations') != ['budgets:DescribeBudgetActionsForAccount','budgets:DescribeBudgetAction'] or provenance.get('execution_observed') is not False or
                    provenance.get('read_only') is not True or provenance.get('detail_get_complete') is not True):
                raise ValueError('native budget account/provenance unverified')
            if action.get('Status') not in STATUSES or action.get('ActionType') not in {'RUN_SSM_DOCUMENTS','APPLY_IAM_POLICY','APPLY_SCP_POLICY'}:
                raise ValueError('native budget state/type unsupported')
            execution(action,account,partition)
            if action.get('BudgetName') != name or action['ActionType'] != 'RUN_SSM_DOCUMENTS':continue
            if set(get(action,'Definition',dict)) != {'SsmActionDefinition'}:
                raise ValueError('native SSM definition is ambiguous')
            native = definition({**get(action, 'Definition.SsmActionDefinition', dict), **{k:action[k] for k in ('ExecutionRoleArn','ApprovalModel','NotificationType','ActionThreshold')}}, account, provenance.get('partition'))
            definition(approved, account, provenance.get('partition'))
            if (action['Status'] in {'STANDBY','EXECUTION_IN_PROGRESS'} and
                    all(native[k] == approved[k] for k in native if k != 'InstanceIds') and
                    set(native['InstanceIds']) == set(approved['InstanceIds'])):
                suitable.append(action['ActionId'])
        return result(not suitable, budget_name=name, approved_stop_action_ids=sorted(suitable),
                      evidence_semantics='configured native stop action; execution and target instance state not observed')
    except (ValueError,KeyError,TypeError,AttributeError) as exc:
        raise Unavailable('native Budgets configuration or owner policy unavailable') from exc


@_signed("aws_budgets_stop_action", ["budget_action"])
def budget_stop(item, index):
    if any(key in item for key in ('Definition','Status','ExecutionRoleArn','AccountId')):
        return _native_budget_stop(item, index)
    scope = _item(item, index, "budget_action", "ActionId")
    policy = _policy(index, scope)
    documents = _strings(get(policy, "approved_stop_document_arns", list), empty=False)
    roles = _strings(get(policy, "approved_stop_target_role_arns", list), empty=False)
    thresholds = get(policy, "budget_action_thresholds", dict)
    budget_name = get(item, "BudgetName", str)
    if budget_name not in thresholds or not isinstance(thresholds[budget_name], dict):
        raise Unavailable("approved budget threshold unavailable")
    approved_threshold = thresholds[budget_name]
    approved_type = get(approved_threshold, "ActionThresholdType", str)
    approved_value = get(approved_threshold, "ActionThresholdValue")
    if approved_type not in ("PERCENTAGE", "ABSOLUTE_VALUE") or type(approved_value) not in (int, float) or approved_value <= 0:
        raise Unavailable("malformed approved budget threshold")
    suitable_ids = []
    seen = set()
    for action in _rows(index, "budget_action", scope):
        if get(action, "BudgetName", str) != budget_name:
            continue
        action_id = get(action, "ActionId", str)
        if not action_id or action_id in seen:
            raise Unavailable("duplicate budget action identity")
        seen.add(action_id)
        threshold = get(action, "ActionThreshold", dict)
        value = get(threshold, "ActionThresholdValue")
        kind = get(threshold, "ActionThresholdType", str)
        if type(value) not in (int, float) or value <= 0 or kind not in ("PERCENTAGE", "ABSOLUTE_VALUE"):
            raise Unavailable("malformed budget action threshold")
        status = get(action, "ActionStatus", str)
        action_type = get(action, "ActionType", str)
        if status not in ("STANDBY", "EXECUTION_IN_PROGRESS", "EXECUTION_SUCCESS", "EXECUTION_FAILURE", "REVERSE_IN_PROGRESS", "REVERSE_SUCCESS", "REVERSE_FAILURE", "RESET_IN_PROGRESS", "RESET_SUCCESS", "RESET_FAILURE"):
            raise Unavailable("unrecognized budget action status")
        if action_type not in ("RUN_SSM_DOCUMENTS", "APPLY_IAM_POLICY", "APPLY_SCP_POLICY"):
            raise Unavailable("unrecognized budget action type")
        if action_type != "RUN_SSM_DOCUMENTS":
            continue
        document = get(action, "SsmActionDefinition.DocumentArn", str)
        _arn(document)
        targets = _strings(get(action, "TargetRoleArns", list), empty=False)
        for arn in targets:
            _arn_scope(arn, scope, "iam")
        if (status in ("STANDBY", "EXECUTION_IN_PROGRESS") and document in documents and targets <= roles
                and kind == approved_type and value == approved_value):
            suitable_ids.append(action_id)
    return result(not suitable_ids, budget_name=budget_name, approved_stop_action_ids=sorted(suitable_ids))


@_signed("aws_service_transport_peer_authentication", ["elbv2_listener", "load_balancer"])
def alb_listener(item, index):
    scope = _item(item, index, "elbv2_listener", "ListenerArn")
    listeners_arn = get(item, "ListenerArn", str)
    _arn_scope(listeners_arn, scope, "elasticloadbalancing")
    lb_arn = get(item, "LoadBalancerArn", str)
    _arn_scope(lb_arn, scope, "elasticloadbalancing")
    lbs = _rows(index, "load_balancer", scope)
    matching = [lb for lb in lbs if get(lb, "LoadBalancerArn", str) == lb_arn]
    if len(matching) != 1:
        raise Unavailable("listener load balancer join unavailable")
    lb = matching[0]
    if get(lb, "Type", str) != "application":
        return "NOT_APPLICABLE", {"reason": "listener does not belong to an ALB"}
    scheme = get(lb, "Scheme", str)
    if scheme == "internal":
        return "NOT_APPLICABLE", {"reason": "ALB is internal"}
    if scheme != "internet-facing":
        raise Unavailable("unrecognized load balancer scheme")
    policy = _policy(index, scope)
    certs = _strings(get(policy, "approved_acm_certificate_arns", list), empty=False)
    tls = _strings(get(policy, "approved_tls_policies", list), empty=False)
    protocol = get(item, "Protocol", str)
    if protocol not in ("HTTP", "HTTPS"):
        raise Unavailable("unsupported public ALB listener protocol")
    if protocol == "HTTP":
        return result(True, listener_arn=listeners_arn, protocol=protocol)
    configured = {get(cert, "CertificateArn", str) for cert in list_of_objects(get(item, "Certificates", list))}
    if not configured:
        raise Unavailable("ALB listener certificate inventory unavailable")
    for arn in configured:
        _arn_scope(arn, scope, "acm")
    ssl = get(item, "SslPolicy", str)
    if not ssl:
        raise Unavailable("ALB listener TLS policy unavailable")
    return result(not bool(configured & certs) or ssl not in tls, listener_arn=listeners_arn,
                  approved_certificate_present=bool(configured & certs), approved_tls_policy=ssl in tls,
                  semantics="Server certificate and TLS configuration only; client peer validation requires manual evidence")


@_signed("aws_siem_log_delivery", ["log_destination", "log_subscription_filter"], target="scope")
def siem_subscription(item, index):
    scope = _scope(index)
    if get(item, "scope", str) != scope:
        raise Unavailable("SIEM subject is foreign to scope")
    policy = _policy(index, scope)
    approved = get(policy, "approved_siem_destination_arn", str)
    _arn(approved)
    designated = _strings(get(policy, "designated_log_groups", list))
    destinations = _rows(index, "log_destination", scope)
    targets = {}
    for dest in destinations:
        arn = get(dest, "arn", str)
        _arn_scope(arn, scope, "logs")
        if arn in targets:
            raise Unavailable("duplicate CloudWatch Logs destination")
        targets[arn] = _arn(get(dest, "targetArn", str))
    subscriptions = _rows(index, "log_subscription_filter", scope)
    by_group = {}
    for row in subscriptions:
        name = get(row, "logGroupName", str)
        if not name:
            raise Unavailable("empty log group name")
        if name in by_group:
            raise Unavailable("duplicate log group subscription inventory")
        by_group[name] = list_of_objects(get(row, "subscriptionFilters", list))
    if set(by_group) != designated:
        raise Unavailable("designated log group subscription coverage incomplete")
    missing = []
    for group in sorted(designated):
        matches = False
        for filt in by_group[group]:
            dest = _arn(get(filt, "destinationArn", str))
            get(filt, "filterPattern", str)
            matches |= dest == approved or targets.get(dest) == approved
        if not matches:
            missing.append(group)
    return result(bool(missing), missing_log_groups=missing,
                  semantics="Configured subscriptions only; event delivery and SIEM analysis require separate evidence")


@_signed("aws_development_backup_assignment", ["backup_selection", "backup_plan"])
def development_backup(item, index):
    scope = _item(item, index, "backup_selection", "id")
    policy = _policy(index, scope)
    development = _strings(get(policy, "development_resource_arns", list))
    if not development:
        return "NOT_APPLICABLE", {"reason": "no approved development resources in scope"}
    for arn in development:
        _arn_scope(arn, scope)
    plans = _rows(index, "backup_plan", scope)
    scheduled, seen_plans = set(), set()
    for plan in plans:
        plan_id = get(plan, "BackupPlanId", str)
        if not plan_id or plan_id in seen_plans:
            raise Unavailable("missing or duplicate backup plan identity")
        seen_plans.add(plan_id)
        rules = list_of_objects(get(plan, "Rules", list))
        if any(get(rule, "ScheduleExpression", str) for rule in rules):
            scheduled.add(plan_id)
    selections = _rows(index, "backup_selection", scope)
    selected = set()
    seen = set()
    for selection in selections:
        key = get(selection, "id", str)
        plan_id = get(selection, "BackupPlanId", str)
        if key in seen or key != plan_id + "/" + get(selection, "SelectionId", str):
            raise Unavailable("duplicate or malformed backup selection identity")
        seen.add(key)
        resources = _strings(get(selection, "Resources", list))
        excluded = _strings(get(selection, "NotResources", list))
        # Wildcards and tag/condition selection need a dedicated exact matcher.
        if any("*" in arn or "?" in arn for arn in resources | excluded):
            raise Unavailable("backup selection wildcard semantics unavailable")
        for arn in resources | excluded:
            _arn_scope(arn, scope)
        if get(selection, "ListOfTags", list) or get(selection, "Conditions", dict):
            raise Unavailable("backup selection tag/condition matcher unavailable")
        if plan_id in scheduled:
            selected |= (resources - excluded) & development
    missing = sorted(development - selected)
    return result(bool(missing), unassigned_development_resource_arns=missing,
                  semantics="Exact ARN selections under scheduled plans; resource recovery untested")


@_signed("aws.pci.codecommit.pr_review_approval", ["codecommit_pull_request"])
def codecommit_review(item, index):
    scope = _item(item, index, "codecommit_pull_request", "pullRequestId")
    status = get(item, "pullRequestStatus", str)
    if status not in ("OPEN", "CLOSED"):
        raise Unavailable("unrecognized pull request status")
    targets = list_of_objects(get(item, "pullRequestTargets", list))
    if not targets:
        raise Unavailable("pull request targets unavailable")
    merged = [target for target in targets if get(target, "mergeMetadata.IsMerged", bool)]
    if not merged:
        return "NOT_APPLICABLE", {"reason": "pull request has no merged target"}
    author = get(item, "authorArn", str)
    _arn_scope(author, scope)
    reviewers = _strings(get(_policy(index, scope), "security_reviewer_arns", list), empty=False)
    states = list_of_objects(get(item, "ApprovalStates", list))
    events = list_of_objects(get(item, "ApprovalEvents", list))
    valid, seen_states = set(), set()
    for state in states:
        reviewer = get(state, "UserArn", str)
        _arn_scope(reviewer, scope)
        if reviewer in seen_states:
            raise Unavailable("duplicate or conflicting reviewer approval state")
        seen_states.add(reviewer)
        decision = get(state, "ApprovalState", str)
        if decision not in ("APPROVE", "REVOKE"):
            raise Unavailable("unrecognized pull request approval state")
        if decision == "APPROVE" and reviewer != author and reviewer in reviewers:
            valid.add(reviewer)
    for event in events:
        reviewer = get(event, "UserArn", str)
        _arn_scope(reviewer, scope)
        decision = get(event, "ApprovalState", str)
        if decision not in ("APPROVE", "REVOKE"):
            raise Unavailable("unrecognized approval event")
        _timestamp(get(event, "eventDate", str))
    missing = []
    for target in merged:
        merged_at = _timestamp(get(target, "mergeMetadata.MergedAt", str))
        latest = {}
        for event in events:
            event_at = _timestamp(get(event, "eventDate", str))
            if event_at >= merged_at:
                continue
            reviewer = event["UserArn"]
            if reviewer in latest and latest[reviewer][0] == event_at and latest[reviewer][1] != event["ApprovalState"]:
                raise Unavailable("conflicting approval events at the same instant")
            if reviewer not in latest or event_at > latest[reviewer][0]:
                latest[reviewer] = (event_at, event["ApprovalState"])
        if not any(reviewer in valid and decision == "APPROVE" for reviewer, (_, decision) in latest.items()):
            missing.append(get(target, "repositoryName", str))
    return result(bool(missing), pull_request_id=item["pullRequestId"], unreviewed_merged_targets=missing)


_BOUND_KEYS = {"aws:principalorgid", "aws:sourceaccount", "aws:sourcearn", "aws:principalarn"}


def _restricted(condition):
    if not isinstance(condition, dict):
        raise Unavailable("malformed resource policy condition")
    for operator, clauses in condition.items():
        if not isinstance(clauses, dict):
            raise Unavailable("malformed resource policy condition clauses")
        for key, value in clauses.items():
            if not isinstance(key, str) or not isinstance(value, (str, list)):
                raise Unavailable("malformed resource policy condition value")
            values = value if isinstance(value, list) else [value]
            if not values or any(not isinstance(x, str) or not x for x in values):
                raise Unavailable("malformed resource policy condition value")
            if key.casefold() not in _BOUND_KEYS:
                continue
            if operator not in ("StringEquals", "ArnEquals", "StringLike", "ArnLike"):
                raise Unavailable("unrecognized principal boundary condition operator")
            if all(x != "*" and "?" not in x and "*" not in x for x in values):
                return True
    return False


@_signed("aws_cis_aws_resource_policy_unrestricted_principal", ["aws_resource_policy"])
def unrestricted_policy(item, index):
    scope = _item(item, index, "aws_resource_policy", "ResourceArn")
    _arn_scope(get(item, "ResourceArn", str), scope)
    raw = get(item, "Policy")
    if isinstance(raw, str):
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise Unavailable("malformed JSON resource policy") from exc
    else:
        document = raw
    if not isinstance(document, dict):
        raise Unavailable("resource policy document unavailable")
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    statements = list_of_objects(statements)
    if not statements:
        raise Unavailable("resource policy statement inventory unavailable")
    if any(get(statement, "Effect", str) == "Deny" for statement in statements):
        raise Unavailable("Deny interaction requires full policy evaluation")
    unrestricted = []
    for statement in statements:
        effect = get(statement, "Effect", str)
        if effect != "Allow":
            raise Unavailable("unrecognized resource policy effect")
        if ("Action" not in statement and "NotAction" not in statement or
                "Resource" not in statement and "NotResource" not in statement):
            raise Unavailable("incomplete resource policy statement")
        if "NotPrincipal" in statement:
            raise Unavailable("NotPrincipal policy semantics unavailable")
        principal = get(statement, "Principal")
        wildcard = principal == "*" or isinstance(principal, dict) and any(value == "*" or isinstance(value, list) and "*" in value for value in principal.values())
        if not isinstance(principal, (str, dict)):
            raise Unavailable("malformed resource policy principal")
        values = [principal] if isinstance(principal, str) else list(principal.values())
        if not values or any(not isinstance(value, (str, list)) or isinstance(value, str) and not value or
                             isinstance(value, list) and (not value or any(not isinstance(x, str) or not x for x in value))
                             for value in values):
            raise Unavailable("malformed resource policy principal")
        restricted = _restricted(statement.get("Condition", {}))
        if wildcard and not restricted:
            unrestricted.append(get(statement, "Sid", str) if "Sid" in statement else "<unnamed>")
    return result(bool(unrestricted), resource_arn=item["ResourceArn"], unrestricted_statements=unrestricted)
