"""Scoped logging declaration joins; no log messages or time series are read."""
import re
from . import register, result, unknown
from .facts import get, optional, complete_items, list_of_objects, unique_join, Unavailable
from .fixtures import CASES

IDS, REFERENCE_SPECS = [], {}
PATTERNS = {'logging_metric_alert_audit_configuration_changes': '\\s*protoPayload.methodName\\s*=\\s*"SetIamPolicy"\\s*AND\\s*protoPayload.serviceData.policyDelta.auditConfigDeltas:\\*\\s*', 'logging_metric_alert_custom_role_changes_with_iam_admin_undelete_role': '\\s*resource\\.type\\s*=\\s*"iam_role"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*=\\s*"google\\.iam\\.admin\\.v1\\.CreateRole"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*"google\\.iam\\.admin\\.v1\\.DeleteRole"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*"google\\.iam\\.admin\\.v1\\.UpdateRole"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*"google\\.iam\\.admin\\.v1\\.UndeleteRole"\\s*\\)', 'logging_metric_alert_custom_role_changes': '\\s*resource\\.type\\s*=\\s*"iam_role"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*=\\s*"google\\.iam\\.admin\\.v1\\.CreateRole"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*"google\\.iam\\.admin\\.v1\\.DeleteRole"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*"google\\.iam\\.admin\\.v1\\.UpdateRole"\\s*\\)', 'logging_metric_alert_firewall_rule_changes': '\\s*resource\\.type\\s*=\\s*"gce_firewall_rule"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*:\\s*"compute\\.firewalls\\.patch"\\s*OR\\s*protoPayload\\.methodName\\s*:\\s*"compute\\.firewalls\\.insert"\\s*OR\\s*protoPayload\\.methodName\\s*:\\s*"compute\\.firewalls\\.delete"\\s*\\)', 'logging_metric_alert_network_changes': '\\s*resource\\.type\\s*=\\s*gce_network\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*=\\s*"beta\\.compute\\.networks\\.insert"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*"beta\\.compute\\.networks\\.patch"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*"v1\\.compute\\.networks\\.delete"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*"v1\\.compute\\.networks\\.removePeering"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*"v1\\.compute\\.networks\\.addPeering"\\s*\\)', 'logging_metric_alert_network_route_changes': '\\s*resource\\.type\\s*=\\s*"gce_route"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*:\\s*"compute\\.routes\\.delete"\\s*OR\\s*protoPayload\\.methodName\\s*:\\s*"compute\\.routes\\.insert"\\s*\\)', 'logging_metric_alert_project_ownership_assignment': '\\s*\\(protoPayload.serviceName\\s*=\\s*"cloudresourcemanager.googleapis.com"\\s*\\)\\s*AND\\s*\\(\\s*ProjectOwnership\\s*OR\\s*projectOwnerInvitee\\s*\\)\\s*OR\\s*\\(\\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\\s*=\\s*"REMOVE"\\s*AND\\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\\s*=\\s*"roles/owner"\\s*\\)\\s*OR\\s*\\(\\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\\s*=\\s*"ADD"\\s*AND\\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\\s*=\\s*"roles/owner"\\s*\\)\\s*', 'logging_metric_alert_sql_instance_configuration_changes': '\\s*protoPayload.methodName\\s*=\\s*"cloudsql.instances.update"\\s*', 'logging_metric_alert_storage_iam_permission_changes': '\\s*resource\\.type\\s*=\\s*"gcs_bucket"\\s*AND\\s*protoPayload\\.methodName\\s*=\\s*"storage\\.setIamPermissions"'}


def rule(query, kind, function, good, bad, dependencies):
    cid = "gcp.ports." + query
    register(cid, "gcp", "hardening", kind, query.replace("_", " "), "medium", "AU-6",
        "Review the declared logging/alert configuration, exact resource scope and collected dependency completeness.",
        dependencies=dependencies)(function)
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None}
    IDS.append(cid)
    REFERENCE_SPECS[query] = cid
    return cid


def project_prefixes(item):
    project = get(item, "projectId", str)
    number = optional(item, "name", "", str).removeprefix("projects/")
    return ["projects/" + value + "/" for value in {project, number} if value]


def metric_alert(query, pattern):
    def evaluate(item, index):
        prefixes = project_prefixes(item)
        metrics = complete_items(index, "logging_metric")
        alerts = complete_items(index, "monitoring_alert_policy")
        eligible = []
        for metric in metrics:
            name = get(metric, "name", str)
            if not any(name.startswith(prefix) for prefix in prefixes):
                continue
            if optional(metric, "disabled", False, bool):
                continue
            if re.search(pattern, get(metric, "filter", str)):
                eligible.append(get(metric, "metricDescriptor.type", str))
        matches = []
        for alert in alerts:
            name = get(alert, "name", str)
            if not any(name.startswith(prefix) for prefix in prefixes) or not get(alert, "enabled", bool):
                continue
            for condition in list_of_objects(get(alert, "conditions", list)):
                threshold = optional(condition, "conditionThreshold", None, dict)
                if threshold is None:
                    continue
                condition_filter = get(threshold, "filter", str)
                if any('metric.type="' + metric_type + '"' in condition_filter for metric_type in eligible):
                    matches.append(name)
        return result(not matches, declared_alerts=sorted(set(matches)),
            semantics="Same-project enabled metric/alert and pinned event-filter template declaration. Cross-project metrics scopes, delivery, incident thresholds and filter equivalence require separate evidence.")
    # Produce a concrete matching filter from this reviewed source grammar.
    filter_value = pattern.replace(r"\s*", "")
    filter_value = re.sub(r"\\([.()*])", r"\1", filter_value)
    good = {"projectId": "p"}
    bad = {"projectId": "q"}
    cid = rule(query + "_scoped", "project", evaluate, good, bad,
        ["project", "logging_metric", "monitoring_alert_policy"])
    CASES[cid]["index"] = {"collections": {kind: [{"status": "collected"}] for kind in ("logging_metric", "monitoring_alert_policy")},
        "logging_metric": [{"data": {"name": "projects/p/metrics/m", "filter": filter_value, "metricDescriptor": {"type": "logging.googleapis.com/user/m"}}}],
        "monitoring_alert_policy": [{"data": {"name": "projects/p/alertPolicies/a", "enabled": True,
            "conditions": [{"conditionThreshold": {"filter": 'metric.type="logging.googleapis.com/user/m"'}}]}}]}
    REFERENCE_SPECS[query] = cid


for _query, _pattern in PATTERNS.items():
    metric_alert(_query, _pattern)


def all_entries(item, index):
    prefixes = project_prefixes(item)
    sinks = complete_items(index, "log_sink")
    matches = []
    for sink in sinks:
        name = get(sink, "name", str)
        if not any(name.startswith(prefix) for prefix in prefixes) or optional(sink, "disabled", False, bool):
            continue
        exclusions = list_of_objects(optional(sink, "exclusions", [], list))
        if any(not optional(exclusion, "disabled", False, bool) for exclusion in exclusions):
            continue
        if not optional(sink, "filter", "", str) and get(sink, "destination", str):
            matches.append(name)
    return result(not matches, declared_sinks=matches,
        semantics="Enabled unfiltered project sink without active exclusions; destination write success is separate")


cid = rule("logging_sink_all_entries_enabled", "project", all_entries, {"projectId": "p"}, {"projectId": "q"}, ["project", "log_sink"])
CASES[cid]["index"] = {"collections": {"log_sink": [{"status": "collected"}]}, "log_sink": [{"data": {"name": "projects/p/sinks/all", "filter": "", "destination": "storage.googleapis.com/b"}}]}


def retained_destination(item, index):
    destination = get(item, "destination", str)
    if not destination.startswith("storage.googleapis.com/"):
        return "NOT_APPLICABLE", {"reason": "Source covers Cloud Storage sink destinations only"}
    bucket_name = destination.split("/", 1)[1]
    bucket = unique_join(index, "bucket", "name", bucket_name)
    policy = optional(bucket, "retentionPolicy", None, dict)
    locked = optional(policy, "isLocked", False, bool) if policy is not None else False
    return result(not locked, bucket=bucket_name, retention_locked=locked,
        semantics="Declared locked destination retention, not proof of exports or retained log volume")


cid = rule("logging_bucket_retention_policy_enabled", "log_sink", retained_destination,
    {"destination": "storage.googleapis.com/locked"}, {"destination": "storage.googleapis.com/unlocked"}, ["log_sink", "bucket"])
CASES[cid]["index"] = {"collections": {"bucket": [{"status": "collected"}]}, "bucket": [{"data": {"name": "locked", "retentionPolicy": {"isLocked": True}}}, {"data": {"name": "unlocked", "retentionPolicy": {"isLocked": False}}}]}


def dns_network_logging(item, index):
    network_url = get(item, "selfLink", str)
    policies = complete_items(index, "dns_policy")
    matched = []
    for policy in policies:
        networks = list_of_objects(optional(policy, "networks", [], list))
        if any(get(network, "networkUrl", str) == network_url for network in networks):
            matched.append(policy)
    if len(matched) > 1:
        return unknown("ambiguous DNS policy attachment")
    return result(not matched or not optional(matched[0], "enableLogging", False, bool),
        network_reference=network_url, semantics="Exact project-qualified network reference; policy declaration, not runtime DNS events")


cid = rule("compute_network_dns_logging_scoped", "network", dns_network_logging,
    {"selfLink": "https://www.googleapis.com/compute/v1/projects/p/global/networks/v"},
    {"selfLink": "https://www.googleapis.com/compute/v1/projects/q/global/networks/v"}, ["network", "dns_policy"])
CASES[cid]["index"] = {"collections": {"dns_policy": [{"status": "collected"}]}, "dns_policy": [{"data": {"enableLogging": True, "networks": [{"networkUrl": "https://www.googleapis.com/compute/v1/projects/p/global/networks/v"}]}}]}
