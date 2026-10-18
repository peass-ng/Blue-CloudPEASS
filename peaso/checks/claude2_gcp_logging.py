"""claude2_gcp: CIS Cloud Logging metric-filter/alert (2.4-2.11) and all-entries sink (2.2) predicates.

False-positive controls:
  * Metric filters are matched *semantically*: each filter is evaluated with the Logging query language
    (OR binds tighter than AND, NOT tightest, implicit AND, ``:`` substring, repeated-field any-match) against
    synthetic Admin Activity entries for every change the CIS filter captures. Equivalent rewrites, extra
    whitespace, reordered terms or broader filters therefore match; a regex over the CIS text is not used.
  * A metric only counts when an *enabled* alert policy uses it in a threshold condition and the alert has at
    least one *enabled* notification channel (channel inventory is required; missing -> UNKNOWN).
  * FAIL requires proof that nothing outside the collected project could satisfy the control: the project has
    no folder/organization ancestors (or their sinks are collected and route nothing to a log bucket), no
    project sink routes to another project's log bucket, and, when a local metric exists, the Monitoring
    metrics scope is collected and contains only the project itself. Otherwise the result is MANUAL.
"""
from __future__ import annotations
import re

from .claude2_gcp_common import (gcp, cid, cases, scope_index, strings, project_ids, in_project, result, get, optional,
                                 list_of_objects, complete_items, Unavailable, CASES)
from .claude2_gcp_logfilter import verdict, audit_event

LOGGING_IDS = []
CHANNEL_KIND = "monitoring_notification_channel"
CRM = "cloudresourcemanager.googleapis.com"


def _versions(project, resource_type, collection, methods):
    return [audit_event(project, "compute.googleapis.com", f"{version}.compute.{collection}.{method}", resource_type)
            for version in ("v1", "beta") for method in methods]


def _owner_delta(action):
    return {"serviceData": {"@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
                            "policyDelta": {"bindingDeltas": [{"action": action, "role": "roles/owner",
                                                               "member": "user:new-owner@example.com"}]}}}


EVENTS = {
    "project_ownership_changes": lambda p: [
        audit_event(p, CRM, "SetIamPolicy", "project", **_owner_delta("ADD")),
        audit_event(p, CRM, "SetIamPolicy", "project", **_owner_delta("REMOVE")),
        audit_event(p, CRM, "InsertProjectOwnershipInvite", "project")],
    "audit_configuration_changes": lambda p: [
        audit_event(p, CRM, "SetIamPolicy", "project", serviceData={
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {"auditConfigDeltas": [{"action": "REMOVE", "service": "allServices", "logType": "DATA_READ"}]}})],
    "custom_role_changes": lambda p: [
        audit_event(p, "iam.googleapis.com", "google.iam.admin.v1." + m, "iam_role") for m in ("CreateRole", "DeleteRole", "UpdateRole")],
    "custom_role_changes_with_undelete": lambda p: [
        audit_event(p, "iam.googleapis.com", "google.iam.admin.v1." + m, "iam_role")
        for m in ("CreateRole", "DeleteRole", "UpdateRole", "UndeleteRole")],
    "firewall_rule_changes": lambda p: _versions(p, "gce_firewall_rule", "firewalls", ("patch", "insert", "delete")),
    "route_changes": lambda p: _versions(p, "gce_route", "routes", ("delete", "insert")),
    "network_changes": lambda p: _versions(p, "gce_network", "networks", ("insert", "patch", "delete", "removePeering", "addPeering")),
    "bucket_iam_changes": lambda p: [audit_event(p, "storage.googleapis.com", "storage.setIamPermissions", "gcs_bucket")],
    "sql_instance_configuration_changes": lambda p: [
        audit_event(p, "cloudsql.googleapis.com", "cloudsql.instances.update", "cloudsql_database")],
}
CIS_FILTERS = {
    "project_ownership_changes": '(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")',
    "audit_configuration_changes": 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*',
    "custom_role_changes": 'resource.type="iam_role" AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole")',
    "custom_role_changes_with_undelete": 'resource.type="iam_role" AND (protoPayload.methodName = "google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole" OR protoPayload.methodName="google.iam.admin.v1.UndeleteRole")',
    "firewall_rule_changes": 'resource.type="gce_firewall_rule" AND (protoPayload.methodName:"compute.firewalls.patch" OR protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.delete")',
    "route_changes": 'resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")',
    "network_changes": 'resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")',
    "bucket_iam_changes": 'resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"',
    "sql_instance_configuration_changes": 'protoPayload.methodName="cloudsql.instances.update"',
}
TITLES = {
    "project_ownership_changes": "project ownership assignments/changes",
    "audit_configuration_changes": "audit configuration changes",
    "custom_role_changes": "custom role changes (create, delete, update)",
    "custom_role_changes_with_undelete": "custom role changes (create, delete, update, undelete)",
    "firewall_rule_changes": "VPC network firewall rule changes",
    "route_changes": "VPC network route changes",
    "network_changes": "VPC network changes",
    "bucket_iam_changes": "Cloud Storage IAM permission changes",
    "sql_instance_configuration_changes": "SQL instance configuration changes",
}
METRIC_IDS = {}


# --- Project-boundary proofs --------------------------------------------------------------------------------------

def active_project(project):
    state = optional(project, "state", None, str)
    if state is not None and state != "ACTIVE":
        return "NOT_APPLICABLE", {"reason": "Project is not ACTIVE", "state": state}
    return None


def ancestors(project):
    """Folder/organization ancestors, ``None`` when unknown. Raises when nothing establishes the hierarchy."""
    if "_ancestry" not in project:
        parent = optional(project, "parent", None, str)
        if parent and parent.startswith(("folders/", "organizations/")):
            return [parent], "parent"
        raise Unavailable("project ancestry (getAncestry) not collected")
    out = []
    for row in list_of_objects(get(project, "_ancestry", list)):
        resource = get(row, "resourceId", dict)
        kind, identifier = get(resource, "type", str), str(get(resource, "id", (str, int)))
        if kind in ("folder", "organization"):
            out.append(kind + "s/" + identifier)
    return out, "getAncestry"


def _active(sink):
    return not optional(sink, "disabled", False, bool)


def _active_exclusions(sink):
    return [x for x in list_of_objects(optional(sink, "exclusions", [], list)) if not optional(x, "disabled", False, bool)]


def inherited_sinks(project):
    """Collected ancestor sinks (future ``_inherited_sinks`` fact) or ``None`` when not collected."""
    if "_inherited_sinks" not in project:
        return None
    sinks = list_of_objects(get(project, "_inherited_sinks", list))
    for sink in sinks:
        get(sink, "destination", str)
    return sinks


def inheritance_gate(project, *, logging_destinations_only):
    """None when no uncollected ancestor configuration can matter, else a MANUAL result tuple."""
    parents, source = ancestors(project)
    if not parents:
        return None
    sinks = inherited_sinks(project)
    if sinks is None:
        return "MANUAL", {"reason": "Project has folder/organization ancestors whose aggregated sinks were not collected",
                          "ancestors": parents, "ancestry_source": source}
    relevant = [s.get("name") for s in sinks if _active(s) and optional(s, "includeChildren", False, bool)
                and (not logging_destinations_only or get(s, "destination", str).startswith("logging.googleapis.com/"))]
    if relevant:
        return "MANUAL", {"reason": "An ancestor aggregated sink routes this project's entries elsewhere; review its "
                                    "destination for the control", "ancestor_sinks": relevant}
    return None


def cross_project_sinks(project, index):
    ids = project_ids(project)
    out = []
    for sink in complete_items(index, "log_sink"):
        if not in_project(get(sink, "name", str), ids) or not _active(sink):
            continue
        destination = get(sink, "destination", str)
        match = re.match(r"logging\.googleapis\.com/projects/([^/]+)/", destination)
        if match and match.group(1) not in ids:
            out.append({"sink": sink["name"], "destination": destination})
    return out


def metrics_scope_local(project):
    """True only when the (future) ``_monitoring_metrics_scopes`` fact proves no other scoping project."""
    if "_monitoring_metrics_scopes" not in project:
        return False
    scopes = strings(get(project, "_monitoring_metrics_scopes", list), "metrics scopes")
    ids = project_ids(project)
    return all(scope.rsplit("/", 1)[-1] in ids for scope in scopes)


# --- Metric and alert matching ---------------------------------------------------------------------------------

def metric_type(metric):
    descriptor = optional(metric, "metricDescriptor", None, dict)
    if descriptor is not None and "type" in descriptor:
        return get(descriptor, "type", str)
    metric_id = optional(metric, "metricId", None, str) or get(metric, "name", str).rsplit("/metrics/", 1)[-1]
    return "logging.googleapis.com/user/" + metric_id


def threshold_link(text, mtype):
    """'exact' for a metric.type restriction on ``mtype``, 'uncertain' for another reference, else None."""
    if re.search(r'metric\.type\s*=\s*"?' + re.escape(mtype) + r'(?=["\s)]|$)', text):
        return "exact"
    short = mtype.rsplit("/", 1)[-1]
    return "uncertain" if short and (mtype in text or "user/" + short in text or "user_" + short in text) else None


def alert_links(alert, mtype):
    links = []
    conditions = list_of_objects(get(alert, "conditions", list))
    for condition in conditions:
        threshold = optional(condition, "conditionThreshold", None, dict)
        if threshold is not None:
            link = threshold_link(get(threshold, "filter", str), mtype)
            if link:
                links.append(link)
        for key in ("conditionMonitoringQueryLanguage", "conditionPrometheusQueryLanguage", "conditionSql"):
            body = optional(condition, key, None, dict)
            if body is not None and threshold_link(str(body.get("query", body)), mtype):
                links.append("uncertain")
    combiner = optional(alert, "combiner", "OR", str)
    if "exact" in links and len(conditions) > 1 and combiner != "OR":
        links = ["uncertain"]
    return "exact" if "exact" in links else "uncertain" if links else None


def matched_log_conditions(alert, events):
    found = []
    for condition in list_of_objects(get(alert, "conditions", list)):
        body = optional(condition, "conditionMatchedLog", None, dict)
        if body is not None and verdict(get(body, "filter", str), events)[0] != "none":
            found.append(optional(condition, "displayName", "", str))
    return found


def channel_state(alert, index):
    """('enabled'|'none'|'pending', evidence) for the alert's notification channels."""
    names = strings(optional(alert, "notificationChannels", [], list), "notification channels")
    if not names:
        return "none", {"notification_channels": []}
    try:
        inventory = {get(c, "name", str): c for c in complete_items(index, CHANNEL_KIND)}
    except Unavailable:
        return "pending", {"notification_channels": names, "channel_inventory": "not collected"}
    enabled, unresolved = [], []
    for name in names:
        if name not in inventory:
            continue
        channel = inventory[name]
        # NotificationChannel.enabled is an optional BoolValue. The list read
        # uses a fields projection, and absence does not attest enabled=true.
        try:
            if get(channel, "enabled", bool):
                enabled.append(name)
        except Unavailable:
            # A sibling's unreadable field cannot erase an independently
            # verified enabled channel, but cannot itself prove delivery.
            unresolved.append(name)
    state = "enabled" if enabled else "pending" if unresolved else "none"
    return state, {"notification_channels": names, "enabled_channels": enabled,
                   "unresolved_channels": unresolved}


def metric_alert(name):
    slug = "logging.metric_alert_" + name

    @gcp(slug, "project", "Log metric filter and notifying alert exist for " + TITLES[name], control="AU-6", category="hardening",
         dependencies=["project", "logging_metric", "monitoring_alert_policy", CHANNEL_KIND, "log_sink"],
         remediation="Create a log-based metric whose filter captures every change in the CIS reference filter, and an enabled "
                     "Cloud Monitoring alert policy with a threshold condition on that metric and at least one enabled "
                     "notification channel.")
    def evaluate(project, index):
        inactive = active_project(project)
        if inactive:
            return inactive
        ids = project_ids(project)
        events = EVENTS[name](get(project, "projectId", str))
        metrics = [m for m in complete_items(index, "logging_metric") if in_project(get(m, "name", str), ids)]
        alerts = [a for a in complete_items(index, "monitoring_alert_policy") if in_project(get(a, "name", str), ids)]
        candidates = []
        for metric in metrics:
            if optional(metric, "disabled", False, bool):
                continue
            match, _ = verdict(get(metric, "filter", str), events)
            if optional(metric, "bucketName", "", str) and match == "full":
                match = "partial"  # bucket-scoped metrics only count entries routed to that bucket
            if match != "none":
                candidates.append((metric["name"], metric_type(metric), match))
        chains, pending, uncertain, unnotified = [], [], [], []
        for metric_name, mtype, match in candidates:
            for alert in alerts:
                link = alert_links(alert, mtype)
                if link is None:
                    continue
                enabled = optional(alert, "enabled", None, bool)
                if enabled is False:
                    unnotified.append({"metric": metric_name, "alert": alert["name"], "issue": "alert disabled"})
                    continue
                state, channels = channel_state(alert, index)
                row = {"metric": metric_name, "metric_type": mtype, "filter_match": match, "alert": alert["name"],
                       "link": link, **channels}
                if state == "none":
                    unnotified.append({**row, "issue": "no enabled notification channel"})
                elif state == "pending":
                    pending.append(row)
                elif match == "full" and link == "exact" and enabled is True:
                    chains.append(row)
                else:
                    uncertain.append(row)
        for alert in alerts:
            if optional(alert, "enabled", None, bool) is not False and matched_log_conditions(alert, events):
                state, channels = channel_state(alert, index)
                if state != "none":
                    uncertain.append({"alert": alert["name"], "issue": "log-match alert instead of a log-based metric", **channels})
        evidence = {"matching_metrics": [{"metric": n, "metric_type": t, "filter_match": m} for n, t, m in candidates],
                    "alert_chains": chains, "unnotified": unnotified,
                    "semantics": "Semantic Logging-query evaluation of same-project metrics against synthetic audit entries"}
        if chains:
            return result(False, **evidence)
        if pending:
            return "UNKNOWN", {**evidence, "pending_channel_checks": pending,
                               "reason": "Notification channel inventory not collected; channel enablement cannot be verified"}
        if uncertain:
            return "MANUAL", {**evidence, "uncertain": uncertain,
                              "reason": "A metric or alert may satisfy the control but could not be proven equivalent"}
        gate = inheritance_gate(project, logging_destinations_only=True)
        if gate:
            return gate[0], {**evidence, **gate[1]}
        elsewhere = cross_project_sinks(project, index)
        if elsewhere:
            return "MANUAL", {**evidence, "cross_project_sinks": elsewhere,
                              "reason": "Project sinks route entries to another project's log bucket, whose metrics were not joined"}
        if candidates and not metrics_scope_local(project):
            return "MANUAL", {**evidence, "reason": "A matching metric exists; alert policies in a Monitoring metrics-scope host "
                                                    "project were not collected"}
        return result(True, **evidence)

    check_id = cid(slug)
    LOGGING_IDS.append(check_id)
    METRIC_IDS[name] = check_id
    _fixtures(check_id, name)
    return check_id


def _fixtures(check_id, name):
    project = {"name": "projects/123", "projectId": "p", "state": "ACTIVE", "_ancestry": [{"resourceId": {"type": "project", "id": "p"}}]}
    metric = {"name": "projects/p/metrics/m", "metricId": "m", "filter": CIS_FILTERS[name],
              "metricDescriptor": {"type": "logging.googleapis.com/user/m"}}
    alert = {"name": "projects/p/alertPolicies/a", "enabled": True, "combiner": "OR",
             "notificationChannels": ["projects/p/notificationChannels/1"],
             "conditions": [{"conditionThreshold": {"filter": 'resource.type="global" AND metric.type="logging.googleapis.com/user/m"'}}]}
    channel = {"name": "projects/p/notificationChannels/1", "type": "email", "enabled": True}
    sink = {"name": "projects/p/sinks/_Required", "destination": "logging.googleapis.com/projects/p/locations/global/buckets/_Required"}
    base = {"logging_metric": [metric], "monitoring_alert_policy": [alert], CHANNEL_KIND: [channel], "log_sink": [sink]}
    nothing = {"logging_metric": [], "monitoring_alert_policy": [], CHANNEL_KIND: [], "log_sink": [sink]}
    cases(check_id, project, project, pass_index=scope_index(base), fail_index=scope_index(nothing),
          manual={**project, "_ancestry": [{"resourceId": {"type": "project", "id": "p"}}, {"resourceId": {"type": "organization", "id": "9"}}]},
          manual_index=scope_index(nothing),
          unknown=project, unknown_index=scope_index({k: v for k, v in base.items() if k != CHANNEL_KIND}),
          not_applicable={**project, "state": "DELETE_REQUESTED"}, not_applicable_index=scope_index(base),
          malformed={**project, "projectId": 1})


for _name in EVENTS:
    metric_alert(_name)


# --- CIS 2.2: sink for all log entries -------------------------------------------------------------------------

def all_entries(sink):
    return (_active(sink) and not optional(sink, "filter", "", str).strip() and bool(get(sink, "destination", str))
            and not _active_exclusions(sink))


@gcp("logging.sink_all_log_entries", "project", "A log sink exports all log entries of the project", control="AU-9",
     category="hardening", dependencies=["project", "log_sink"],
     remediation="Create an enabled sink with an empty filter and no active exclusions, preferably an organization-level "
                 "aggregated sink with includeChildren, exporting to a protected destination.")
def sink_all_log_entries(project, index):
    inactive = active_project(project)
    if inactive:
        return inactive
    ids = project_ids(project)
    local = [s for s in complete_items(index, "log_sink") if in_project(get(s, "name", str), ids)]
    matches = [s["name"] for s in local if all_entries(s)]
    if matches:
        return result(False, sinks=matches, source="project")
    excluded = [s["name"] for s in local if _active(s) and not optional(s, "filter", "", str).strip() and _active_exclusions(s)]
    parents, source = ancestors(project)
    if parents:
        inherited = inherited_sinks(project)
        if inherited is None:
            return "MANUAL", {"reason": "No same-project all-entries sink; folder/organization aggregated sinks were not collected",
                              "ancestors": parents, "ancestry_source": source}
        aggregated = [s.get("name") for s in inherited if optional(s, "includeChildren", False, bool) and all_entries(s)]
        if aggregated:
            return result(False, sinks=aggregated, source="ancestor aggregated sink")
        excluded += [s.get("name") for s in inherited if optional(s, "includeChildren", False, bool) and _active(s)
                     and not optional(s, "filter", "", str).strip()]
    if excluded:
        return "MANUAL", {"reason": "An empty-filter sink has active exclusions; review whether the exclusions drop security entries",
                          "sinks": excluded}
    return result(True, sinks=[s["name"] for s in local], ancestors=parents)


_SINK = cid("logging.sink_all_log_entries")
LOGGING_IDS.append(_SINK)
_PROJECT = {"name": "projects/123", "projectId": "p", "_ancestry": [{"resourceId": {"type": "project", "id": "p"}}]}
_REQUIRED = {"name": "projects/p/sinks/_Default", "filter": 'NOT LOG_ID("cloudaudit.googleapis.com/activity")',
             "destination": "logging.googleapis.com/projects/p/locations/global/buckets/_Default"}
cases(_SINK, _PROJECT, _PROJECT,
      pass_index=scope_index({"log_sink": [_REQUIRED, {"name": "projects/p/sinks/all", "destination": "storage.googleapis.com/archive"}]}),
      fail_index=scope_index({"log_sink": [_REQUIRED]}),
      manual={**_PROJECT, "_ancestry": [{"resourceId": {"type": "folder", "id": "5"}}]}, manual_index=scope_index({"log_sink": [_REQUIRED]}),
      unknown={"name": "projects/123", "projectId": "p"}, unknown_index=scope_index({"log_sink": [_REQUIRED]}),
      malformed={**_PROJECT, "projectId": 1})
