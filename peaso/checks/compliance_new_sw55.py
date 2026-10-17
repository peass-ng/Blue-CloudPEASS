"""Signed GCP compliance predicates over complete, scope-bound snapshot facts."""
from __future__ import annotations

from dataclasses import replace
from collections import Counter
from datetime import datetime, timezone
import json
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard

SPECS = {
    "gcp.bigquery.table_classification_tags": ("bigquery_table", "hardening", "medium", "BigQuery table columns carry approved classification tags", "d57612c4e2fa6b368382a6651f0730b0be95137145cd8b38aba7144ffe08fe9e"),
    "gcp.network.vpc_service_controls_supported_services": ("service_perimeter", "network", "high", "VPC Service Controls cover every approved supported service", "5cbcb911696eb2a0dbf6138bb75079f7fe2f65ddaf0c9bee3636a21675755095"),
    "gcp.resourcemanager.folder_environment_structure": ("folder", "hardening", "medium", "Folders separate projects by environment and sensitivity", "6a1ac2b8164694d49ad02c19f4734881ee13849baf3e8ad0b33ed9d680086061"),
    "gcp_c5_access_approval": ("access_approval_settings", "identity", "medium", "Customer consent before provider access", "941fa5534735309073b50a08f0001b8728c0a54cd1e896c866affb70d0bb13a5"),
    "gcp_logging_scc_findings_alert": ("organization", "monitoring", "high", "High severity SCC findings lack an alert route", "c7b21dcae287922260517dfbff0a3a241eb2d188761dfbfe4481a5e79b057f11"),
}


def _signed(check_id, *dependencies):
    kind, category, severity, title, _ = SPECS[check_id]
    def decorate(function):
        register(check_id, "gcp", category if category in {"hardening", "network"} else "hardening",
                 kind, title, severity, "CM-6", "Review the approved policy and correct the recorded GCP configuration.",
                 dependencies=list(dependencies))(function)
        if category not in {"hardening", "network"}:
            CHECKS[-1] = replace(CHECKS[-1], category=category)
        return function
    return decorate


def _scope(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "gcp":
        raise Unavailable("foreign provider")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"(?:projects|folders|organizations)/[A-Za-z0-9][A-Za-z0-9._:-]*", scope):
        raise Unavailable("invalid GCP scope")
    return scope


def _inventory(index, kind, scope):
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable(kind + " inventory unavailable")
    env = envelopes[0]
    if get(env, "type", str) != kind or get(env, "scope", str) != scope or get(env, "status", str) not in ("collected", "empty"):
        raise Unavailable(kind + " inventory incomplete or foreign scope")
    if env.get("coverage_status", "collected") not in ("collected", "empty"):
        raise Unavailable(kind + " coverage incomplete")
    rows = complete_items(index, kind)
    items = get(env, "items", list)
    if len(items) != len(rows) or (env["status"] == "empty") != (len(rows) == 0):
        raise Unavailable(kind + " inventory count mismatch")
    wrappers = get(index, kind, list)
    if len(wrappers) != len(rows):
        raise Unavailable(kind + " wrapper count mismatch")
    for wrapper in wrappers:
        if (get(wrapper, "type", str) != kind or get(wrapper, "scope", str) != scope or
                wrapper.get("provider", "gcp") != "gcp" or get(wrapper, "data", dict) not in items):
            raise Unavailable(kind + " wrapper foreign or inconsistent")
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    if Counter(map(encode, items)) != Counter(map(encode, rows)):
        raise Unavailable(kind + " envelope and resource rows disagree")
    for row in rows:
        guard(row)
        provenance = row.get("_provenance")
        if isinstance(provenance, dict) and "scope" in provenance and provenance["scope"] != scope:
            raise Unavailable(kind + " native provenance foreign scope")
    return rows


def _anchor(item, rows):
    if sum(row == item for row in rows) != 1:
        raise Unavailable("anchor absent or duplicate")


def _policy(index, scope):
    policy = get(get(get(index, "context", dict), "metadata", dict), "sw55_policy", dict)
    if get(policy, "scope", str) != scope or get(policy, "status", str) != "collected":
        raise Unavailable("approved policy absent or foreign scope")
    return policy


def _strings(value, *, nonempty=False):
    if not isinstance(value, list) or (nonempty and not value) or any(not isinstance(x, str) or not x for x in value) or len(set(value)) != len(value):
        raise Unavailable("invalid approved string list")
    return set(value)


def _time(value):
    if not isinstance(value, str) or not value:
        raise Unavailable("invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise Unavailable("timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


@_signed("gcp.bigquery.table_classification_tags", "bigquery_table")
def table_classification(item, index):
    scope = _scope(index)
    if not scope.startswith("projects/"):
        raise Unavailable("table requires project scope")
    rows = _inventory(index, "bigquery_table", scope)
    _anchor(item, rows)
    policy = _policy(index, scope)
    required = get(policy, "required_classification", dict)
    table_ref = get(item, "tableReference", dict)
    table_key = ".".join((get(table_ref, "projectId", str), get(table_ref, "datasetId", str), get(table_ref, "tableId", str)))
    if table_ref["projectId"] != scope.split("/", 1)[1] or not all(table_ref.values()):
        raise Unavailable("foreign table reference")
    if not required:
        raise Unavailable("classification inventory empty")
    for table, columns in required.items():
        if not isinstance(table, str) or not isinstance(columns, dict) or not columns:
            raise Unavailable("malformed classification inventory")
        for path, tags in columns.items():
            if not isinstance(path, str) or not path or any(not part for part in path.split(".")):
                raise Unavailable("malformed column path")
            _strings(tags, nonempty=True)
    if table_key not in required:
        return unknown("table absent from required classification inventory; unlisted columns are unproven", table=table_key)
    if get(item, "_provenance", dict).get("schema_full") is not True:
        raise Unavailable("complete tables.get schema unavailable")
    fields = get(get(item, "schema", dict), "fields", list)
    observed = {}
    def walk(nodes, prefix=""):
        for field in nodes:
            name = get(field, "name", str)
            if not name or "." in name or prefix + name in observed:
                raise Unavailable("malformed or duplicate schema field")
            path = prefix + name
            tags = field.get("policyTags")
            if tags is None:
                if "policyTags" in field.get("_coverage", {}):
                    get(field, "policyTags", dict)
                names = []
            else:
                names = get(get(field, "policyTags", dict), "names", list)
            observed[path] = _strings(names)
            if "fields" in field:
                walk(get(field, "fields", list), path + ".")
    walk(fields)
    missing = [path for path in required[table_key] if path not in observed]
    if missing:
        return unknown("required column absent from complete table schema", columns=sorted(missing))
    bad = sorted(path for path, approved in required[table_key].items() if not observed[path].intersection(approved))
    return result(bool(bad), table=table_key, unclassified_columns=bad, checked_columns=sorted(required[table_key]))


@_signed("gcp.resourcemanager.folder_environment_structure", "folder", "project")
def folder_structure(item, index):
    scope = _scope(index)
    folders = _inventory(index, "folder", scope)
    _anchor(item, folders)
    projects = _inventory(index, "project", scope)
    policy = _policy(index, scope)
    environments = _strings(get(policy, "environment_labels", list), nonempty=True)
    sensitivities = _strings(get(policy, "sensitivity_labels", list), nonempty=True)
    by_name = {}
    for folder in folders:
        name = get(folder, "name", str)
        if not re.fullmatch(r"folders/[0-9]+", name) or name in by_name:
            raise Unavailable("invalid or duplicate folder")
        get(folder, "displayName", str)
        get(folder, "parent", str)
        by_name[name] = folder
    if not projects:
        return "NOT_APPLICABLE", {"reason": "complete scope has no projects"}
    bad = []
    seen_projects = set()
    for project in projects:
        name = get(project, "name", str)
        if not name.startswith("projects/") or name in seen_projects:
            raise Unavailable("invalid or duplicate project")
        seen_projects.add(name)
        parent = get(project, "parent", str)
        labels, visited = set(), set()
        while parent.startswith("folders/"):
            if parent in visited or parent not in by_name:
                raise Unavailable("folder parent chain incomplete or cyclic")
            visited.add(parent)
            folder = by_name[parent]
            labels.add(get(folder, "displayName", str))
            parent = get(folder, "parent", str)
        if parent != scope and not (scope.startswith("folders/") and scope in visited and re.fullmatch(r"organizations/[0-9]+", parent)):
            raise Unavailable("project parent chain outside audited scope")
        if not labels.intersection(environments) or not labels.intersection(sensitivities):
            bad.append(name)
    return result(bool(bad), projects_missing_labels=sorted(bad), checked_projects=sorted(seen_projects))


@_signed("gcp.network.vpc_service_controls_supported_services", "service_perimeter", "service_usage")
def vpc_supported_services(item, index):
    scope = _scope(index)
    if not scope.startswith("projects/"):
        raise Unavailable("perimeter requires project scope")
    perimeters = _inventory(index, "service_perimeter", scope)
    _anchor(item, perimeters)
    services = _inventory(index, "service_usage", scope)
    policy = _policy(index, scope)
    protected = _strings(get(policy, "protected_project_numbers", list), nonempty=True)
    supported = _strings(get(policy, "supported_services", list), nonempty=True)
    if any(not re.fullmatch(r"[0-9]+", number) for number in protected):
        raise Unavailable("invalid protected project number")
    if get(policy, "project_number", str) not in protected:
        raise Unavailable("current project not in protected inventory")
    if get(policy, "project_id", str) != scope.split("/", 1)[1]:
        raise Unavailable("policy project identity mismatch")
    enabled = set()
    names = set()
    for service in services:
        name = get(service, "name", str)
        if not name.startswith(scope + "/services/") or name in names:
            raise Unavailable("invalid or duplicate service")
        names.add(name)
        state = get(service, "state", str)
        if state not in {"ENABLED", "DISABLED"}:
            raise Unavailable("unrecognized service state")
        if state == "ENABLED":
            enabled.add(name.split("/services/", 1)[1])
    covered, restricted, perimeter_names = set(), set(), set()
    for perimeter in perimeters:
        perimeter_name = get(perimeter, "name", str)
        if not re.fullmatch(r"accessPolicies/[0-9]+/servicePerimeters/[A-Za-z0-9_-]+", perimeter_name) or perimeter_name in perimeter_names:
            raise Unavailable("invalid or duplicate service perimeter")
        perimeter_names.add(perimeter_name)
        if get(perimeter, "_representation", str) != "full":
            raise Unavailable("partial perimeter representation")
        status = get(perimeter, "status", dict)
        resources = _strings(get(status, "resources", list))
        restricted_services = _strings(get(status, "restrictedServices", list))
        if any(not re.fullmatch(r"projects/[0-9]+", r) for r in resources):
            raise Unavailable("malformed perimeter resources")
        included = {r.split("/", 1)[1] for r in resources} & protected
        covered.update(included)
        if get(policy, "project_number", str) in included:
            restricted.update(restricted_services)
    missing_projects = sorted(protected - covered)
    missing_services = sorted((enabled & supported) - restricted)
    return result(bool(missing_projects or missing_services), missing_project_numbers=missing_projects,
                  missing_enabled_supported_services=missing_services)


@_signed("gcp_c5_access_approval", "access_approval_settings", "access_approval_request", "provider_access_event")
def prior_customer_consent(item, index):
    scope = _scope(index)
    settings = _inventory(index, "access_approval_settings", scope)
    _anchor(item, settings)
    if get(item, "name", str) != scope + "/accessApprovalSettings":
        raise Unavailable("settings identity mismatch")
    requests = _inventory(index, "access_approval_request", scope)
    events = _inventory(index, "provider_access_event", scope)
    policy = _policy(index, scope)
    consent = get(policy, "consent_scopes", list)
    if not consent or any(not isinstance(row, dict) for row in consent):
        raise Unavailable("approved customer consent scope unavailable")
    consent_pairs = {(get(row, "serviceName", str), get(row, "resourceName", str)) for row in consent}
    if len(consent_pairs) != len(consent):
        raise Unavailable("duplicate consent scope")
    coverage = get(policy, "log_coverage", dict)
    if get(coverage, "status", str) != "collected":
        raise Unavailable("provider access log coverage incomplete")
    start, end = _time(get(coverage, "start", str)), _time(get(coverage, "end", str))
    if start >= end:
        raise Unavailable("invalid log coverage window")
    approvals, request_names = [], set()
    for request in requests:
        name = get(request, "name", str)
        if not name.startswith(scope + "/approvalRequests/") or name in request_names:
            raise Unavailable("foreign or duplicate approval request")
        request_names.add(name)
        requested_resource = get(request, "requestedResourceName", str)
        match = re.fullmatch(r"//([a-z0-9.-]+)/(.*)", requested_resource)
        if not match or not match.group(2):
            raise Unavailable("approval resource/service scope cannot be resolved")
        pair = (match.group(1), match.group(2))
        decision = request.get("approve")
        full = (request.get("_representation") == "full" or
                isinstance(request.get("_provenance"), dict) and request['_provenance'].get('representation') == 'full')
        if decision is None and full:
            decision_at = None
        elif isinstance(decision, dict):
            decision_at = _time(get(decision, "decisionTime" if 'decisionTime' in decision else 'approveTime', str))
            if decision.get('autoApproved') is True and decision.get('policyApproved') is not True:
                raise Unavailable('automatic approval has no verified customer policy approval')
        else:
            raise Unavailable("approval decision unavailable")
        expiration = _time(get(request, "requestedExpiration", str))
        requested_at = _time(get(request, "requestTime", str))
        if requested_at >= expiration or decision_at is not None and not requested_at <= decision_at < expiration:
            raise Unavailable("approval chronology inconsistent")
        if isinstance(decision, dict) and 'expireTime' in decision:
            expiration = _time(get(decision, 'expireTime', str))
        if isinstance(decision, dict) and 'invalidateTime' in decision:
            expiration = min(expiration, _time(get(decision, 'invalidateTime', str)))
        if decision_at is not None and decision_at >= expiration:
            raise Unavailable('approval effective expiration is inconsistent')
        approvals.append((pair, decision_at, expiration, name))
    violations, checked, event_names = [], [], set()
    for event in events:
        event_id = get(event, "name", str)
        if event_id in event_names:
            raise Unavailable("duplicate provider access event")
        event_names.add(event_id)
        if get(event, "provider_access", bool) is not True:
            raise Unavailable("event provider access classification unverified")
        get(event, "principal", str)
        pair = (get(event, "serviceName", str), get(event, "resourceName", str))
        if scope.startswith("projects/") and pair[1] != scope and not pair[1].startswith(scope + "/"):
            raise Unavailable("provider access event foreign project")
        at = _time(get(event, "timestamp", str))
        if not start <= at < end:
            raise Unavailable("event outside proven log window")
        if pair not in consent_pairs:
            continue
        checked.append(event_id)
        references = event.get('approvalRequests')
        if references is not None and (not isinstance(references, list) or
                any(not isinstance(ref, str) for ref in references)):
            raise Unavailable('provider event approval references malformed')
        if not any(p == pair and decision is not None and decision <= at < expiry and
                   (references is None or name in references) for p, decision, expiry, name in approvals):
            violations.append(event_id)
    if not checked:
        return "NOT_APPLICABLE", {"reason": "no proven in-scope provider access events requiring consent"}
    return result(bool(violations), unapproved_access_events=sorted(violations), checked_events=sorted(checked))


_FILTER_TERM = re.compile(r'(?:finding\.)?(state|severity)\s*=\s*"(ACTIVE|INACTIVE|HIGH|CRITICAL|MEDIUM|LOW|UNSPECIFIED)"')


def _matches_filter(expression, finding):
    if not isinstance(expression, str):
        return None
    if not expression.strip():
        return True
    # Deliberately narrow: arbitrary SCC filter expressions cannot be safely inferred.
    # SCC's filter language gives OR higher precedence than AND (unlike SQL).
    parts = re.split(r"\s+AND\s+", expression)
    values = []
    for part in parts:
        terms = re.split(r"\s+OR\s+", part)
        parsed = [_FILTER_TERM.fullmatch(term.strip()) for term in terms]
        if any(term is None for term in parsed):
            return None
        values.append(any(finding[term.group(1)] == term.group(2) for term in parsed))
    return all(values)


@_signed("gcp_logging_scc_findings_alert", "organization", "scc_finding", "scc_notification_config")
def scc_finding_route(item, index):
    scope = _scope(index)
    if not scope.startswith("organizations/"):
        raise Unavailable("SCC route requires organization scope")
    organizations = _inventory(index, "organization", scope)
    _anchor(item, organizations)
    if get(item, "name", str) != scope:
        raise Unavailable("organization identity mismatch")
    findings = _inventory(index, "scc_finding", scope)
    configs = _inventory(index, "scc_notification_config", scope)
    policy = _policy(index, scope)
    topics = _strings(get(policy, "approved_on_call_topics", list), nonempty=True)
    approved, config_names = [], set()
    for config in configs:
        name = get(config, "name", str)
        if not name.startswith(scope + "/notificationConfigs/") or name in config_names:
            raise Unavailable("foreign or duplicate SCC notification config")
        config_names.add(name)
        expression = get(config, "filter", str)
        if get(config, "pubsubTopic", str) in topics:
            approved.append((name, expression))
    unsafe, uncertain, checked, finding_names = [], [], [], set()
    for finding in findings:
        name = get(finding, "name", str)
        if not name.startswith(scope + "/sources/") or name in finding_names:
            raise Unavailable("foreign or duplicate SCC finding")
        finding_names.add(name)
        state = get(finding, "state", str)
        severity = get(finding, "severity", str)
        _time(get(finding, "createTime", str))
        if state not in {"ACTIVE", "INACTIVE"} or severity not in {"HIGH", "CRITICAL", "MEDIUM", "LOW", "UNSPECIFIED"}:
            raise Unavailable("unrecognized finding state or severity")
        if state != "ACTIVE" or severity not in {"HIGH", "CRITICAL"}:
            continue
        checked.append(name)
        matches = [_matches_filter(expression, finding) for _, expression in approved]
        if True in matches:
            continue
        if None in matches:
            uncertain.append(name)
        else:
            unsafe.append(name)
    if unsafe:
        return result(True, findings_without_route=sorted(unsafe), checked_findings=sorted(checked))
    if uncertain:
        return unknown("approved route filter cannot be evaluated", uncertain_findings=sorted(uncertain))
    if not checked:
        return "NOT_APPLICABLE", {"reason": "no active HIGH or CRITICAL finding in complete inventory"}
    return result(False, checked_findings=sorted(checked))
