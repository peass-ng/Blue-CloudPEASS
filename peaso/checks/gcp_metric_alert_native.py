"""Bounded native log-metric/alert association; no event or delivery claims.

Only the complete reference Logging expression is admitted (modulo grouping,
ordering, whitespace and quoted bare values). Other expressions stay UNKNOWN.
Monitoring threshold/absence selectors are parsed separately from MQL.
"""
from __future__ import annotations

import json
import re

from . import result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, optional

_TOKEN = re.compile(r'\s*("(?:[^"\\]|\\.)*"|[():=]|[A-Za-z0-9_.*+/,%!\'-]+)')


def _expression(text, *, monitoring=False):
    """Small positive Logging grammar, with documented OR-before-AND precedence."""
    if not isinstance(text, str) or not text.strip() or len(text) > 20000:
        raise Unavailable("filter unavailable or outside supported grammar")
    tokens, offset = [], 0
    while offset < len(text.rstrip()):
        match = _TOKEN.match(text, offset)
        if not match:
            raise Unavailable("filter syntax needs semantic review")
        tokens.append(match[1])
        offset = match.end()
    if len(tokens) > 1024:
        raise Unavailable("filter expression too complex")
    pos = 0

    def combine(op, nodes):
        flat = []
        for node in nodes:
            flat.extend(node[1] if node[0] == op else [node])
        return flat[0] if len(flat) == 1 else (op, tuple(sorted(set(flat))))

    def value(token):
        if token in ("AND", "OR", "NOT", "(", ")", "=", ":") or token.startswith("-"):
            raise Unavailable("unsupported filter operator")
        if token.startswith('"'):
            try:
                return json.loads(token)
            except ValueError as exc:
                raise Unavailable("unsupported filter string escape") from exc
        return token

    def atom(depth):
        nonlocal pos
        if depth > 48 or pos >= len(tokens):
            raise Unavailable("incomplete or complex filter expression")
        token = tokens[pos]
        pos += 1
        if token == "(":
            node = conjunction(depth + 1)
            if pos >= len(tokens) or tokens[pos] != ")":
                raise Unavailable("unbalanced filter expression")
            pos += 1
            return node
        left = value(token)
        if pos < len(tokens) and tokens[pos] in ("=", ":"):
            op = tokens[pos]
            pos += 1
            if token.startswith('"') or pos >= len(tokens):
                raise Unavailable("unsupported field comparison")
            if monitoring and not tokens[pos].startswith('"') and not (left == "project" and tokens[pos].isdigit()):
                raise Unavailable("Monitoring selector requires quoted string values")
            right = value(tokens[pos])
            pos += 1
            return ("atom", left, op, right)
        return ("global", left)

    def disjunction(depth):
        nonlocal pos
        nodes = [atom(depth)]
        while pos < len(tokens) and tokens[pos] == "OR":
            pos += 1
            nodes.append(atom(depth))
        return combine("OR", nodes)

    def conjunction(depth):
        nonlocal pos
        nodes = [disjunction(depth)]
        while pos < len(tokens) and tokens[pos] != ")":
            if tokens[pos] == "AND":
                pos += 1
            nodes.append(disjunction(depth))  # Logging and Monitoring allow implicit AND.
        return combine("AND", nodes)

    tree = conjunction(0)
    if pos != len(tokens):
        raise Unavailable("trailing filter syntax")
    return tree


def reference_filter_matches(text, reference):
    """True only for a fully proven reference expression; never substring search."""
    if _expression(text) != _expression(reference):
        raise Unavailable("Logging filter differs from the complete reference expression")
    return True


def _selector_matches(text, metric_type, projects, project_id):
    if len(text) > 2048:
        raise Unavailable("Monitoring selector exceeds API length limit")
    tree = _expression(text, monitoring=True)
    atoms = tree[1] if tree[0] == "AND" else (tree,)
    if any(atom[0] != "atom" or atom[2] != "=" for atom in atoms):
        raise Unavailable("Monitoring selector needs semantic review")
    types = {a[3] for a in atoms if a[1] == "metric.type"}
    if not types:
        raise Unavailable("Monitoring selector has no exact metric type")
    if types != {metric_type}:
        return False
    for _, field, _, value in atoms:
        if field in ("project", "resource.labels.project_id"):
            allowed = projects if field == "project" else {project_id}
            if value not in allowed:
                return False
        elif field not in ("metric.type", "resource.type"):
            raise Unavailable("Monitoring selector contains additional restrictions")
    resource_types = {a[3] for a in atoms if a[1] == "resource.type"}
    if not resource_types or "" in resource_types:
        raise Unavailable("Monitoring selector has no required resource type")
    if len(resource_types) > 1:
        return False
    return True


def _alert_matches(alert, metric_type, projects, project_id):
    validity = optional(alert, "validity", {}, dict)
    if validity and get(validity, "code", int) != 0:
        return False
    conditions = list_of_objects(get(alert, "conditions", list))
    uncertain = False
    for condition in conditions:
        forms = [key for key in condition if key.startswith("condition")]
        if len(forms) != 1:
            raise Unavailable("ambiguous Monitoring condition union")
        key = forms[0]
        if key not in ("conditionThreshold", "conditionAbsent"):
            uncertain = True  # MQL, PromQL and log-match are different languages.
            continue
        try:
            body = get(condition, key, dict)
            if _selector_matches(get(body, "filter", str), metric_type, projects, project_id):
                return True
        except Unavailable:
            uncertain = True
    if uncertain:
        raise Unavailable("alert condition association could not be proved")
    return False


def evaluate_metric_alert_native(item, index, reference_filter):
    """Same-project reference metric plus an enabled, valid associated policy.

    Threshold values, absence durations, policy combiners and notification
    channels do not establish event delivery and are outside this declaration
    check. A threshold and an absence condition both constitute association.
    """
    project = get(item, "projectId", str)
    if not project or "/" in project:
        raise Unavailable("malformed project identifier")
    projects = {project}
    number = optional(item, "name", "", str)
    if number:
        match = re.fullmatch(r"projects/([^/]+)", number)
        if not match:
            raise Unavailable("malformed project resource name")
        if match[1] != project and not match[1].isdigit():
            raise Unavailable("project resource name is not a native numeric alias")
        projects.add(match[1])
    metrics, uncertain = [], False
    for metric in complete_items(index, "logging_metric"):
        try:
            name = get(metric, "name", str)
            match = re.fullmatch(r"projects/([^/]+)/metrics/(.+)", name)
            if not match:
                raise Unavailable("metric project binding unavailable")
            if match[1] not in projects or optional(metric, "disabled", False, bool):
                continue
            reference_filter_matches(get(metric, "filter", str), reference_filter)
            if optional(metric, "bucketName", "", str):
                raise Unavailable("bucket-scoped metric coverage not evaluated")
            metric_type = get(metric, "metricDescriptor.type", str)
            if metric_type != "logging.googleapis.com/user/" + optional(metric, "metricId", match[2], str):
                raise Unavailable("metric descriptor type does not identify this log metric")
            metrics.append(metric_type)
        except Unavailable:
            uncertain = True
    alerts = complete_items(index, "monitoring_alert_policy")
    alerted = []
    for alert in alerts:
        try:
            name = get(alert, "name", str)
            match = re.fullmatch(r"projects/([^/]+)/alertPolicies/([^/]+)", name)
            if not match:
                raise Unavailable("alert project binding unavailable")
            if match[1] not in projects or not get(alert, "enabled", bool):
                continue
            for metric_type in metrics:
                if _alert_matches(alert, metric_type, projects, project):
                    alerted.append({"alert": name, "metric_type": metric_type})
        except Unavailable:
            uncertain = True
    evidence = dict(matching_metrics=sorted(set(metrics)), alerting=alerted,
                    semantics="Same-project reference metric and enabled alert declarations; event triggering, "
                              "cross-project metrics scopes and notification delivery are not evaluated")
    if not alerted and uncertain:
        return unknown("Metric or alert filter association needs semantic review", **evidence)
    return result(not alerted, **evidence)
