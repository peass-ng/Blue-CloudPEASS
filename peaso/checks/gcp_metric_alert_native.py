"""Bounded native log-metric/alert association; no event or delivery claims.

Only the complete reference Logging expression is admitted (modulo grouping,
ordering, whitespace and quoted bare values). Other expressions stay UNKNOWN.
Monitoring threshold/absence selectors are parsed separately from MQL.
"""
from __future__ import annotations

import json
import math
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
    references = reference if isinstance(reference, tuple) else (reference,)
    if _expression(text) not in [_expression(value) for value in references]:
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


def _counter_threshold_matches(body, metric, metric_type, projects, project_id, resource_type):
    """Prove the bounded positive-count alert contract, not incident delivery."""
    if not _selector_matches(get(body, "filter", str), metric_type, projects, project_id):
        return False
    if resource_type is not None:
        tree = _expression(get(body, "filter", str), monitoring=True)
        atoms = tree[1] if tree[0] == "AND" else (tree,)
        if {atom[3] for atom in atoms if atom[1] == "resource.type"} != {resource_type}:
            return False
    descriptor = get(metric, "metricDescriptor", dict)
    if (get(descriptor, "metricKind", str) != "DELTA"
            or get(descriptor, "valueType", str) != "INT64"):
        raise Unavailable("event alert requires a native DELTA INT64 counter")
    comparison = get(body, "comparison", str)
    threshold = optional(body, "thresholdValue", 0, (int, float))
    if type(threshold) not in (int, float) or not math.isfinite(threshold):
        raise Unavailable("event alert threshold is not finite")
    # Negative/non-event thresholds cannot attest detection of positive counts.
    # Values above zero require an owner-chosen event volume policy, which this
    # check does not invent. The native default 0 is preserved on omitted scalars.
    if comparison != "COMPARISON_GT" or not 0 <= threshold < 1:
        raise Unavailable("event alert does not prove detection of a positive count")
    if get(body, "duration", str) != "0s":
        raise Unavailable("event alert has an unproved sustained-count requirement")
    for key in ("denominatorFilter", "denominatorAggregations", "forecastOptions", "evaluationMissingData"):
        if key in body or key in body.get("_coverage", {}):
            raise Unavailable("advanced event alert threshold semantics require review")
    for aggregation in list_of_objects(optional(body, "aggregations", [], list)):
        period = get(aggregation, "alignmentPeriod", str)
        if not re.fullmatch(r"[0-9]+s", period) or int(period[:-1]) < 60:
            raise Unavailable("event alert alignment period is unavailable")
        if get(aggregation, "perSeriesAligner", str) not in ("ALIGN_DELTA", "ALIGN_SUM"):
            raise Unavailable("event alert aligner does not preserve event counts")
        if optional(aggregation, "crossSeriesReducer", "REDUCE_NONE", str) != "REDUCE_NONE":
            raise Unavailable("event alert cross-series reduction requires review")
        if optional(aggregation, "groupByFields", [], list):
            raise Unavailable("event alert grouping requires review")
    trigger = optional(body, "trigger", {}, dict)
    if trigger and (set(trigger) != {"count"} or get(trigger, "count", int) != 1):
        raise Unavailable("event alert requires an unproved number of time series")
    return True


def _alert_matches(alert, metric_type, projects, project_id, *, metric=None, event_threshold=False, resource_type=None):
    validity = optional(alert, "validity", {}, dict)
    if validity and get(validity, "code", int) != 0:
        return False
    conditions = list_of_objects(get(alert, "conditions", list))
    if event_threshold:
        if not 1 <= len(conditions) <= 6:
            raise Unavailable("event alert has no valid native condition inventory")
        if len(conditions) > 1 and optional(alert, "combiner", "", str) != "OR":
            raise Unavailable("an AND gate does not prove independent event detection")
    uncertain = False
    for condition in conditions:
        forms = [key for key in condition if key.startswith("condition")]
        if len(forms) != 1:
            raise Unavailable("ambiguous Monitoring condition union")
        key = forms[0]
        if key not in (("conditionThreshold",) if event_threshold else ("conditionThreshold", "conditionAbsent")):
            uncertain = True  # MQL, PromQL and log-match are different languages.
            continue
        try:
            body = get(condition, key, dict)
            matches = (_counter_threshold_matches(body, metric, metric_type, projects, project_id, resource_type)
                       if event_threshold else _selector_matches(get(body, "filter", str), metric_type, projects, project_id))
            if matches:
                return True
        except Unavailable:
            uncertain = True
    if uncertain:
        raise Unavailable("alert condition association could not be proved")
    return False


def evaluate_metric_alert_native(item, index, reference_filter, *, event_threshold=False, resource_type=None):
    """Same-project reference metric plus an enabled, valid associated policy.

    Threshold values, absence durations, policy combiners and notification
    channels do not establish event delivery and are outside this declaration
    check. A threshold and an absence condition both constitute association.
    """
    return evaluate_metric_alert_rows_native(item, complete_items(index, "logging_metric"),
        complete_items(index, "monitoring_alert_policy"), reference_filter, event_threshold=event_threshold,
        resource_type=resource_type)


def evaluate_metric_alert_rows_native(item, metric_rows, alerts, reference_filter, *, event_threshold=False, resource_type=None):
    """Shared row consumer after the caller proves complete scoped inventories.

    event_threshold=False is explicitly association configuration only. True
    additionally requires a supported positive-count threshold independent of
    unrelated condition gates; neither mode establishes notification delivery.
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
    for metric in metric_rows:
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
            metrics.append((metric_type, metric))
        except Unavailable:
            uncertain = True
    alerted = []
    for alert in alerts:
        try:
            name = get(alert, "name", str)
            match = re.fullmatch(r"projects/([^/]+)/alertPolicies/([^/]+)", name)
            if not match:
                raise Unavailable("alert project binding unavailable")
            if match[1] not in projects or not get(alert, "enabled", bool):
                continue
            for metric_type, metric in metrics:
                if _alert_matches(alert, metric_type, projects, project, metric=metric, event_threshold=event_threshold,
                                  resource_type=resource_type):
                    alerted.append({"alert": name, "metric_type": metric_type})
        except Unavailable:
            uncertain = True
    evidence = dict(matching_metrics=sorted({mtype for mtype, _ in metrics}), alerting=alerted,
                    assessed_configuration="positive-count event threshold" if event_threshold else "metric/alert association only",
                    semantics="Same-project reference metric and enabled alert declarations; event triggering, "
                              "cross-project metrics scopes and notification delivery are not evaluated")
    if not alerted and uncertain:
        return unknown("Metric or alert filter association needs semantic review", **evidence)
    return result(not alerted, **evidence)
