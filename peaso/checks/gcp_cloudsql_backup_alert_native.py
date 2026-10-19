"""Bounded native Cloud SQL scheduled-backup alert configuration contract.

This inspects declarations, never sends a test event or claims delivery. Complex
filters, restricted event subsets and advanced threshold semantics stay UNKNOWN.
"""
import math
import re

from .facts import Unavailable, get, list_of_objects

EXPECTED = {
    "resource.type": "cloudsql_database",
    "protoPayload.methodName": "cloudsql.instances.automatedBackup",
    "protoPayload.metadata.windowStatus": "STATUS_FAILED",
}
_CLAUSE = re.compile(r'\s*([A-Za-z][A-Za-z0-9_.]*)\s*=\s*"([^"\\]*)"\s*')


def matches_failed_window(expression):
    """True/False for the exact supported conjunction; None for other syntax.

    Deliberately no sample-event inference: matching a fabricated entry cannot
    establish that a filter covers all instances or all failed windows.
    """
    if not isinstance(expression, str) or not expression.strip():
        return None
    fields, cursor = {}, 0
    while cursor < len(expression):
        match = _CLAUSE.match(expression, cursor)
        if not match or match[1] in fields:
            return None
        fields[match[1]] = match[2]
        cursor = match.end()
        if cursor == len(expression):
            break
        separator = re.match(r'AND\s+', expression[cursor:])
        if separator:
            cursor += separator.end()
            if cursor == len(expression):
                return None
        elif cursor and expression[cursor - 1].isspace() and _CLAUSE.match(expression, cursor):
            pass  # Logging's implicit conjunction, including newline-separated clauses.
        else:
            return None
    if set(fields) != set(EXPECTED):
        return None
    return fields == EXPECTED


def _optional(row, key, default, expected):
    if key in row.get('_coverage', {}) or key in row:
        return get(row, key, expected)
    # These defaults are the native protobuf scalar defaults, not inferred policy.
    return default


def _policy_identity(alert, aliases):
    name = get(alert, 'name', str)
    match = re.fullmatch(r'projects/([^/]+)/alertPolicies/([^/]+)', name)
    if not match or match[1] not in aliases:
        raise Unavailable('alert policy belongs to another project or has no native identity')
    return name


def _threshold_matches(body, metric_names):
    expression = get(body, 'filter', str)
    match = re.fullmatch(r'\s*metric\.type\s*=\s*"([^"\\]+)"\s*'
                         r'(?:AND\s+resource\.type\s*=\s*"cloudsql_database"\s*)?', expression)
    if not match:
        return None
    if match[1] not in metric_names:
        return False
    if get(body, 'comparison', str) != 'COMPARISON_GT':
        return None
    threshold = body.get('thresholdValue', 0)
    if (type(threshold) not in (int, float) or not math.isfinite(threshold)
            or threshold != 0 or 'thresholdValue' in body.get('_coverage', {})):
        return None
    if get(body, 'duration', str) != '0s':
        return None
    if any(key in body or key in body.get('_coverage', {}) for key in
           ('denominatorFilter', 'denominatorAggregations', 'forecastOptions', 'evaluationMissingData')):
        return None
    if _optional(body, 'aggregations', [], list):
        return None
    trigger = _optional(body, 'trigger', {}, dict)
    if trigger and (set(trigger) != {'count'} or type(trigger['count']) is not int or trigger['count'] != 1):
        return None
    return True


def configured_alerts(project, scope, alerts, metrics):
    """Return native alert names; fail closed on unproved candidate semantics."""
    aliases = {scope.split('/', 1)[1]}
    if 'projectId' in project:
        aliases.add(get(project, 'projectId', str))
    uncertain, active = False, []
    metric_names = set()
    for metric in metrics:
        mid = get(metric, 'metricId', str)
        if not mid or '/' in mid or get(metric, 'name', str) != scope + '/metrics/' + mid:
            raise Unavailable('logging metric has a foreign or malformed native identity')
        if _optional(metric, 'disabled', False, bool):
            continue
        decision = matches_failed_window(get(metric, 'filter', str))
        if decision is None:
            uncertain = True
        elif decision:
            descriptor = get(metric, 'metricDescriptor', dict)
            mtype = 'logging.googleapis.com/user/' + mid
            if (get(descriptor, 'type', str) != mtype
                    or get(descriptor, 'metricKind', str) != 'DELTA'
                    or get(descriptor, 'valueType', str) != 'INT64'
                    or _optional(metric, 'bucketName', '', str)):
                uncertain = True
            else:
                metric_names.add(mtype)
    for alert in alerts:
        name = _policy_identity(alert, aliases)
        # This is a BoolValue: unlike scalar protobuf fields, missing on read
        # has no default interpretation (AlertPolicy API contract).
        if not get(alert, 'enabled', bool):
            continue
        if _optional(alert, 'validity', {}, dict):
            # The output-only field is populated only for invalid policies,
            # which do not generate incidents even if enabled.
            continue
        conditions = list_of_objects(get(alert, 'conditions', list))
        if not conditions:
            raise Unavailable('enabled alert policy has no native conditions')
        decisions = []
        if len(conditions) > 1 and any('conditionMatchedLog' in condition for condition in conditions):
            uncertain = True
            continue  # Native LogMatch must be the policy's only condition.
        for condition in conditions:
            kinds = [key for key in condition if key.startswith('condition')]
            if len(kinds) != 1:
                decisions.append(None)
            elif kinds[0] == 'conditionMatchedLog':
                decisions.append(matches_failed_window(get(condition, 'conditionMatchedLog.filter', str)))
            elif kinds[0] == 'conditionThreshold':
                decisions.append(_threshold_matches(get(condition, 'conditionThreshold', dict), metric_names))
            else:
                decisions.append(None)
        independent = len(conditions) == 1 or _optional(alert, 'combiner', '', str) == 'OR'
        if independent and True in decisions:
            active.append(name)
        elif None in decisions or True in decisions:
            uncertain = True
    if active:
        return sorted(set(active))
    if uncertain:
        raise Unavailable('backup alert filter or threshold semantics are outside the supported native contract')
    return []


def install_fixtures():
    """Current native-produced examples supersede legacy synthetic truth markers."""
    import gzip
    import json
    from pathlib import Path
    from .fixtures import CASES

    CASES['gcp_cloudsql_backup_failure_alert'] = json.loads(gzip.decompress(
        Path(__file__).with_name('gcp_cloudsql_backup_alert_fixtures.json.gz').read_bytes()))
