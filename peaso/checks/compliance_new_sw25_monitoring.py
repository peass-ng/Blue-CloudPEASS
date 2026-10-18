"""Measured reporting/capacity/transition evidence and native alert declarations."""
from __future__ import annotations

from . import result, unknown
from .facts import Unavailable, get, list_of_objects, optional
from datetime import timedelta
from decimal import Decimal
import hashlib
import json
from .compliance_new_sw25_facts import (
    REPORT_ID, ROUTING_ID, CAPACITY_ID, GATEWAY_ID, SETTINGS_ID, REQUIRED_ID,
    FAMILIES, ARM_TYPES, _text, _strings, _date, _number, _scope, _policy, _now,
    _rows, _arm, _one, _coverage, _aggregate, _literal, _duration,
)

def _alerts(index):
    alerts = []
    for kind in FAMILIES:
        for row in _rows(index, kind):
            props = get(row, 'properties', dict)
            get(props, 'enabled', bool)
            scopes = _strings(get(props, 'scopes', list))
            if not scopes or len({s.casefold() for s in scopes}) != len(scopes):
                raise Unavailable('alert effective scope absent')
            for scope in scopes:
                if scope.casefold() != _scope(index).casefold():
                    _arm(scope, _scope(index))
            alerts.append((kind, row))
    return alerts


def _groups(index):
    return {get(g, 'id', str).casefold(): get(g, 'properties.enabled', bool)
            for g in _rows(index, 'action_group')}


def _group_ids(kind, props, scope):
    if kind == 'activity_log_alert':
        ids = [get(a, 'actionGroupId', str) for a in list_of_objects(get(props, 'actions.actionGroups', list))]
    elif kind == 'metric_alert':
        ids = [get(a, 'actionGroupId', str) for a in list_of_objects(get(props, 'actions', list))]
    elif kind == 'scheduled_query_rule':
        ids = _strings(get(props, 'actions.actionGroups', list))
    else:
        raise Unavailable('unsupported alert family')
    groups = {_arm(i, scope, ARM_TYPES['action_group']) for i in ids}
    if len(groups) != len(ids):
        raise Unavailable('duplicate alert action-group identity')
    return groups


def _routing(index):
    scope = _scope(index)
    metadata = get(get(index, 'context', dict), 'metadata', dict)
    absent = object()
    legacy = optional(metadata, 'sw25_policy', absent, dict)
    parent = optional(metadata, 'compliance_policy', absent, dict)
    namespace = optional(parent, 'sw25', absent, dict) if parent is not absent else absent
    supplied = legacy is not absent or namespace is not absent
    other_requirements_only = (
        legacy is absent and namespace is not absent
        and set(namespace) == {'status', 'scope', 'checks'}
        and namespace['status'] == 'collected'
        and isinstance(namespace['scope'], str) and namespace['scope'].casefold() == scope.casefold()
        and isinstance(namespace['checks'], dict) and bool(namespace['checks'])
        and ROUTING_ID not in namespace['checks'])
    policy = _policy(index, ROUTING_ID) if supplied and not other_requirements_only else {}
    # Optional ID is absent/null by default; no prelisted alert IDs are needed.
    required = optional(policy, 'actionGroupId', None)
    if required is not None:
        required = _arm(required, scope, ARM_TYPES['action_group'])
    alerts = _alerts(index)
    failures = []
    for kind, alert in alerts:
        if '_routing_provenance' in alert:
            from ..collectors.azure_alert_routing_native import verify_projection
            try:
                verify_projection(kind, scope, alert)
            except ValueError as exc:
                raise Unavailable(str(exc)) from exc
        props = get(alert, 'properties', dict)
        native = _group_ids(kind, props, scope)
        states = _strings(get(props, '_applicableActionStates', list))
        if not states or not set(states) <= {'Activated', 'Resolved', 'No Data'}:
            raise Unavailable('applicable alert action-state semantics unresolved')
        bindings = list_of_objects(get(props, '_actionStateBindings', list))
        observed = {}
        for binding in bindings:
            state = get(binding, 'state', str)
            if state not in states or state in observed:
                raise Unavailable('duplicate/foreign action state binding')
            groups = {_arm(g, scope, ARM_TYPES['action_group']) for g in _strings(get(binding, 'actionGroupIds', list))}
            if not groups <= native:
                raise Unavailable('state binding conflicts with native action group declarations')
            observed[state] = groups
        if set(observed) != set(states):
            raise Unavailable('action-state binding incomplete')
        # These alert types share one action list across the resolved applicable
        # states; the collector proves that contract, not inferred delivery.
        if any(groups != native for groups in observed.values()):
            raise Unavailable('state-specific routing interpretation unsupported')
        if any(not groups or required is not None and required not in groups for groups in observed.values()):
            failures.append({'alertId': get(alert, 'id', str), 'reason': 'Applicable action state has no required action group'})
    return result(bool(failures), violations=failures, alert_count=len(alerts),
                  semantics='Configured routing only; receiver availability and delivery untested')


def _metric_alerts(index):
    scope = _scope(index)
    rows = _rows(index, 'metric_alert')
    for alert in rows:
        props = get(alert, 'properties', dict)
        get(props, 'enabled', bool)
        scopes = _strings(get(props, 'scopes', list))
        if not scopes or len({s.casefold() for s in scopes}) != len(scopes):
            raise Unavailable('metric alert scope absent')
        for rid in scopes:
            _arm(rid, scope)
    return rows


def _criteria(props, *, require_namespace=True):
    criteria = get(props, 'criteria', dict)
    kind = _text(_literal(criteria, 'odata.type'))
    if kind not in ('Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria',
                    'Microsoft.Azure.Monitor.MultipleResourceMultipleMetricCriteria'):
        raise Unavailable('unsupported metric alert criteria type')
    conditions = list_of_objects(get(criteria, 'allOf', list))
    if not conditions:
        raise Unavailable('metric alert criteria empty')
    for condition in conditions:
        _text(get(condition, 'metricName', str))
        # metricNamespace is optional in the pinned 2018-03-01 native API.
        # Exact settings comparison still requires it; a name-only presence
        # requirement must not infer or invent a namespace for an omitted one.
        if require_namespace or 'metricNamespace' in condition:
            _text(get(condition, 'metricNamespace', str))
        if get(condition, 'criterionType', str) != 'StaticThresholdCriterion':
            raise Unavailable('dynamic/unsupported criterion interpretation')
    return kind, conditions


def _resources(index):
    # A paged native generic ARM Resources LIST projected as resource inventory.
    scope = _scope(index)
    return {_arm(get(r, 'id', str), scope) for r in _rows(index, 'azure_resource')}


def _required_metrics(index):
    policy, scope = _policy(index, REQUIRED_ID), _scope(index)
    required = list_of_objects(get(policy, 'requiredMetrics', list))
    if not required:
        return 'NOT_APPLICABLE', {'reason': 'Frozen policy explicitly specifies no resources/metrics'}
    inventory, alerts = _resources(index), _metric_alerts(index)
    failures, uncertain = [], []
    seen = set()
    for requirement in required:
        rid = _arm(get(requirement, 'resourceId', str), scope)
        metric = _text(get(requirement, 'metricName', str))
        namespace = optional(requirement, 'metricNamespace', None)
        if namespace is not None:
            namespace = _text(namespace)
        key = (rid, metric, namespace)
        if key in seen:
            raise Unavailable('duplicate required resource/metric')
        seen.add(key)
        if rid not in inventory:
            uncertain.append({'resourceId': rid, 'reason': 'Required resource missing from measured inventory'})
            continue
        found, unresolved = False, False
        for alert in alerts:
            props = get(alert, 'properties', dict)
            if rid not in {r.casefold() for r in get(props, 'scopes', list)} or not get(props, 'enabled', bool):
                continue
            try:
                _, conditions = _criteria(props, require_namespace=namespace is not None)
                found |= any(get(c, 'metricName', str) == metric and (namespace is None or get(c, 'metricNamespace', str) == namespace) for c in conditions)
            except Unavailable:
                unresolved = True
        if not found:
            (uncertain if unresolved else failures).append({'resourceId': rid, 'metricName': metric})
    return _aggregate(failures, uncertain, required_metric_count=len(required))


def _dimensions(value):
    result = []
    seen = set()
    for dimension in list_of_objects(value):
        name = _text(get(dimension, 'name', str))
        operator = get(dimension, 'operator', str)
        if operator not in ('Include', 'Exclude') or name in seen:
            raise Unavailable('malformed metric dimensions')
        seen.add(name)
        values = _strings(get(dimension, 'values', list))
        if not values:
            raise Unavailable('empty metric dimension values')
        result.append((name, operator, tuple(sorted(values))))
    return tuple(sorted(result))


def _setting(value, scope, *, expected=False):
    scopes = tuple(sorted(_arm(r, scope) for r in _strings(get(value, 'scopes', list))))
    if not scopes or len(set(scopes)) != len(scopes):
        raise Unavailable('expected metric scope absent or duplicated')
    severity = get(value, 'severity', int)
    if severity not in range(5):
        raise Unavailable('invalid metric alert severity')
    frequency, window = _duration(get(value, 'evaluationFrequency', str)), _duration(get(value, 'windowSize', str))
    kind, conditions = _criteria(value)
    fingerprints = []
    for condition in conditions:
        aggregation, operator = get(condition, 'timeAggregation', str), get(condition, 'operator', str)
        if aggregation not in ('Average', 'Minimum', 'Maximum', 'Total', 'Count') or operator not in ('Equals', 'GreaterThan', 'GreaterThanOrEqual', 'LessThan', 'LessThanOrEqual'):
            raise Unavailable('unsupported metric threshold semantics')
        fingerprints.append((get(condition, 'metricNamespace', str), get(condition, 'metricName', str),
                             aggregation, operator, _number(get(condition, 'threshold'), signed=True),
                             _dimensions(get(condition, 'dimensions', list))))
    if len(set(fingerprints)) != len(fingerprints):
        raise Unavailable('duplicate metric conditions')
    return scopes, severity, frequency, window, kind, tuple(sorted(fingerprints))


def _metric_settings(index):
    policy, scope = _policy(index, SETTINGS_ID), _scope(index)
    expected = list_of_objects(get(policy, 'expectedMetricSettings', list))
    if not expected:
        raise Unavailable('expected metric setting policy empty')
    settings = []
    for setting in expected:
        required = _setting(setting, scope, expected=True)
        configured_groups = optional(setting, 'actionGroupIds', None)
        approved_groups = None if configured_groups is None else {_arm(g, scope, ARM_TYPES['action_group']) for g in _strings(configured_groups)}
        if approved_groups == set():
            raise Unavailable('explicit expected enabled action-group policy empty')
        settings.append((required, approved_groups))
    alerts = _metric_alerts(index)
    for alert in alerts:
        if 'type' in alert and get(alert, 'type', str).casefold() != ARM_TYPES['metric_alert'].casefold():
            raise Unavailable('metric alert native type differs from ARM identity')
        proof = alert.get('_provenance')
        if proof is not None and (not isinstance(proof, dict) or
                'read_only' in proof and get(proof, 'read_only', bool) is not True):
            raise Unavailable('metric alert native declaration is not read-only')
    if not any(get(alert, 'properties.enabled', bool) for alert in alerts):
        return _aggregate([{'expectedSetting': number, 'reason': 'Complete native metric alert inventory contains no enabled rule'}
                           for number in range(len(settings))], [], expected_setting_count=len(settings))
    groups = _groups(index)
    failures, uncertain = [], []
    for number, (required, approved_groups) in enumerate(settings):
        match, unresolved = False, False
        for alert in alerts:
            props = get(alert, 'properties', dict)
            if not get(props, 'enabled', bool):
                continue
            try:
                measured = _setting(props, scope)
                if measured != required:
                    continue
                routed = _group_ids('metric_alert', props, scope)
                if approved_groups is not None:
                    routed &= approved_groups
                if any(g not in groups for g in routed):
                    raise Unavailable('metric alert action group missing from inventory')
                match |= any(groups[g] for g in routed)
            except Unavailable:
                unresolved = True
        if not match:
            (uncertain if unresolved else failures).append({'expectedSetting': number})
    return _aggregate(failures, uncertain, expected_setting_count=len(expected))


def _window(policy, now):
    start, end = _date(get(policy, 'windowStart', str)), _date(get(policy, 'windowEnd', str))
    if start >= end or end > now:
        raise Unavailable('approved lookback window invalid')
    return start, end


def _critical_reporting(index):
    policy, now = _policy(index, REPORT_ID), _now(index)
    start, end = _window(policy, now)
    delay = _number(get(policy, 'maxReportDelaySeconds'), positive=True)
    definitions = list_of_objects(get(policy, 'criticalFailures', list))
    if not definitions:
        raise Unavailable('failure-classification policy absent')
    operations = {}
    approved_recipients = get(policy, 'departmentRecipients', dict)
    for definition in definitions:
        operation = _text(get(definition, 'operationName', str))
        if operation in operations:
            raise Unavailable('ambiguous failure classification')
        departments = _strings(get(definition, 'departmentIds', list))
        if not departments:
            raise Unavailable('responsible departments missing')
        for department in departments:
            if not _strings(_literal(approved_recipients, department)):
                raise Unavailable('responsible department recipient policy absent')
        operations[operation] = departments
    evidence = _one(index, 'failure_reporting_window')
    if _date(get(evidence, 'windowStart', str)) != start or _date(get(evidence, 'windowEnd', str)) != end:
        raise Unavailable('failure detection evidence belongs to another window')
    if set(_strings(get(evidence, 'operationNames', list))) != set(operations):
        raise Unavailable('failure classification coverage incomplete')
    events, deliveries = _rows(index, 'critical_failure_event'), _rows(index, 'failure_delivery_record')
    failures, uncertain, count = [], [], 0
    ids = {get(e, 'id', str) for e in events}
    if any(get(d, 'eventId', str) not in ids for d in deliveries):
        raise Unavailable('delivery record belongs to unmeasured failure')
    for event in events:
        operation = get(event, 'operationName', str)
        when = _date(get(event, 'eventTime', str))
        if not start <= when <= end:
            raise Unavailable('foreign failure event window')
        if get(event, 'status', str) != 'Failed':
            raise Unavailable('event failure classification unresolved')
        if operation not in operations:
            continue
        count += 1
        for department in operations[operation]:
            records = [r for r in deliveries if get(r, 'eventId', str) == get(event, 'id', str)
                       and get(r, 'departmentId', str) == department]
            delivered, pending = False, False
            for record in records:
                state = get(record, 'state', str)
                automatic = get(record, 'automatic', bool)
                if state not in ('Delivered', 'Undelivered', 'Pending'):
                    raise Unavailable('unknown notification delivery state')
                _coverage(record, 'receiver')
                receiver = _text(get(record, 'receiverId', str))
                attempted = _date(get(record, 'attemptedAt', str))
                if not when <= attempted <= now:
                    raise Unavailable('notification attempt timestamp unresolved')
                if state == 'Delivered':
                    timestamp = _date(get(record, 'deliveredAt', str))
                    if not attempted <= timestamp <= now:
                        raise Unavailable('notification delivery chronology unresolved')
                    delivered |= (automatic and receiver in _literal(approved_recipients, department)
                                  and (timestamp - when).total_seconds() <= float(delay))
                pending |= state == 'Pending'
            if not delivered:
                if now < when + timedelta(seconds=float(delay)):
                    uncertain.append({'eventId': get(event, 'id', str), 'departmentId': department})
                else:
                    failures.append({'eventId': get(event, 'id', str), 'departmentId': department,
                                     'reason': 'No measured timely automatic notification'})
    if not count:
        intervals = list_of_objects(get(evidence, 'continuousCoverage', list))
        proofs = {get(row, 'id', str): row for row in _rows(index, 'failure_reporting_coverage')}
        spans = []
        for interval in intervals:
            begin, finish = _date(get(interval, 'start', str)), _date(get(interval, 'end', str))
            if (begin >= finish or finish > now
                    or not _strings(get(interval, 'detectionEvidenceIds', list))
                    or not _strings(get(interval, 'reportingEvidenceIds', list))):
                raise Unavailable('independent continuous detection/reporting proof absent or future-dated')
            for purpose, field in (('detection', 'detectionEvidenceIds'), ('reporting', 'reportingEvidenceIds')):
                for pid in get(interval, field, list):
                    proof = proofs.get(pid)
                    if proof is None or get(proof, 'purpose', str) != purpose:
                        raise Unavailable('independent continuity evidence reference unresolved')
                    _text(get(proof, 'independentMonitorId', str))
                    if set(_strings(get(proof, 'operationNames', list))) != set(operations):
                        raise Unavailable('independent monitoring has incomplete failure-classification coverage')
                    _coverage(proof, 'segments')
                    segments = list_of_objects(get(proof, 'segments', list))
                    proof_spans = []
                    for segment in segments:
                        a, b = _date(get(segment, 'start', str)), _date(get(segment, 'end', str))
                        if (a >= b or b > now or get(segment, 'available', bool) is not True
                                or not _strings(get(segment, 'sourceRecordIds', list))):
                            raise Unavailable('continuous failure detection/reporting availability unproven or future-dated')
                        if purpose == 'reporting':
                            receivers = set(_strings(get(segment, 'receiverIds', list)))
                            if (get(segment, 'automaticNotificationCount', int) <= 0
                                    or _number(get(segment, 'maximumMeasuredDelaySeconds')) > delay
                                    or any(not receivers.intersection(_literal(approved_recipients, d))
                                           for departments in operations.values() for d in departments)):
                                raise Unavailable('independent reporting probes do not prove timely responsible-department delivery')
                        proof_spans.append((a, b))
                    proof_cursor = begin
                    for a, b in sorted(proof_spans):
                        if a > proof_cursor:
                            break
                        proof_cursor = max(proof_cursor, b)
                    if proof_cursor < finish:
                        raise Unavailable('independent continuity observations contain a gap')
            spans.append((begin, finish))
        cursor = start
        for begin, finish in sorted(spans):
            if begin > cursor:
                break
            cursor = max(cursor, finish)
        if cursor < end:
            return unknown('Empty failures lack continuous independently evidenced reporting coverage')
    return _aggregate(failures, uncertain, measured_failure_count=count,
                      semantics='Measured automatic notification to responsible departments in approved lookback')


def _capacity(index):
    policy, now, scope = _policy(index, CAPACITY_ID), _now(index), _scope(index)
    start, end = _window(policy, now)
    components = list_of_objects(get(policy, 'components', list))
    if not components:
        raise Unavailable('workload component inventory absent')
    inventory = _resources(index)
    records = _rows(index, 'capacity_record', identity='resourceId')
    changes = _rows(index, 'capacity_change_record')
    # Validate the whole change inventory even when no forecast breaches a
    # threshold. Unused rows cannot bypass subscription/resource binding.
    change_resources = set()
    for change in changes:
        change_resources.add(_arm(get(change, 'resourceId', str), scope))
        _text(get(change, 'forecastId', str))
    measured = {_arm(get(r, 'resourceId', str), scope): r for r in records}
    failures, uncertain, expected_ids = [], [], set()
    for component in components:
        rid = _arm(get(component, 'resourceId', str), scope)
        if rid in expected_ids:
            raise Unavailable('duplicate component policy')
        expected_ids.add(rid)
        scenarios = set(_strings(get(component, 'failureScenarioIds', list)))
        if not scenarios:
            raise Unavailable('component failure scenario policy missing')
        try:
            if rid not in inventory or rid not in measured:
                raise Unavailable('unmeasured workload component')
            record = measured[rid]
            if _date(get(record, 'windowStart', str)) != start or _date(get(record, 'windowEnd', str)) != end:
                raise Unavailable('capacity measurements cover another window')
            _coverage(record, 'samples')
            samples = list_of_objects(get(record, 'samples', list))
            if not samples:
                raise Unavailable('capacity baseline unmeasured')
            sample_times = [_date(get(s, 'time', str)) for s in samples]
            frequency = get(component, 'sampleIntervalSeconds', int)
            if frequency <= 0 or len(set(sample_times)) != len(sample_times) or any(t < start or t > end for t in sample_times):
                raise Unavailable('metric sample times malformed')
            ordered = sorted(sample_times)
            boundaries = [start, *ordered, end]
            if any((b - a).total_seconds() > frequency for a, b in zip(boundaries, boundaries[1:])):
                raise Unavailable('metric sample coverage has gaps')
            uses = [_number(get(s, 'usage')) for s in samples]
            baseline = get(record, 'baseline', dict)
            average, peak = _number(get(baseline, 'average')), _number(get(baseline, 'peak'))
            _text(get(baseline, 'approvalRecordId', str))
            if _date(get(baseline, 'approvedAt', str)) > now:
                raise Unavailable('baseline approval is future dated')
            # A complete approved baseline contradiction is already decisive;
            # unresolved forecast fields cannot erase that observed failure.
            if average != sum(uses) / len(uses) or peak != max(uses):
                failures.append({'resourceId': rid, 'reason': 'Approved baseline contradicts complete measured use'})
            forecast = get(record, 'forecast', dict)
            forecast_id = _text(get(forecast, 'id', str))
            issued = _date(get(forecast, 'issuedAt', str))
            if not end <= issued <= now:
                raise Unavailable('capacity forecast chronology unresolved')
            tolerance = _number(get(component, 'toleranceFraction'), positive=True)
            if tolerance > 1:
                raise Unavailable('invalid approved tolerance')
            scenarios_rows = list_of_objects(get(forecast, 'failureScenarios', list))
            scenario_ids = [_text(get(s, 'id', str)) for s in scenarios_rows]
            if set(scenario_ids) != scenarios or len(scenario_ids) != len(scenarios):
                raise Unavailable('failure-constrained forecast coverage incomplete')
            demands = [forecast, *scenarios_rows]
            breach = False
            for demand in demands:
                avg, maximum, capacity = _number(get(demand, 'average')), _number(get(demand, 'peak')), _number(get(demand, 'capacity'), positive=True)
                if avg > maximum:
                    raise Unavailable('forecast average exceeds peak')
                breach |= maximum > capacity * tolerance or avg > capacity * tolerance
            relevant = [c for c in changes if _arm(get(c, 'resourceId', str), scope) == rid
                        and get(c, 'forecastId', str) == forecast_id]
            for change in relevant:
                when = _date(get(change, 'initiatedAt', str))
                if not issued <= when <= now:
                    raise Unavailable('change initiation chronology unresolved')
                _text(get(change, 'changeManagementId', str))
            if breach:
                if not relevant:
                    failures.append({'resourceId': rid, 'reason': 'Forecast breaches tolerance without change initiation'})
        except Unavailable as exc:
            uncertain.append({'resourceId': rid, 'reason': str(exc)})
    if set(measured) - expected_ids:
        raise Unavailable('capacity records contain foreign policy components')
    if change_resources - expected_ids:
        raise Unavailable('capacity changes contain foreign policy components')
    return _aggregate(failures, uncertain, component_count=len(components))



def _gateway_consistent_timeline(claims):
    """Reject incompatible same-target health histories in O(segments log segments).

    Every claim begins inclusively. A transition ends the old state
    exclusively and starts the new one inclusively. The final window end
    remains inclusive, so observations at a shared endpoint agree.
    """
    for segments in claims.values():
        farthest = {'Healthy': None, 'Unhealthy': None}
        for begin, finish, end_inclusive, state in sorted(segments, key=lambda segment: segment[0]):
            other = farthest['Unhealthy' if state == 'Healthy' else 'Healthy']
            if other is not None and (other[0] > begin or other[0] == begin and other[1]):
                raise Unavailable('overlapping gateway target health histories contradict')
            edge = (finish, end_inclusive)
            if farthest[state] is None or edge > farthest[state]:
                farthest[state] = edge


def _gateway_health(index):
    scope = _scope(index)
    gateways = _rows(index, 'application_gateway')
    if not gateways:
        envelopes = get(index, 'collections', dict)['application_gateway']
        if any(get(e, 'status', str) != 'empty' or get(e, 'items', list) for e in envelopes):
            raise Unavailable('gateway absence requires an explicit empty inventory')
        return 'NOT_APPLICABLE', {'reason': 'No Application Gateways in complete subscription inventory'}
    policy, now = _policy(index, GATEWAY_ID), _now(index)
    start, end = _window(policy, now)
    latency = get(policy, 'maxAlertLatencySeconds', int)
    frequency = get(policy, 'evaluationIntervalSeconds', int)
    if latency <= 0 or frequency <= 0 or get(policy, 'targetDenominator', str) != 'totalTargetsAtWindowStart':
        raise Unavailable('gateway transition denominator/latency policy unresolved')
    for gateway in gateways:
        if 'type' in gateway and get(gateway, 'type', str).casefold() != ARM_TYPES['application_gateway'].casefold():
            raise Unavailable('gateway native type differs from ARM identity')
        proof = gateway.get('_provenance')
        if proof is not None and (not isinstance(proof, dict) or
                'read_only' in proof and get(proof, 'read_only', bool) is not True):
            raise Unavailable('gateway native observation is not read-only')
    if any(w.get('provider', 'azure') != 'azure' for w in get(index, 'application_gateway', list)):
        raise Unavailable('gateway native wrapper belongs to another provider')
    alerts = _alerts(index)
    for kind, alert in alerts:
        if 'type' in alert and get(alert, 'type', str).casefold() != ARM_TYPES[kind].casefold():
            raise Unavailable('alert native type differs from ARM identity')
    if not any(get(alert, 'properties.enabled', bool) for _, alert in alerts):
        return _aggregate([{'gatewayId': get(g, 'id', str).casefold(),
            'reason': 'Complete native alert inventories contain no enabled gateway alert rule'} for g in gateways], [],
            gateway_count=len(gateways), alert_count=len(alerts))
    groups = _groups(index)
    for group in _rows(index, 'action_group'):
        if 'type' in group and get(group, 'type', str).casefold() != ARM_TYPES['action_group'].casefold():
            raise Unavailable('action group native type differs from ARM identity')
    deliverable = False
    for kind, alert in alerts:
        props = get(alert, 'properties', dict)
        if not get(props, 'enabled', bool):
            continue
        routed = _group_ids(kind, props, scope)
        if any(group not in groups for group in routed):
            raise Unavailable('gateway action group unresolved')
        deliverable |= any(groups[group] for group in routed)
    if not deliverable:
        return _aggregate([{'gatewayId': get(g, 'id', str).casefold(),
            'reason': 'Complete native alert actions contain no enabled delivery group'} for g in gateways], [],
            gateway_count=len(gateways), alert_count=len(alerts))
    semantic_rows = _rows(index, 'gateway_alert_semantics')
    semantics = {get(s, 'alertId', str).casefold(): s for s in semantic_rows}
    if len(semantics) != len(semantic_rows):
        raise Unavailable('ambiguous gateway alert semantic proof')
    definitions = {get(a, 'id', str).casefold(): (kind, a) for kind, a in alerts}
    if set(semantics) - set(definitions):
        raise Unavailable('gateway semantic evidence belongs to absent alert')
    observations = _rows(index, 'gateway_health_evidence')
    by_gateway = {}
    for observation in observations:
        rid = _arm(get(observation, 'gatewayId', str), scope, ARM_TYPES['application_gateway'])
        if rid in by_gateway:
            raise Unavailable('duplicate gateway health evidence')
        by_gateway[rid] = observation
    if set(by_gateway) - {get(g, 'id', str).casefold() for g in gateways}:
        raise Unavailable('foreign gateway transition data')
    failures, uncertain = [], []
    for gateway in gateways:
        rid, matching, unresolved = get(gateway, 'id', str).casefold(), {}, False
        for aid, (kind, alert) in definitions.items():
            props = get(alert, 'properties', dict)
            if rid not in {s.casefold() for s in get(props, 'scopes', list)} or not get(props, 'enabled', bool):
                continue
            try:
                if aid not in semantics:
                    raise Unavailable('effective gateway rule semantics unresolved')
                semantic = semantics[aid]
                # Bind a read-only parser result to the actual native rule body.
                fingerprint = hashlib.sha256(json.dumps(props, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                if get(semantic, 'propertiesSha256', str) != fingerprint or get(semantic, 'parserVersion', str) != 'gateway-transition-v1':
                    raise Unavailable('rule semantic proof does not bind current declaration')
                parsed = get(semantic, 'criteria', dict)
                matches = (get(parsed, 'numerator', str) == 'healthyToUnhealthyTargets'
                           and get(parsed, 'denominator', str) == 'totalTargetsAtWindowStart'
                           and get(parsed, 'windowSeconds', int) == 300
                           and get(parsed, 'operator', str) == 'GreaterThan'
                           and _number(get(parsed, 'thresholdFraction')) == Decimal('0.1'))
                if not matches:
                    continue
                interval = get(semantic, 'evaluationFrequencySeconds', int)
                if interval <= 0:
                    raise Unavailable('gateway rule evaluation interval must be positive')
                if interval > latency:
                    continue
                routed = _group_ids(kind, props, scope)
                if any(g not in groups for g in routed):
                    raise Unavailable('gateway action group unresolved')
                enabled_groups = {g for g in routed if groups[g]}
                if enabled_groups:
                    matching[aid] = enabled_groups
            except Unavailable:
                unresolved = True
        if not matching:
            (uncertain if unresolved else failures).append({'gatewayId': rid, 'reason': 'No enabled effective five-minute >10% transition rule with enabled group'})
            continue
        try:
            if rid not in by_gateway:
                raise Unavailable('gateway transition/delivery data missing')
            evidence = by_gateway[rid]
            if _date(get(evidence, 'coverageStart', str)) != start or _date(get(evidence, 'coverageEnd', str)) != end:
                raise Unavailable('gateway health coverage belongs to another lookback')
            _coverage(evidence, 'windows'); _coverage(evidence, 'alertEvaluations')
            windows = list_of_objects(get(evidence, 'windows', list))
            if not windows:
                raise Unavailable('gateway transitions unmeasured')
            observed_ends = set()
            claims, claim_count = {}, 0
            for window in windows:
                begin, finish = _date(get(window, 'start', str)), _date(get(window, 'end', str))
                if (finish - begin).total_seconds() != 300 or not start <= begin < finish <= end or finish in observed_ends:
                    raise Unavailable('five-minute transition window unresolved')
                observed_ends.add(finish)
                targets = list_of_objects(get(window, 'targets', list))
                ids = [_text(get(t, 'id', str)) for t in targets]
                if not ids or len(set(ids)) != len(ids):
                    raise Unavailable('target denominator missing/ambiguous')
                if (set(_strings(get(window, 'startTargetIds', list))) != set(ids)
                        or set(_strings(get(window, 'endTargetIds', list))) != set(ids)):
                    raise Unavailable('backend membership/denominator changed or unresolved')
                changed = 0
                for target in targets:
                    before, after = get(target, 'startHealth', str), get(target, 'endHealth', str)
                    if before not in ('Healthy', 'Unhealthy') or after not in ('Healthy', 'Unhealthy'):
                        raise Unavailable('backend target health unresolved')
                    _coverage(target, 'transitions')
                    transitions = list_of_objects(get(target, 'transitions', list))
                    state, prior_time, unhealthy_transition = before, begin, False
                    segments = claims.setdefault(_text(get(target, 'id', str)), [])
                    for transition in transitions:
                        when = _date(get(transition, 'at', str))
                        from_state, to_state = get(transition, 'fromHealth', str), get(transition, 'toHealth', str)
                        if (not prior_time < when <= finish or from_state != state
                                or to_state not in ('Healthy', 'Unhealthy') or to_state == from_state):
                            raise Unavailable('backend transition chronology incomplete or malformed')
                        unhealthy_transition |= from_state == 'Healthy' and to_state == 'Unhealthy'
                        claim_count += 1
                        if claim_count > 100000 or len(segments) >= 10000:
                            raise Unavailable('gateway target timeline claim limit exceeded')
                        segments.append((prior_time, when, False, state))
                        prior_time, state = when, to_state
                    claim_count += 1
                    if claim_count > 100000 or len(segments) >= 10000:
                        raise Unavailable('gateway target timeline claim limit exceeded')
                    segments.append((prior_time, finish, True, state))
                    if state != after:
                        raise Unavailable('backend transition history disagrees with endpoint health')
                    changed += unhealthy_transition
                records = list_of_objects(get(window, 'alertEvaluations', list))
                if Decimal(changed) / len(targets) > Decimal('0.1'):
                    fired = False
                    for record in records:
                        aid = get(record, 'alertId', str).casefold()
                        if aid not in matching:
                            continue
                        issued = get(record, 'fired', bool)
                        if issued:
                            when = _date(get(record, 'firedAt', str))
                            group = _arm(get(record, 'actionGroupId', str), scope, ARM_TYPES['action_group'])
                            delivered = _date(get(record, 'deliveredAt', str))
                            if not finish <= when <= delivered <= now:
                                raise Unavailable('gateway firing/delivery chronology unresolved')
                            fired |= (group in matching[aid] and (when - finish).total_seconds() <= latency
                                      and (delivered - finish).total_seconds() <= latency)
                    if not fired:
                        failures.append({'gatewayId': rid, 'windowEnd': finish.isoformat(), 'reason': 'Measured >10% transition did not issue a timely delivered alert'})
            _gateway_consistent_timeline(claims)
            cursor = start + timedelta(seconds=300)
            expected_ends = set()
            while cursor <= end:
                expected_ends.add(cursor); cursor += timedelta(seconds=frequency)
            if not expected_ends or observed_ends != expected_ends:
                raise Unavailable('rolling transition window coverage incomplete')
        except Unavailable as exc:
            uncertain.append({'gatewayId': rid, 'reason': str(exc)})
    return _aggregate(failures, uncertain, gateway_count=len(gateways))


