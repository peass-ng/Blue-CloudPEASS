"""Effective Entra subject, recurring schedule, instance and decision joins."""
from __future__ import annotations

from . import result, unknown
from .facts import Unavailable, get, list_of_objects, optional
from datetime import timedelta
from .compliance_new_sw25_facts import (
    GUEST_PRIV_ID, MONTHLY_ID, REGULAR_ID, NONPRIV_ID, PRIV_ID, TENANT_ID,
    _text, _strings, _date, _policy, _now, _rows, _coverage, _aggregate,
)

# Access reviews use native Graph review/instance/decision rows, plus collector-
# resolved effective subjects, scope membership and due-window enumerations.
# These are facts about joins/schedules, never a precomputed compliant flag.
def _cadence(definition, maximum_days=None, monthly=False):
    recurrence = get(definition, 'settings.recurrence', dict)
    pattern = get(recurrence, 'pattern', dict)
    kind, interval = get(pattern, 'type', str), get(pattern, 'interval', int)
    if interval <= 0:
        raise Unavailable('invalid review recurrence interval')
    if kind == 'daily':
        days = interval
    elif kind == 'weekly':
        days = 7 * interval
    elif kind in ('absoluteMonthly', 'relativeMonthly'):
        days = 31 * interval
    elif kind in ('absoluteYearly', 'relativeYearly'):
        days = 366 * interval
    else:
        raise Unavailable('unsupported recurrence')
    if monthly:
        return kind in ('absoluteMonthly', 'relativeMonthly') and interval == 1 or kind in ('daily', 'weekly') and days <= 28
    # A three-calendar-month cadence can exceed 90 days, so only proven bounded
    # intervals pass a 90-day requirement. Collector due windows refine this.
    return maximum_days is None or days <= maximum_days


def _review_scope(definition, now, start):
    _coverage(definition, 'instances')
    scope = get(definition, '_resolvedScope', dict)
    if get(scope, 'status', str) != 'collected':
        raise Unavailable('review effective scope unresolved')
    members = set(_strings(get(scope, 'subjectIds', list)))
    excluded = set(_strings(get(scope, 'excludedSubjectIds', list)))
    if not excluded <= members:
        raise Unavailable('review exclusions not resolved against subject inventory')
    schedule = get(definition, '_resolvedSchedule', dict)
    if get(schedule, 'status', str) != 'collected':
        raise Unavailable('review due-window resolution incomplete')
    if _date(get(schedule, 'coverageStart', str)) > start or _date(get(schedule, 'coverageEnd', str)) < now:
        raise Unavailable('review schedule evidence does not cover required history')
    active_start = _date(get(schedule, 'activeStart', str))
    active_end = get(schedule, 'activeEnd')
    if active_end is not None:
        active_end = _date(active_end)
        if active_end < active_start:
            raise Unavailable('invalid current review schedule')
    if active_start > now or active_end is not None and active_end < now:
        return set(), []
    windows = list_of_objects(get(schedule, 'dueWindows', list))
    seen = set()
    for window in windows:
        wid = _text(get(window, 'instanceId', str))
        if not set(_strings(get(window, 'subjectIds', list))) <= members:
            raise Unavailable('due window has an unresolved principal/assignment scope')
        begin, end = _date(get(window, 'startDateTime', str)), _date(get(window, 'endDateTime', str))
        if wid in seen or begin >= end:
            raise Unavailable('duplicate/invalid due window')
        seen.add(wid)
    return members - excluded, windows


def _review_decision(decisions, instance, subject, tenant_creator, window=None):
    matches = [d for d in decisions if get(d, 'instanceId', str) == get(instance, 'id', str)
               and get(d, 'principal.id', str) == get(subject, 'principalId', str)
               and get(d, '_subjectId', str) == get(subject, 'id', str)]
    if not matches:
        return False
    if len(matches) != 1:
        raise Unavailable('ambiguous assignment/principal review decision')
    decision = matches[0]
    state = get(decision, 'decision', str)
    if state == 'NotReviewed':
        return False
    if state not in ('Approve', 'Deny', 'DontKnow'):
        raise Unavailable('unrecognized decision state')
    reviewed = _date(get(decision, 'reviewedDateTime', str))
    reviewer = _text(get(decision, 'reviewedBy.id', str))
    if not reviewer or reviewed > _date(get(instance, 'completedDateTime', str)):
        raise Unavailable('decision completion chronology unresolved')
    if window is not None and not window[0] <= reviewed <= window[1]:
        return False
    if tenant_creator:
        return state == 'Approve'
    return True


def _reviews(cid, index):
    policy = _policy(index, cid)
    now = _now(index)
    age = 90 if cid == NONPRIV_ID else 31 if cid == MONTHLY_ID else get(policy, 'reviewMaxAgeDays' if cid == TENANT_ID else 'maxReviewAgeDays', int)
    if age <= 0:
        raise Unavailable('invalid review-age policy')
    start = now - timedelta(days=age)
    subjects = _rows(index, 'access_review_subject', graph=True)
    applicable, classification_unknown = [], []
    for subject in subjects:
        try:
            state = get(subject, 'grantState', str)
            role = get(subject, 'roleClass', str)
            guest = get(subject, 'userType', str)
            enabled = get(subject, 'accountEnabled', bool)
            _text(get(subject, 'principalId', str))
            if state not in ('Active', 'Eligible', 'None') or role not in ('privileged', 'nonPrivileged', 'tenantCreator', 'none') or guest not in ('Guest', 'Member', 'ServicePrincipal'):
                raise Unavailable('effective assignment classification unresolved')
            if role != 'none':
                _text(get(subject, 'assignmentId', str)); _text(get(subject, 'roleDefinitionId', str))
        except Unavailable:
            if cid != TENANT_ID:
                raise
            classification_unknown.append(get(subject, 'id', str))
            continue
        selected = ((cid in (MONTHLY_ID, REGULAR_ID) and role == 'none' and guest == 'Guest' and (enabled or cid == REGULAR_ID))
                    or cid == GUEST_PRIV_ID and role == 'privileged' and state == 'Active' and guest == 'Guest'
                    or cid == PRIV_ID and role == 'privileged' and state in ('Active', 'Eligible')
                    or cid == NONPRIV_ID and role == 'nonPrivileged' and state == 'Active'
                    or cid == TENANT_ID and role == 'tenantCreator' and state == 'Active')
        if selected:
            applicable.append(subject)
    if not applicable:
        if classification_unknown:
            return unknown('Tenant Creator assignment classification unresolved')
        if cid == NONPRIV_ID:
            return result(False, applicable_subject_count=0)
        return 'NOT_APPLICABLE', {'reason': 'Complete effective subject inventory has no applicable users/assignments'}
    definitions = _rows(index, 'access_review_definition', graph=True)
    instances = _rows(index, 'access_review_instance', graph=True)
    decisions = _rows(index, 'access_review_decision', graph=True)
    dids = {get(d, 'id', str) for d in definitions}
    iids = {get(i, 'id', str) for i in instances}
    if any(get(i, 'definitionId', str) not in dids for i in instances) or any(get(d, 'instanceId', str) not in iids for d in decisions):
        raise Unavailable('foreign review child or decision')
    failures, uncertain = [], classification_unknown[:]
    for subject in applicable:
        sid = get(subject, 'id', str)
        matched, unresolved, denied_active = False, False, False
        for definition in definitions:
            try:
                members, due = _review_scope(definition, now, start)
                if not members <= {get(s, 'id', str) for s in subjects}:
                    raise Unavailable('review scope contains unresolved foreign subjects')
                if sid not in members:
                    continue
                status = get(definition, 'status', str)
                if status not in ('InProgress', 'Completed', 'NotStarted', 'Applied', 'Applying', 'Scheduled'):
                    raise Unavailable('review definition state unresolved')
                cadence_bound = age if cid in (NONPRIV_ID, GUEST_PRIV_ID) else None
                if not _cadence(definition, cadence_bound, cid == MONTHLY_ID):
                    continue
                children = [i for i in instances if get(i, 'definitionId', str) == get(definition, 'id', str)]
                due_windows = [w for w in due if sid in get(w, 'subjectIds', list) and _date(get(w, 'endDateTime', str)) <= now]
                if cid in (MONTHLY_ID, GUEST_PRIV_ID):
                    if not due_windows:
                        raise Unavailable('no due boundary observed in required interval')
                    latest = max(due_windows, key=lambda w: _date(get(w, 'endDateTime', str)))
                    if _date(get(latest, 'endDateTime', str)) < start:
                        continue
                    latest_windows = [w for w in due_windows if _date(get(w, 'endDateTime', str)) == _date(get(latest, 'endDateTime', str))]
                    candidates = [i for i in children if get(i, 'id', str) in {get(w, 'instanceId', str) for w in latest_windows}]
                else:
                    completed_children = []
                    for child in children:
                        state = get(child, 'status', str)
                        if state not in ('Completed', 'InProgress', 'NotStarted', 'Applied', 'Applying'):
                            raise Unavailable('review instance state unresolved')
                        if state == 'Completed':
                            completed_children.append(child)
                    candidates = sorted(completed_children, key=lambda i: _date(get(i, 'completedDateTime', str)), reverse=True)[:1]
                for instance in candidates:
                    state = get(instance, 'status', str)
                    if state not in ('Completed', 'InProgress', 'NotStarted', 'Applied', 'Applying'):
                        raise Unavailable('review instance state unresolved')
                    if state != 'Completed':
                        continue
                    _coverage(instance, 'decisions')
                    completed = _date(get(instance, 'completedDateTime', str))
                    if not start <= completed <= now:
                        continue
                    window = (start, now)
                    if cid in (MONTHLY_ID, GUEST_PRIV_ID):
                        latest = next(w for w in latest_windows if get(w, 'instanceId', str) == get(instance, 'id', str))
                        window = (_date(get(latest, 'startDateTime', str)), _date(get(latest, 'endDateTime', str)))
                        if not window[0] <= completed <= window[1]:
                            continue
                    if _review_decision(decisions, instance, subject, cid == TENANT_ID, window):
                        matched = True
                    elif cid == TENANT_ID:
                        exact = [d for d in decisions if get(d, 'instanceId', str) == get(instance, 'id', str)
                                 and get(d, '_subjectId', str) == sid and get(d, 'principal.id', str) == get(subject, 'principalId', str)]
                        denied_active |= any(get(d, 'decision', str) == 'Deny' for d in exact)
            except Unavailable:
                unresolved = True
        if denied_active:
            failures.append({'subjectId': sid, 'reason': 'Active Tenant Creator grant retained after denial'})
        elif matched:
            continue
        elif unresolved:
            uncertain.append(sid)
        else:
            failures.append({'subjectId': sid, 'reason': 'No timely recurring completed principal/assignment review'})
    return _aggregate(failures, uncertain, applicable_subject_count=len(applicable))


