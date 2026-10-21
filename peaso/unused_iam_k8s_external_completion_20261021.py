"""Positive, cluster-bound audit observations for external RBAC subjects."""
from __future__ import annotations

from datetime import datetime, timezone


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError('missing timestamp')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timestamp lacks timezone')
    return result.astimezone(timezone.utc)


def evaluate_subject_use(subject, events, *, cluster_id, source_cluster_id,
                         captured_at, source_status, source_requests=()):
    """Recognize a successful API request by an exact User or Group subject.

    No audit event can establish that this particular binding authorized the
    request; that requires authorization decision evidence outside Event.UserInfo.
    Empty/failed audit history never establishes an unused subject.
    """
    kind, name = subject.get('kind'), subject.get('name')
    if kind not in ('User', 'Group') or not isinstance(name, str) or not name:
        return 'UNKNOWN', {'reason': 'external subject identity is unavailable'}
    if not cluster_id or cluster_id != source_cluster_id:
        return 'UNKNOWN', {'reason': 'audit source belongs to another cluster'}
    if not isinstance(events, list) or not source_requests:
        return 'UNKNOWN', {'reason': 'cluster audit history is unavailable or partial'}
    try:
        now = _timestamp(captured_at)
    except (ValueError, TypeError):
        return 'UNKNOWN', {'reason': 'capture time is unavailable'}
    matches = []
    for event in events:
        if not isinstance(event, dict):
            return 'UNKNOWN', {'reason': 'audit event is malformed'}
        if event.get('apiVersion') != 'audit.k8s.io/v1' or event.get('stage') != 'ResponseComplete':
            continue
        # A request made with impersonation establishes the impersonated name's
        # activity, not activity by the original credential behind event.user.
        if event.get('impersonatedUser'):
            continue
        user, response = event.get('user'), event.get('responseStatus')
        if not isinstance(user, dict) or not isinstance(response, dict):
            continue
        code = response.get('code')
        if type(code) is not int or not 200 <= code < 300:
            continue
        observed = (user.get('username') == name if kind == 'User'
                    else isinstance(user.get('groups'), list) and name in user['groups'])
        if not observed:
            continue
        try:
            when = _timestamp(event.get('stageTimestamp'))
        except (ValueError, TypeError):
            return 'UNKNOWN', {'reason': 'matching audit event time is unavailable'}
        if when > now:
            return 'UNKNOWN', {'reason': 'audit event time is after capture'}
        matches.append(when)
    if matches:
        last = max(matches)
        return 'PASS', {'subject_kind': kind, 'subject_name': name,
                        'last_successful_api_request': last.isoformat(), 'cluster_id': cluster_id,
                        'source_requests': list(source_requests),
                        'summary': f'External {kind} {name} appears in a successful Kubernetes API request on {last.date().isoformat()}.\n'
                                   'The audit event is bound to this cluster and authenticated subject.\n'
                                   'It does not identify which RBAC binding authorized the request.'}
    if source_status == 'denied':
        return 'DENIED', {'reason': 'cluster audit source was denied'}
    if source_status not in ('collected', 'empty'):
        return 'UNKNOWN', {'reason': 'cluster audit history is unavailable or partial'}
    return 'UNKNOWN', {'subject_kind': kind, 'subject_name': name,
                       'reason': 'no successful matching audit event; audit coverage and retention do not prove inactivity'}
