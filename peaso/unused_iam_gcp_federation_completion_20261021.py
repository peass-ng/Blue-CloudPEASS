"""Evaluate positive STS token-exchange audit evidence for federation providers.

Cloud Audit Logs are opt-in and retention-bounded. An empty read is never an
inactivity finding, even when the requested log pages are complete.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re


def _time(value):
    if not isinstance(value, str):
        raise ValueError('missing timestamp')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timestamp lacks timezone')
    return result.astimezone(timezone.utc)


def evaluate_provider_use(provider_name, entries, *, read_status, captured_at,
                          source_requests=(), scope=None):
    """Return PASS for a bound successful exchange, otherwise UNKNOWN/DENIED.

    The caller must supply entries from a read-only, paginated Cloud Logging
    entries:list read scoped to the relevant project or organization. This
    deliberately has no FAIL path: missing events do not prove inactivity.
    """
    if not isinstance(provider_name, str) or not re.fullmatch(
            r'(?:projects/[^/]+/locations/global/workloadIdentityPools/[^/]+|'
            r'locations/global/workforcePools/[^/]+)/providers/[^/]+', provider_name):
        return 'UNKNOWN', {'reason': 'provider identity is malformed'}
    if not isinstance(entries, list):
        return 'UNKNOWN', {'reason': 'federation audit inventory is malformed'}
    if not source_requests or not isinstance(scope, str) or not scope:
        return 'UNKNOWN', {'reason': 'audit request provenance is unavailable'}
    try:
        now = _time(captured_at)
    except (ValueError, TypeError):
        return 'UNKNOWN', {'reason': 'capture time is unavailable'}
    matches = []
    for entry in entries:
        if not isinstance(entry, dict):
            return 'UNKNOWN', {'reason': 'audit entry is malformed'}
        payload = entry.get('protoPayload')
        if not isinstance(payload, dict) or payload.get('resourceName') != provider_name:
            continue
        if entry.get('logName') != scope + '/logs/cloudaudit.googleapis.com%2Fdata_access':
            continue
        if payload.get('methodName') not in (
                'google.identity.sts.v1.SecurityTokenService.ExchangeToken',
                'google.identity.sts.v1beta.SecurityTokenService.ExchangeToken',
                'google.identity.sts.SecurityTokenService.ExchangeToken'):
            continue
        status = payload.get('status')
        if status not in (None, {}):
            continue
        try:
            when = _time(entry.get('timestamp'))
        except (ValueError, TypeError):
            return 'UNKNOWN', {'reason': 'matching exchange time is unavailable'}
        if when > now:
            return 'UNKNOWN', {'reason': 'exchange time is after capture'}
        matches.append(when)
    if matches:
        last = max(matches)
        return 'PASS', {'provider_name': provider_name, 'last_successful_exchange': last.isoformat(),
                        'source_scope': scope, 'source_requests': list(source_requests),
                        'summary': f'{provider_name} has a successful token exchange recorded on {last.date().isoformat()}.\n'
                                   'The STS audit event names this exact provider and a successful request.\n'
                                   'This is observed federation use within the available log history.'}
    if read_status == 'denied':
        return 'DENIED', {'reason': 'federation token-exchange audit read was denied'}
    if read_status not in ('collected', 'empty'):
        return 'UNKNOWN', {'reason': 'federation audit inventory is incomplete'}
    return 'UNKNOWN', {'provider_name': provider_name,
                       'reason': 'no successful exchange in available logs; logging or retention may be incomplete',
                       'source_scope': scope, 'source_requests': list(source_requests)}
