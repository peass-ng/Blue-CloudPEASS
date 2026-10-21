"""Strict Policy Analyzer observation projection; no SDK or registry imports."""
from datetime import datetime, timezone
import re

ACTIVITY_TYPES = {'service_account': 'serviceAccountLastAuthentication',
                  'service_account_key': 'serviceAccountKeyLastAuthentication'}
INSIGHT_KIND = 'service_account_insight'
INSIGHT_TYPE = 'google.iam.serviceAccount.Insight'


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('activity timestamp is unavailable')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('activity timestamp lacks timezone')
    return parsed.astimezone(timezone.utc)


def project_activity(row, scope, kind, project_tokens):
    if not isinstance(row, dict) or row.get('activityType') != ACTIVITY_TYPES[kind]:
        raise ValueError('activity type differs from the requested native resource')
    name = row.get('fullResourceName')
    suffix = r'/keys/[^/?#]+' if kind == 'service_account_key' else ''
    match = re.fullmatch(r'//iam\.googleapis\.com/projects/([^/?#]+)/serviceAccounts/[^/?#]+' + suffix, name or '')
    if not match or match.group(1) not in project_tokens:
        raise ValueError('activity resource belongs to a different project')
    period, body = row.get('observationPeriod'), row.get('activity')
    if not isinstance(period, dict) or not isinstance(body, dict):
        raise ValueError('activity observation period is unavailable')
    start, end = timestamp(period.get('startTime')), timestamp(period.get('endTime'))
    if start >= end:
        raise ValueError('activity observation period is contradictory')
    last = body.get('lastAuthenticatedTime')
    if last is not None and timestamp(last) > end:
        raise ValueError('activity date is later than its observation period')
    fact = {'observationStartTime': period['startTime'], 'observationEndTime': period['endTime'],
            'resource_name': name.removeprefix('//iam.googleapis.com/'),
            'activity_type': row['activityType'], 'project_scope': scope}
    if kind == 'service_account':
        identity = body.get('serviceAccount')
        uid = identity.get('serviceAccountId') if isinstance(identity, dict) else None
        if not isinstance(uid, str) or not re.fullmatch(r'[1-9][0-9]{5,30}', uid):
            raise ValueError('activity immutable service account identity is unavailable')
        fact['service_account_id'] = uid
    if last is not None:
        fact['lastAuthenticatedTime'] = last
    return fact
