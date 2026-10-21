"""Opt-in, bounded Cloud Logging read for STS exchange evidence."""
from __future__ import annotations

from datetime import datetime
import re

ENDPOINT = 'https://logging.googleapis.com/v2/entries:list'


def read_provider_exchanges(collector, provider_name, scope, *, start, end):
    """Read every page for an exact provider and interval, preserving receipts.

    The caller supplies the authorized log source. A project source covers only
    that project's logs; a workforce organization needs its organization source.
    """
    from .gcp import ReadError
    if not re.fullmatch(r'(?:projects|organizations)/[^/]+', scope):
        raise ValueError('one exact project or organization log source is required')
    if not re.fullmatch(r'(?:projects/[^/]+/locations/global/workloadIdentityPools/[^/]+|locations/global/workforcePools/[^/]+)/providers/[^/]+', provider_name):
        raise ValueError('provider identity is malformed')
    try:
        bounds = [datetime.fromisoformat(value.replace('Z', '+00:00')) for value in (start, end)]
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError('explicit timezone-aware interval is required') from exc
    if any(value.tzinfo is None for value in bounds):
        raise ValueError('explicit timezone-aware interval is required')
    if bounds[0] >= bounds[1]:
        raise ValueError('log interval must increase')
    # Cloud Logging query string literals use quoted JSON-style escaping.
    import json
    filter_text = ('logName=' + json.dumps(scope + '/logs/cloudaudit.googleapis.com%2Fdata_access')
                   + ' AND protoPayload.resourceName=' + json.dumps(provider_name)
                   + ' AND (protoPayload.methodName="google.identity.sts.v1.SecurityTokenService.ExchangeToken"'
                   + ' OR protoPayload.methodName="google.identity.sts.v1beta.SecurityTokenService.ExchangeToken")'
                   + ' AND timestamp>=' + json.dumps(start) + ' AND timestamp<=' + json.dumps(end))
    rows, refs, token, seen = [], [], None, set()
    try:
        while True:
            if len(refs) >= 1000:
                raise ReadError('partial', 'federation_audit_page_limit')
            body = {'resourceNames': [scope], 'filter': filter_text, 'orderBy': 'timestamp desc', 'pageSize': 1000}
            if token:
                body['pageToken'] = token
            response, ref = collector.read(ENDPOINT, scope, method='POST', body=body)
            refs.append(ref)
            if not isinstance(response, dict) or not isinstance(response.get('entries', []), list):
                raise ReadError('malformed', 'federation_audit_response_malformed')
            rows.extend(response.get('entries', []))
            next_token = response.get('nextPageToken')
            if not next_token:
                return {'status': 'collected' if rows else 'empty', 'entries': rows,
                        'source_scope': scope, 'source_requests': refs,
                        'query_interval': {'start': start, 'end': end}}
            if not isinstance(next_token, str) or next_token in seen:
                raise ReadError('malformed', 'federation_audit_pagination_cycle')
            seen.add(next_token)
            token = next_token
    except ReadError as exc:
        return {'status': exc.status, 'entries': rows, 'source_scope': scope,
                'source_requests': refs + ([exc.request_id] if getattr(exc, 'request_id', None) else []),
                'query_interval': {'start': start, 'end': end}, 'error': exc.error}
