"""Explicit query approvals and native aggregate-only table ingestion evidence.

Approvals are operator decisions, never claims that Azure measured query
semantics. Logs receipts come only from fixed read-only aggregate requests.
https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import math
import re

CID = 'azure.other.security_event_correlation'
KEY = CID.replace('.', '|')
NATIVE_TYPES = {'security_query_review', 'security_table_ingestion'}
ARM = 'https://management.azure.com'
LOGS = 'https://api.loganalytics.io'
API = 'https://api.loganalytics.azure.com/v1/workspaces/'
GUID = r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
SCOPE = re.compile(r'/subscriptions/[A-Za-z0-9._-]{1,128}', re.I)


def instant(value):
    if not isinstance(value, str): raise ValueError('timestamp required')
    date = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if date.utcoffset() is None: raise ValueError('timestamp timezone required')
    return date


def _text(value):
    if (not isinstance(value, str) or not value.strip() or value != value.strip()
            or len(value) > 2048 or any(ord(c) < 32 for c in value)):
        raise ValueError('invalid approval text')
    return value


def _strings(value, *, minimum=1, maximum=64):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError('invalid approval list')
    for item in value: _text(item)
    if len({item.casefold() for item in value}) != len(value):
        raise ValueError('duplicate approval list entry')
    return value


def _arm(value, scope, native_type):
    _text(value)
    if (any(c in value for c in '%?#\\') or any(part in {'.', '..'} for part in value.split('/'))
            or re.fullmatch(re.escape(scope) + r'/resourceGroups/[^/?#\s]+/providers/' +
                    re.escape(native_type) + r'/[^/?#\s]+', value, re.I) is None):
        raise ValueError('approval resource scope or type mismatch')


def normalize(review):
    """Validate only approved requirements, never accept ingestion outcomes."""
    from peaso.server.native_policy_validation import bounded
    bounded(review)
    fields = {'status', 'scope', 'authorized_by', 'document_id', 'observed_at', 'expires_at', 'checks'}
    if set(review) != fields or review['status'] != 'collected' or not SCOPE.fullmatch(str(review['scope'])):
        raise ValueError('unscoped correlation review')
    for field in ('authorized_by', 'document_id'): _text(review[field])
    if instant(review['observed_at']) >= instant(review['expires_at']):
        raise ValueError('approval must precede expiry')
    checks = review['checks']
    if not isinstance(checks, dict) or set(checks) != {KEY}:
        raise ValueError('unsupported correlation review check')
    config = checks[KEY]
    required = {'requiredWorkspaceIds', 'requiredEventTables', 'requiredCorrelationFragments',
                'maxCorrelationWindowSeconds', 'approvedCriteria', 'approvedQueryReviews',
                'ingestionLookbackSeconds', 'ingestionMaxAgeSeconds'}
    if not isinstance(config, dict) or set(config) != required:
        raise ValueError('unsupported correlation requirements')
    for field in ('ingestionLookbackSeconds', 'ingestionMaxAgeSeconds', 'maxCorrelationWindowSeconds'):
        if type(config[field]) is not int or not 1 <= config[field] <= 86400:
            raise ValueError('invalid correlation measurement window')
    if config['ingestionMaxAgeSeconds'] > config['ingestionLookbackSeconds']:
        raise ValueError('ingestion age exceeds observation window')
    for workspace in _strings(config['requiredWorkspaceIds'], maximum=16):
        _arm(workspace, review['scope'], 'Microsoft.OperationalInsights/workspaces')
    for table in _strings(config['requiredEventTables'], minimum=3, maximum=32):
        if re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,127}', table) is None:
            raise ValueError('invalid event table identifier')
    _strings(config['requiredCorrelationFragments'], maximum=32)
    criteria = config['approvedCriteria']
    if not isinstance(criteria, list) or not 1 <= len(criteria) <= 32:
        raise ValueError('missing approved criteria')
    for criterion in criteria:
        if (not isinstance(criterion, dict) or set(criterion) != {'operator', 'threshold', 'timeAggregation'}
                or criterion['operator'] not in {'GreaterThan', 'GreaterThanOrEqual', 'LessThan', 'LessThanOrEqual', 'Equal', 'Equals'}
                or criterion['timeAggregation'] not in {'Count', 'Average', 'Minimum', 'Maximum', 'Total'}
                or type(criterion['threshold']) not in (int, float) or not math.isfinite(criterion['threshold'])):
            raise ValueError('invalid approved correlation criterion')
    approvals, seen = config['approvedQueryReviews'], set()
    if not isinstance(approvals, list) or not 1 <= len(approvals) <= 64:
        raise ValueError('explicit query reviews required')
    for approval in approvals:
        if (not isinstance(approval, dict) or set(approval) != {'ruleId', 'querySha256', 'correlatedTables', 'approved'}
                or type(approval['approved']) is not bool
                or not isinstance(approval['querySha256'], str)
                or re.fullmatch('[0-9a-f]{64}', approval['querySha256']) is None):
            raise ValueError('invalid query approval')
        _arm(approval['ruleId'], review['scope'], 'Microsoft.Insights/scheduledQueryRules')
        _strings(approval['correlatedTables'], minimum=3, maximum=32)
        if any(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,127}', t) is None for t in approval['correlatedTables']):
            raise ValueError('invalid reviewed table identifier')
        key = approval['ruleId'].casefold(), approval['querySha256']
        if key in seen: raise ValueError('duplicate query approval')
        seen.add(key)
    return deepcopy(review)


def _approval(options, scope):
    raw = options.get('compliance_policy', {}).get('sw13')
    if not isinstance(raw, dict) or KEY not in raw.get('checks', {}):
        from .azure import AzureReadError
        raise AzureReadError('security_correlation_review_unavailable')
    review = normalize(raw)
    if review['scope'].casefold() != scope.casefold():
        raise ValueError('foreign correlation review')
    now = datetime.now(timezone.utc)
    if not instant(review['observed_at']) <= now <= instant(review['expires_at']):
        from .azure import AzureReadError
        raise AzureReadError('security_correlation_review_not_current')
    return review


def _aggregate(response, start, end):
    if not isinstance(response, dict) or 'error' in response or 'partialError' in response:
        raise ValueError('partial Logs ingestion response')
    tables = response.get('tables')
    if not isinstance(tables, list) or len(tables) != 1 or not isinstance(tables[0], dict):
        raise ValueError('invalid Logs ingestion table')
    table = tables[0]
    columns, rows = table.get('columns'), table.get('rows')
    expected = [('event_count', 'long'), ('last_ingested_at', 'datetime'), ('last_event_at', 'datetime')]
    if (not isinstance(columns, list) or any(not isinstance(c, dict) for c in columns)
            or [(c.get('name'), c.get('type')) for c in columns] != expected
            or not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], list) or len(rows[0]) != 3):
        raise ValueError('invalid Logs ingestion aggregate')
    count, ingested, event = rows[0]
    if type(count) is not int or count < 0: raise ValueError('invalid Logs event count')
    if count:
        if any(not start <= instant(date) <= end for date in (ingested, event)):
            raise ValueError('ingestion timestamp outside query window')
    elif ingested is not None or event is not None:
        raise ValueError('empty ingestion contradicts timestamps')
    return count, ingested, event


def collect(reader, request, scopes, wanted, options):
    if not NATIVE_TYPES.intersection(wanted): return
    review = options.get('compliance_policy', {}).get('sw13')
    if (not isinstance(review, dict) or not isinstance(review.get('checks'), dict)
            or KEY not in review['checks']):
        for scope in scopes:
            for kind in sorted(NATIVE_TYPES.intersection(wanted)):
                reader.collections.append({'type': kind, 'scope': scope,
                    'service': 'security_correlation', 'status': 'not_collected', 'items': [],
                    'error': {'code': 'security_correlation_review_unavailable'}})
        return
    jobs = []
    for scope in scopes:
        if 'security_query_review' in wanted:
            def reviews(scope=scope):
                review = _approval(options, scope)
                header = {k: review[k] for k in ('authorized_by', 'document_id', 'observed_at', 'expires_at')}
                for approval in review['checks'][KEY]['approvedQueryReviews']:
                    digest = hashlib.sha256((approval['ruleId'].casefold() + approval['querySha256']).encode()).hexdigest()
                    yield [{'id': scope + '/providers/BlueCloudPEASS/securityQueryReviews/' + digest,
                        'scope': scope, **deepcopy(approval), **header,
                        '_provenance': {'read_only': True, 'authority': 'operator_approval',
                            'source_operation': 'explicit_query_review', 'cloud_semantics_measured': False}}]
            jobs.append(('security_query_review', scope, 'operator_query_approval', reviews))
        if 'security_table_ingestion' in wanted:
            def ingestion(scope=scope):
                review = _approval(options, scope)
                config = review['checks'][KEY]
                for workspace in config['requiredWorkspaceIds']:
                    detail = reader.call(request, ARM + workspace + '?api-version=2022-10-01')
                    if (not isinstance(detail, dict) or str(detail.get('id', '')).casefold() != workspace.casefold()
                            or str(detail.get('type', '')).casefold() != 'microsoft.operationalinsights/workspaces'):
                        raise ValueError('workspace identity unresolved')
                    customer = detail.get('properties', {}).get('customerId')
                    if not isinstance(customer, str) or re.fullmatch(GUID, customer) is None:
                        raise ValueError('workspace customer identity unresolved')
                    for table in config['requiredEventTables']:
                        end = datetime.now(timezone.utc)
                        start = end - timedelta(seconds=config['ingestionLookbackSeconds'])
                        query = (table + ' | where TimeGenerated between (datetime(' + start.isoformat()
                            + ') .. datetime(' + end.isoformat() + ')) | summarize event_count=count(), '
                            'last_ingested_at=max(ingestion_time()), last_event_at=max(TimeGenerated)')
                        response = reader.call(request, API + customer + '/query', audience=LOGS,
                            body={'query': query, 'timespan': start.isoformat() + '/' + end.isoformat()})
                        count, ingested, event = _aggregate(response, start, end)
                        fresh = bool(count) and (end - instant(ingested)).total_seconds() <= config['ingestionMaxAgeSeconds']
                        digest = hashlib.sha256(query.encode()).hexdigest()
                        yield [{'id': workspace + '/providers/BlueCloudPEASS/tableIngestion/' + table,
                            'scope': scope, 'workspaceId': workspace, 'tableName': table,
                            'ingestionConfirmed': fresh, 'eventCount': count,
                            'lastIngestedAt': ingested, 'lastEventAt': event,
                            'document_id': 'logs-query:' + digest, 'authorized_by': 'azure-monitor-logs-response',
                            'observed_at': end.isoformat(),
                            'expires_at': (end + timedelta(seconds=config['ingestionMaxAgeSeconds'])).isoformat(),
                            '_provenance': {'read_only': True, 'source_operation': 'Logs_Query',
                                'query_sha256': digest, 'workspace_customer_id': customer,
                                'native_response_complete': True, 'event_payload_retained': False}}]
            jobs.append(('security_table_ingestion', scope, 'Microsoft.OperationalInsights', ingestion))
    reader.run(jobs)
