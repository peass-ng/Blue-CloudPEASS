"""Metadata-only credential metric queries; no SDK, collector or registry imports."""
from datetime import timedelta
import json
import re

API = 'api_key_usage'
HMAC = 'storage_hmac_key_usage'
PARENTS = {API: 'api_key', HMAC: 'storage_hmac_key'}
METRICS = {API: 'serviceruntime.googleapis.com/api/request_count', HMAC: 'storage.googleapis.com/authn/authentication_count'}
RESOURCES = {API: 'consumed_api', HMAC: 'gcs_bucket'}
MAX_POINTS = 200000
WINDOW_DAYS = 365
LAG = timedelta(minutes=30)


def credential_id(item, kind):
    field = 'uid' if kind == API else 'accessId'
    value = item.get(field)
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', value):
        raise ValueError('native credential metadata identifier is unavailable')
    return value


def parameters(kind, project_id, ident, start, end):
    if not re.fullmatch(r'[a-z][a-z0-9-]{4,28}[a-z0-9]', project_id):
        raise ValueError('metric project identity is unavailable')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', ident):
        raise ValueError('metric credential identity is unavailable')
    selector = 'resource.labels.credential_id' if kind == API else 'metric.labels.access_id'
    value = 'apikey:'+ident if kind == API else ident
    clauses = [f'metric.type={json.dumps(METRICS[kind])}', f'resource.type={json.dumps(RESOURCES[kind])}',
               f'project={json.dumps(project_id)}', f'{selector}={json.dumps(value)}']
    if kind == HMAC:
        clauses.append('metric.labels.authentication_method="HMAC"')
    groups = ['resource.labels.project_id']
    if kind == API:
        groups += ['resource.labels.credential_id', 'metric.labels.response_code_class']
    else:
        groups += ['metric.labels.access_id', 'metric.labels.authentication_method', 'metric.labels.response_code']
    return {'filter': ' AND '.join(clauses), 'interval.startTime': start, 'interval.endTime': end,
            'view': 'FULL', 'aggregation.alignmentPeriod': '86400s',
            'aggregation.perSeriesAligner': 'ALIGN_SUM', 'aggregation.crossSeriesReducer': 'REDUCE_SUM',
            'aggregation.groupByFields': groups}
