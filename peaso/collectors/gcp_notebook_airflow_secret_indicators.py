"""Transient scans of existing Composer v1 / Workbench v2 JSON, before cache.

No transport, credential access, reference download, script execution or managed
secret access occurs here. The integration must call only on successful original
unmasked JSON, and share new_budget() across transport responses in one run.
"""
from copy import deepcopy
import json
import re
import threading
import time
from urllib.parse import urlsplit

from peaso.secret_scanning import scan_content, merge_leaks, redact_matches

COMPOSER = 'composer_environment'
WORKBENCH = 'workbench_instance'
KINDS = (COMPOSER, WORKBENCH)
SCHEMA = 'gcp-notebook-airflow-literal-secrets-v1'
MARKER = 'NotebookAirflowSecretIndicators'
FIELDS = {COMPOSER: ('config.softwareConfig.envVariables', 'config.softwareConfig.airflowConfigOverrides',
                     'config.softwareConfig.pypiPackages'), WORKBENCH: ('gceSetup.metadata', 'gceSetup.systemMetadata')}
SPEC = {COMPOSER: ('composer.googleapis.com', 'v1', 'environments'),
        WORKBENCH: ('notebooks.googleapis.com', 'v2', 'instances')}
MAX_ROWS = 100
MAX_PAGE_ROWS = 50
MAX_PAGES = 20
MAX_PAIRS = 128
MAX_KEY_BYTES = 256
MAX_VALUE_BYTES = 16384
MAX_ROW_BYTES = 131072
MAX_TOTAL_BYTES = 1048576
MAX_SECONDS = 60
MAX_LEAKS = 256
MAX_LOCATIONS = 512
SEGMENT = r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}'
PROJECT = r'(?:[a-z][a-z0-9-]{0,62}|[0-9]{1,20})'
LOCATION = r'[a-z][a-z0-9-]{0,62}'
RESOURCE = {COMPOSER: r'[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?', WORKBENCH: SEGMENT}
BOOLEAN_METADATA = ('notebook-disable-root', 'notebook-disable-downloads', 'notebook-disable-terminal',
                    'notebook-disable-nbconvert', 'serial-port-enable', 'enable-oslogin')


def new_budget():
    return {'deadline': time.monotonic() + MAX_SECONDS, 'pages': 0, 'rows': 0,
            'bytes': 0, 'lock': threading.RLock()}


def bound(name, scope, kind, location='-', resource=None):
    if kind not in SPEC or not isinstance(name, str) or not isinstance(scope, str): return False
    match = re.fullmatch(re.escape(scope) + r'/locations/(' + LOCATION + ')/' + SPEC[kind][2] + '/(' + RESOURCE[kind] + ')', name)
    return bool(match and (location == '-' or match[1] == location) and (resource is None or resource == match[2]))


def request_kind(method, url, scope, params=None, body=None):
    p = urlsplit(url)
    if (method != 'GET' or body is not None or p.scheme != 'https' or p.query or p.fragment
            or not isinstance(scope, str) or not re.fullmatch('projects/' + PROJECT, scope)
            or not isinstance(params or {}, dict) or set(params or {}) - {'pageSize', 'pageToken'}):
        raise ValueError('unbound request')
    for kind, (host, version, plural) in SPEC.items():
        if p.netloc != host: continue
        m = re.fullmatch('/' + version + '/' + re.escape(scope) + '/locations/(-|' + LOCATION + ')/' + plural + '(?:/(' + RESOURCE[kind] + '))?', p.path)
        if not m or (m[1] == '-' and (kind == COMPOSER or m[2] is not None)) or (m[2] is not None and params):
            raise ValueError('unbound path')
        return kind, m[1], m[2]
    raise ValueError('unbound host')


def _at(row, path):
    for key in path.split('.'):
        if not isinstance(row, dict) or key not in row: raise ValueError('missing parent')
        row = row[key]
    return row


def _drop_freeform(value):
    if isinstance(value, dict):
        for key in list(value):
            if key.lower() in ('description', 'descriptions', 'labels', 'annotations'):
                value.pop(key)
                coverage = value.get('_coverage')
                if not isinstance(coverage, dict): coverage = {}; value['_coverage'] = coverage
                coverage[key] = {'status': 'unavailable', 'reason': 'freeform_metadata_removed'}
            elif key != '_coverage': _drop_freeform(value[key])
    elif isinstance(value, list):
        for v in value: _drop_freeform(v)


def scrub_row(row, kind):
    """Drop values even when disabled; preserve bounded native security switches."""
    if not isinstance(row, dict): return None
    out = deepcopy(row)
    out.pop(MARKER, None)
    _drop_freeform(out)
    parent_paths = ('config', 'config.softwareConfig') if kind == COMPOSER else ('gceSetup',)
    for path in parent_paths:
        parent, _, key = path.rpartition('.')
        try: container = _at(out, parent) if parent else out
        except ValueError: continue
        if isinstance(container, dict) and key in container and not isinstance(container[key], dict):
            container.pop(key)
            container.setdefault('_coverage', {})[key] = {'status': 'unavailable', 'reason': 'malformed_parent_removed'}
    for field in FIELDS[kind]:
        parent, key = field.rsplit('.', 1)
        try: config = _at(out, parent)
        except ValueError: continue
        if not isinstance(config, dict): continue
        value = config.pop(key, None)
        # Workbench policy facts remain usable only for known safe values.
        if kind == WORKBENCH and isinstance(value, dict):
            retained = {}
            unknown = {}
            for k, v in value.items():
                if k in BOOLEAN_METADATA:
                    retained[k] = v if isinstance(v, str) and v.lower() in ('true', 'false', '1', '0') else None
                elif k == 'proxy-mode':
                    retained[k] = v if v in ('service_account', 'project_editors') else None
                else:
                    retained[k] = None
                if retained[k] is None:
                    unknown[k] = {'status': 'unavailable', 'reason': 'literal_value_removed'}
            if unknown: retained['_coverage'] = unknown
            config[key] = retained
        if kind == COMPOSER:
            for legacy in ('envVariableNames', 'airflowConfigOverrideNames', 'pypiPackageNames'):
                config.pop(legacy, None)
        if kind == COMPOSER or (value is not None and not isinstance(value, dict)):
            config.setdefault('_coverage', {})[key] = {'status': 'unavailable', 'reason': 'literal_values_removed'}
    return out


def unavailable(scope, kind, identity=None):
    return {'schema': SCHEMA, 'scope': scope, 'kind': kind, 'identity': identity,
            'complete': False, 'bytes': 0, 'fields': list(FIELDS[kind]), 'engines': [],
            'leaks': [], 'verification': 'not_attempted'}


def _payload(row, kind):
    if (not isinstance(row, dict) or row.get('collection_status', 'collected') != 'collected'
            or row.get('_coverage') or row.get('_field_mask') or row.get('_representation') not in (None, 'full')):
        raise ValueError('partial representation')
    parents = ['config', 'config.softwareConfig'] if kind == COMPOSER else ['gceSetup']
    for path in parents:
        parent = _at(row, path)
        if (not isinstance(parent, dict) or parent.get('_coverage') or parent.get('_field_mask')
                or parent.get('collection_status', 'collected') != 'collected'
                or any(k.endswith('Names') for k in parent)):
            raise ValueError('missing or scrubbed parent')
    values = {}
    for field in FIELDS[kind]:
        parent, key = field.rsplit('.', 1)
        value = _at(row, parent).get(key, {})
        if not isinstance(value, dict) or len(value) > MAX_PAIRS: raise ValueError('invalid map')
        for k, v in value.items():
            if (not isinstance(k, str) or not 1 <= len(k.encode()) <= MAX_KEY_BYTES
                    or not isinstance(v, str) or len(v.encode()) > MAX_VALUE_BYTES):
                raise ValueError('invalid literal')
        values[field] = value
    payload = json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    if len(payload) > MAX_ROW_BYTES: raise ValueError('row bound')
    return payload


def project_response(response, *, method, url, scope, params=None, body=None,
                     enabled=False, selected_kinds=(), response_complete=True,
                     collection_status='collected', check_cancelled=None, budget=None):
    """Always scrub; scan only original successful native JSON with exact opt-in.

    A shared budget bounds pages/rows/bytes/time across responses and kinds. The
    existing collector retains control of request/page/cancel/deadline budgets.
    No new service request is made. Repeated calls to the same cached page must
    occur only once, before generic cache insertion.
    """
    from .gcp import sanitize
    if not isinstance(response, dict): return sanitize(response)
    host = urlsplit(url).hostname
    kind = next((k for k in KINDS if SPEC[k][0] == host), None)
    if kind is None: return sanitize(response)
    plural = SPEC[kind][2]
    raw_rows = response.get(plural) if plural in response else [response]
    safe = deepcopy(response)
    safe.pop(MARKER, None)
    if not isinstance(raw_rows, list):
        # A malformed native list cannot safely retain arbitrary content.
        return {plural: [], '_coverage': {plural: {'status': 'unavailable', 'reason': 'malformed_native_list'}}}
    safe_rows = [scrub_row(row, kind) for row in raw_rows]
    if plural in response: safe = {k: v for k, v in safe.items() if k in ('nextPageToken', 'unreachable')}; safe[plural] = safe_rows
    else: safe = safe_rows[0]
    _drop_freeform(safe)
    if enabled is not True or not isinstance(selected_kinds, (list, tuple, set)) or kind not in selected_kinds:
        return sanitize(safe)
    budget = budget if budget is not None else new_budget()
    redactions = set()
    with budget['lock']:
        page_ok = False
        try:
            actual, location, resource = request_kind(method, url, scope, params, body)
            if actual != kind: raise ValueError('kind')
            if (response_complete is not True or collection_status != 'collected'
                    or response.get('unreachable') or response.get('_coverage') or response.get('_field_mask')
                    or len(raw_rows) > MAX_PAGE_ROWS or budget['pages'] >= MAX_PAGES
                    or budget['rows'] + len(raw_rows) > MAX_ROWS or time.monotonic() >= budget['deadline']):
                raise ValueError('incomplete page or run budget')
            if plural in response and (set(response) - {plural, 'nextPageToken', 'unreachable'}):
                raise ValueError('unknown page fields')
            if 'unreachable' in response and not isinstance(response['unreachable'], list): raise ValueError('partial page')
            budget['pages'] += 1; budget['rows'] += len(raw_rows)
            page_ok = True
        except Exception: pass
        for raw, out in zip(raw_rows, safe_rows):
            if not isinstance(out, dict): continue
            marker = unavailable(scope, kind)
            out[MARKER] = marker
            try:
                if not page_ok or not isinstance(raw, dict) or not bound(raw.get('name'), scope, kind, location, resource):
                    raise ValueError('unbound row')
                marker['identity'] = raw['name']
                payload = _payload(raw, kind)
                if budget['bytes'] + len(payload) > MAX_TOTAL_BYTES: raise ValueError('scan bound')
                budget['bytes'] += len(payload)
                if check_cancelled is not None: check_cancelled()
                remaining = budget['deadline'] - time.monotonic()
                if remaining <= 0: raise TimeoutError('deadline')
                result = scan_content(payload, kind + '.literal_configuration', timeout=min(5, remaining / 2),
                                      _redact_values=redactions.update)
                if check_cancelled is not None: check_cancelled()
                if time.monotonic() >= budget['deadline']: raise TimeoutError('deadline')
                leaks = merge_leaks(result['leaks'])
                if len(leaks) > MAX_LEAKS or sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS: raise ValueError('result bound')
                marker.update(bytes=len(payload), complete=result['complete'] is True,
                              engines=result['engines'], leaks=leaks)
            except Exception: pass
    return sanitize(redact_matches(safe, redactions))
