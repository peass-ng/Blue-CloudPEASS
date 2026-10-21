"""Opt-in transient Functions v2 literal-value scans, before transport caching.

Only existing offline detection adapters run. No credential validation, Secret
Manager reads, downloads, subprocess output, environment values or snippets are
returned. The caller must use the original successful unmasked API response.
"""

from peaso.secret_evidence import scan_with_source
import re
import time
from urllib.parse import urlsplit

from peaso.secret_scanning import scan_content, merge_leaks, redact_matches

SCHEMA = 'gcp-function-literal-secrets-v1'
MARKER = 'FunctionSecretIndicators'
SURFACES = ('serviceConfig', 'buildConfig')
MAX_FUNCTIONS = 100
MAX_PAIRS = 128
MAX_VALUE_BYTES = 16384
MAX_FUNCTION_BYTES = 131072
MAX_PAGE_BYTES = 1048576
MAX_PAGE_SECONDS = 30
MAX_LEAKS = 256
MAX_LOCATIONS = 512
_PROJECT = r'[a-z][a-z0-9-]{0,62}|[0-9]{1,20}'
_LOCATION = r'[a-z][a-z0-9-]{0,62}'
_FUNCTION = r'[A-Za-z][A-Za-z0-9_-]{0,62}'
_NAME = re.compile(r'projects/(' + _PROJECT + r')/locations/(' + _LOCATION + r')/functions/(' + _FUNCTION + r')')


def _request(method, url, scope, params, body):
    parsed = urlsplit(url)
    if (method != 'GET' or body is not None or parsed.scheme != 'https'
            or parsed.netloc != 'cloudfunctions.googleapis.com' or parsed.query or parsed.fragment
            or not isinstance(scope, str) or not re.fullmatch(r'projects/(' + _PROJECT + ')', scope)
            or not isinstance(params or {}, dict) or set(params or {}) - {'pageSize', 'pageToken'}):
        raise ValueError('unbound native Functions read')
    match = re.fullmatch(r'/v2/' + re.escape(scope) + r'/locations/(-|' + _LOCATION + r')/functions(?:/(' + _FUNCTION + r'))?', parsed.path)
    if match is None or (match[1] == '-' and match[2] is not None):
        raise ValueError('unbound native Functions path')
    return match[1], match[2]


def _bound(name, scope, location, function):
    match = _NAME.fullmatch(name) if isinstance(name, str) else None
    return bool(match and 'projects/' + match[1] == scope and (location == '-' or match[2] == location)
                and (function is None or match[3] == function))


def unavailable(status='unavailable', *, name=None, scope=None):
    return {'schema': SCHEMA, 'status': status, 'identity': name, 'scope': scope,
            'complete': False, 'surfaces': [], 'leaks': [], 'verification': 'not_attempted'}


def _coverage_ok(row, *, source_fields=False):
    if not isinstance(row, dict) or row.get('collection_status', 'collected') != 'collected':
        return False
    coverage = row.get('_coverage', {})
    # The independently authorized source projection may already have omitted
    # free-text metadata. Those unavailable descriptions do not invalidate
    # the original runtime/build environment maps; all other coverage still does.
    return (isinstance(coverage, dict) and all(
        (key in {'description', 'descriptions', 'labels', 'annotations'}
         and entry == {'status': 'unknown', 'reason': 'free_text_not_retained'})
        or (source_fields is True and key in {'source', 'sourceProvenance'}
            and entry == {'status': 'unknown', 'reason': 'function_source_reference_not_retained'})
        for key, entry in coverage.items()) and not row.get('environmentVariableNames'))


def _scan_function(row, scope, location, function, budget, complete, status, check_cancelled, redactions):
    name = row.get('name')
    if not _bound(name, scope, location, function):
        return unavailable('identity_mismatch')
    if status != 'collected' or complete is not True or not _coverage_ok(row):
        return unavailable('incomplete', name=name, scope=scope)
    payloads, total = [], 0
    try:
        for surface in SURFACES:
            config = row[surface]
            if not _coverage_ok(config, source_fields=(surface == 'buildConfig')):
                raise ValueError('unreadable environment configuration')
            # Omitted map on a complete unmasked parent means no literal values.
            values = config.get('environmentVariables', {})
            if (not isinstance(values, dict) or len(values) > MAX_PAIRS
                    or 'environmentVariableNames' in config):
                raise ValueError('environment map unavailable or oversized')
            for key, value in values.items():
                if (not isinstance(key, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', key)
                        or not isinstance(value, str) or len(value) > MAX_VALUE_BYTES):
                    raise ValueError('invalid or oversized environment pair')
                size = len(key.encode('utf-8')) + len(value.encode('utf-8'))
                if len(value.encode('utf-8')) > MAX_VALUE_BYTES:
                    raise ValueError('environment value byte bound')
                total += size
            payload = ('\n'.join(key + '=' + values[key] for key in sorted(values)) + '\n').encode('utf-8')
            total += len(payload)  # Include context/framing in the bound.
            if total > MAX_FUNCTION_BYTES or total > budget[0]:
                raise ValueError('environment byte bound')
            payloads.append((surface, payload, len(values)))
    except (KeyError, TypeError, ValueError, UnicodeError):
        return unavailable('bounds_or_shape', name=name, scope=scope)
    budget[0] -= total
    surfaces, leaks = [], []
    for surface, payload, pairs in payloads:
        try:
            if check_cancelled is not None:
                check_cancelled()
            remaining = budget[1] - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('offline scan time budget')
            outcome = scan_with_source(scan_content, payload, surface + '.environmentVariables', timeout=min(10, remaining / 2),
                                   _redact_values=redactions.update, source={'resource_id': name, 'location_kind': 'configuration', 'scope': scope}, native=row[surface])
            merged = merge_leaks(outcome['leaks'])
            if len(merged) > MAX_LEAKS or sum(len(leak['locations']) for leak in merged) > MAX_LOCATIONS:
                raise ValueError('redacted result bound')
            surfaces.append({'surface': surface, 'pairs': pairs, 'bytes': len(payload),
                             'complete': outcome['complete'], 'engines': outcome['engines']})
            leaks.extend(merged)
        except Exception:
            # Engine exceptions must not escape or be interpolated into evidence.
            surfaces.append({'surface': surface, 'pairs': pairs, 'bytes': len(payload),
                             'complete': False, 'engines': []})
    leaks = merge_leaks(leaks)
    if len(leaks) > MAX_LEAKS or sum(len(leak['locations']) for leak in leaks) > MAX_LOCATIONS:
        return unavailable('result_bound', name=name, scope=scope)
    complete = all(surface['complete'] is True for surface in surfaces)
    return {'schema': SCHEMA, 'status': 'collected' if complete else 'incomplete', 'identity': name,
            'scope': scope, 'complete': complete, 'surfaces': surfaces, 'leaks': leaks,
            'verification': 'not_attempted'}


def project_response(response, *, method, url, scope, params=None, body=None, enabled=False,
                     response_complete=True, collection_status='collected', check_cancelled=None):
    """Return sanitized API data; the raw response is inspected transiently only.

    Defaults to the exact existing names-only sanitizer. A true boolean opt-in,
    successful unmasked GET, matching native identity, and complete runtime/build
    maps are required for clean results. Missing detectors never prove absence.
    """
    from .gcp import sanitize
    safe = sanitize(response)
    if enabled is True:
        from peaso.secret_scanning import omit_free_text_metadata
        safe = omit_free_text_metadata(safe)
    if not isinstance(response, dict) or not isinstance(safe, dict):
        return safe
    raw_rows = response.get('functions') if 'functions' in response else [response]
    safe_rows = safe.get('functions') if 'functions' in safe else [safe]
    if not isinstance(raw_rows, list) or not isinstance(safe_rows, list):
        return safe
    for row in safe_rows:
        if isinstance(row, dict):
            row.pop(MARKER, None)  # A provider-returned marker is never authority.
    if enabled is not True:
        return safe
    try:
        location, function = _request(method, url, scope, params, body)
    except (TypeError, ValueError):
        for row in safe_rows:
            if isinstance(row, dict):
                row[MARKER] = unavailable('unbound_request')
        return safe
    if len(raw_rows) > MAX_FUNCTIONS:
        for row in safe_rows:
            if isinstance(row, dict):
                row[MARKER] = unavailable('page_bound')
        return safe
    budget = [MAX_PAGE_BYTES, time.monotonic() + MAX_PAGE_SECONDS]
    page_complete = response_complete is True and not response.get('unreachable')
    redactions = set()
    for raw, sanitized in zip(raw_rows, safe_rows):
        if not isinstance(raw, dict) or not isinstance(sanitized, dict):
            continue
        sanitized[MARKER] = _scan_function(raw, scope, location, function, budget, page_complete, collection_status, check_cancelled, redactions)
    return redact_matches(safe, redactions)
