"""Default-off, selected ARM app-settings reads; only redacted evidence survives.

The documented list POST is a read action. No site enumeration, mutation,
Key Vault dereference, execution, URL following or credential verification.
"""
from copy import deepcopy
import http.client
import json
import re
import time
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint

KIND = 'app_service_selected_settings'
CHECK = 'azure.review.app_service.selected_app_settings_secret_indicators'
OPTION = 'selected_azure_app_settings'
MARKER = 'SelectedAppSettingSecretIndicators'
SCHEMA = 'azure-selected-app-settings-secrets-v1'
HOST = 'management.azure.com'
API_VERSION = '2025-03-01'
MAX_WIRE = 2097152
MAX_CONTENT = 262144
MAX_VALUE = 65536
MAX_TOTAL = 8388608
MAX_SECONDS = 60
MAX_SETTINGS = 512
MAX_LEAKS = 256
MAX_LOCATIONS = 512
_GUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
_SCOPE = re.compile(r'/subscriptions/' + _GUID + r'\Z', re.I)
# Deliberately bounded subset: literal safe path segments, no escaped aliases,
# query, slash, dot traversal, host, arbitrary URL or provider expansion.
_RESOURCE = re.compile(r'(/subscriptions/' + _GUID + r')/resourceGroups/'
    r'([A-Za-z0-9_()-][A-Za-z0-9_.()-]{0,88}[A-Za-z0-9_()-]|[A-Za-z0-9_()-])'
    r'/providers/Microsoft\.Web/sites/([A-Za-z0-9][A-Za-z0-9-]{0,58}[A-Za-z0-9]|[A-Za-z0-9])'
    r'(?:/slots/([A-Za-z0-9][A-Za-z0-9-]{0,58}[A-Za-z0-9]|[A-Za-z0-9]))?\Z', re.I)


class Incomplete(ValueError):
    """Safe stable errors only; never include native content or URL text."""


def enabled(options):
    return (options.get('content_secret_scans') is True
            and isinstance(options.get('_content_secret_scan_kinds'), list)
            and KIND in options['_content_secret_scan_kinds'])


def selected_targets(options, scopes):
    """Public, credential-free validator; returns exact native routing IDs.

    Validate supplied selections even while disabled; callers must separately
    enforce the public flag and exact named check. Raises safe ValueError.
    """
    if not isinstance(options, dict) or ('content_secret_scans' in options
            and type(options['content_secret_scans']) is not bool):
        raise Incomplete('invalid_selection')
    if OPTION not in options and not enabled(options):
        return []
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not _SCOPE.fullmatch(s) for s in scopes)
            or len({s.casefold() for s in scopes}) != len(scopes)
            or not isinstance(targets, list) or not 1 <= len(targets) <= 8):
        raise Incomplete('invalid_selection')
    seen = set()
    for target in targets:
        match = _RESOURCE.fullmatch(target) if isinstance(target, str) else None
        if (not match or match[1].casefold() not in {s.casefold() for s in scopes}
                or target.casefold() in seen or '/.' in target or len(target) > 512):
            raise Incomplete('invalid_selection')
        seen.add(target.casefold())
    return list(targets)


def identity(target):
    # Keyed locators also conceal values copied into selected names/keys.
    return KIND + ':' + _fingerprint(target.casefold())


def selection_metadata(options, scopes):
    targets = selected_targets(options, scopes)
    return {KIND + '_authorized': enabled(options), KIND + '_selection': {
        scope: [identity(t) for t in targets if _RESOURCE.fullmatch(t)[1].casefold() == scope.casefold()]
        for scope in scopes}, KIND + '_receipts': []}


def _remaining(reader, state):
    reader.check_cancelled()
    left = state['deadline'] - time.monotonic()
    if left <= 0:
        raise Incomplete('deadline_exceeded')
    return min(left, 10)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Incomplete('duplicate_native_field')
        result[key] = value
    return result


def _read(reader, transport, target, operation, state, receipts, scope):
    """Fixed-origin direct TLS, bounded ephemeral JSON; never generic cache."""
    method = 'GET' if operation == 'identity' else 'POST'
    route = target + ('' if method == 'GET' else '/config/appsettings/list') + '?api-version=' + API_VERSION
    connection = None
    response = None
    receipt = {'id': 'app-settings-read-' + str(len(receipts) + 1), 'identity': identity(target),
        'scope': scope, 'method': method, 'operation': operation, 'route': 'exact_selected_' + operation,
        'host': HOST, 'api_version': API_VERSION, 'status': 'unavailable', 'http_status': 0,
        'bytes': 0, 'final_route_verified': False, 'identity_bound': False}
    receipts.append(receipt)
    try:
        token = transport.token('https://' + HOST)
        if not isinstance(token, str) or not token or '\r' in token or '\n' in token:
            raise Incomplete('credential_unavailable')
        connection = http.client.HTTPSConnection(HOST, timeout=_remaining(reader, state))
        connection.set_debuglevel(0)
        connection.request(method, route, body=None, headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Content-Length': '0'})
        response = connection.getresponse()
        receipt['http_status'] = response.status
        receipt['final_route_verified'] = True  # direct fixed TLS origin; redirects are never followed
        if type(response.status) is not int or response.status != 200:
            raise Incomplete('native_read_unavailable')
        encoding = response.getheader('Content-Encoding')
        content_type = response.getheader('Content-Type')
        length = response.getheader('Content-Length')
        if (encoding not in (None, '', 'identity') or not isinstance(content_type, str)
                or content_type.split(';')[0].strip().casefold() != 'application/json'):
            raise Incomplete('unsupported_native_response')
        expected = None
        if length is not None:
            if not isinstance(length, str) or not re.fullmatch(r'[0-9]{1,10}', length):
                raise Incomplete('unsupported_native_response')
            expected = int(length)
            if expected > MAX_WIRE or expected > MAX_TOTAL - state['bytes']:
                raise Incomplete('wire_byte_limit')
        chunks, size = [], 0
        while True:
            timeout = _remaining(reader, state)
            if getattr(connection, 'sock', None) is not None:
                connection.sock.settimeout(timeout)
            block = response.read(min(16384, MAX_WIRE + 1 - size))
            if not isinstance(block, bytes):
                raise Incomplete('unsupported_native_response')
            size += len(block)
            state['bytes'] += len(block)
            receipt['bytes'] = size
            if size > MAX_WIRE or state['bytes'] > MAX_TOTAL:
                raise Incomplete('wire_byte_limit')
            if not block:
                break
            chunks.append(block)
        if not size or expected is not None and size != expected:
            raise Incomplete('partial_native_response')
        value = json.loads(b''.join(chunks).decode('utf-8', errors='strict'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('unsupported_native_response')))
        if not isinstance(value, dict) or set(value) & {'error', 'nextLink', 'value', 'continuationToken', '_coverage', 'partial', '_partial', 'hasMore', 'resultTruncated'}:
            raise Incomplete('unsupported_native_response')
        receipt['status'] = 'collected'
        return value
    except Exception:
        # Do not log exception objects: native error details/URLs can contain values.
        raise Incomplete('native_read_unavailable') from None
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()


def _reference(value):
    """Only documented Key Vault reference forms; no dereference of any URI."""
    if not value.casefold().startswith('@microsoft.keyvault'):
        return False
    uri = r'@Microsoft\.KeyVault\(SecretUri=https://[A-Za-z0-9-]{3,24}\.vault\.(?:azure\.net|azure\.cn|usgovcloudapi\.net)/secrets/[A-Za-z0-9-]{1,127}(?:/[A-Za-z0-9-]{1,128})?\)'
    names = r'@Microsoft\.KeyVault\(VaultName=[A-Za-z0-9-]{3,24};SecretName=[A-Za-z0-9-]{1,127}(?:;SecretVersion=[A-Za-z0-9-]{1,128})?\)'
    if not re.fullmatch(uri, value, re.I) and not re.fullmatch(names, value, re.I):
        raise Incomplete('unsupported_reference')
    return True


def _content(data, target):
    slot = _RESOURCE.fullmatch(target)[4] is not None
    expected_type = 'Microsoft.Web/sites/' + ('slots/' if slot else '') + 'config'
    if (not isinstance(data.get('id'), str) or data['id'].casefold() != (target + '/config/appsettings').casefold()
            or not isinstance(data.get('type'), str) or data['type'].casefold() != expected_type.casefold()
            or data.get('name') != 'appsettings' or not isinstance(data.get('properties'), dict)
            or not 1 <= len(data['properties']) <= MAX_SETTINGS):
        raise Incomplete('settings_identity_or_content')
    values, refs, seen, size = [], 0, set(), 0
    for key, value in data['properties'].items():
        if (not isinstance(key, str) or not 1 <= len(key) <= 512 or key.casefold() in seen
                or not isinstance(value, str)):
            raise Incomplete('unsupported_setting')
        seen.add(key.casefold())
        raw = value.encode('utf-8', errors='strict')
        if len(raw) > MAX_VALUE or any(ord(c) < 32 and c not in '\t\r\n' or ord(c) == 127 for c in value):
            raise Incomplete('unsupported_setting')
        size += len(raw)
        if size > MAX_CONTENT:
            raise Incomplete('content_byte_limit')
        if _reference(value):
            refs += 1
        else:
            values.append(raw)
    payload = b'\n\n'.join(values)
    if not payload or len(payload) > MAX_CONTENT:
        raise Incomplete('literal_content_unavailable')
    return payload, len(values), refs


def _scan(reader, transport, target, scope, state, receipts):
    ident = identity(target)
    marker = {'schema': SCHEMA, 'kind': KIND, 'identity': ident, 'scope': scope,
        'complete': False, 'reason': 'incomplete', 'verification': 'not_attempted',
        'parts': [], 'leaks': [], 'source_requests': [], 'literal_count': 0, 'reference_count': 0,
        'slot': _RESOURCE.fullmatch(target)[4] is not None}
    start = len(receipts)
    try:
        native = reader.call(_read, reader, transport, target, 'identity', state, receipts, scope)
        resource_type = 'Microsoft.Web/sites' + ('/slots' if marker['slot'] else '')
        if (not isinstance(native.get('id'), str) or native['id'].casefold() != target.casefold()
                or not isinstance(native.get('type'), str) or native['type'].casefold() != resource_type.casefold()
                or not isinstance(native.get('properties'), dict)):
            raise Incomplete('site_identity_unbound')
        receipts[-1]['identity_bound'] = True
        del native
        data = reader.call(_read, reader, transport, target, 'settings', state, receipts, scope)
        payload, literals, references = _content(data, target)
        receipts[-1]['identity_bound'] = True
        del data
        _remaining(reader, state)
        from .azure_selected_secret_integration_20261020 import remember
        result = scan_content(payload, ident + '.literals', timeout=min(60, state['deadline'] - time.monotonic()),
            _redact_values=lambda values: remember(reader, 'app_setting_secret_redactions', values))
        marker.update(parts=[{'part': 'literals', 'bytes': len(payload), 'complete': result['complete'],
                              'engines': deepcopy(result['engines'])}],
            literal_count=literals, reference_count=references)
        del payload
        leaks = merge_leaks(result.get('leaks', []))
        if len(leaks) > MAX_LEAKS or sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS:
            raise Incomplete('finding_limit')
        # Only canonical redacted detector evidence can enter the snapshot.
        marker['leaks'] = leaks
        _remaining(reader, state)
        if result['complete'] is not True:
            raise Incomplete('engines_incomplete')
        marker.update(complete=True, reason='complete')
    except Exception:
        marker['reason'] = 'incomplete'
    marker['source_requests'] = [r['id'] for r in receipts[start:]]
    return {'id': ident, MARKER: marker, '_provenance': {'scope': scope,
        'source_requests': list(marker['source_requests'])}}


def collect(reader, transport, scopes, wanted, options):
    if KIND not in wanted:
        return
    targets = selected_targets(options, scopes)
    reader.app_setting_secret_redactions = set()
    reader.app_setting_secret_metadata = selection_metadata(options, scopes)
    if not enabled(options):
        return
    # Serial bounded reads: at most 16 exact native requests, one shared deadline.
    state = {'deadline': time.monotonic() + MAX_SECONDS, 'bytes': 0}
    receipts = reader.app_setting_secret_metadata[KIND + '_receipts']
    jobs = []
    for scope in scopes:
        names = [t for t in targets if _RESOURCE.fullmatch(t)[1].casefold() == scope.casefold()]
        if not names:
            continue
        def fetch(names=names, scope=scope):
            yield [_scan(reader, transport, t, scope, state, receipts) for t in names]
        # One job at a time: shared byte/deadline/receipt limits remain coherent.
        reader.run([(KIND, scope, 'Microsoft.Web', fetch)])
