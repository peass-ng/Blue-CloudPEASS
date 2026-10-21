"""Unregistered selected WEBSITE_RUN_FROM_PACKAGE -> owned Blob capture proposal.

This is a stored-source association, never proof of cached or executed bytes.
Only the process-local sealed projection leaves the ephemeral native reads.
"""
from copy import deepcopy
import hmac
import http.client
import json
import re
import time
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

from peaso.secret_scanning import _fingerprint
from . import azure_app_settings_secret_indicators as settings
from . import azure_selected_storage_secret_indicators as storage
from .azure_function_settings_declarations_20261020 import private_native_logs, _site

KIND = 'azure_function_package_source_20261020'
CHECK = 'azure.review.function.selected_package_source_secret_indicators'
OPTION = 'selected_azure_function_package_sources'
SCHEMA = 'azure-function-package-source-v1'
SITE_VERSION = '2025-03-01'
MAX_TARGETS = 2
MAX_CALLS = 18
MAX_SECONDS = 120
OPERATIONS = ('subscription', 'account', 'site_before', 'settings_before',
              'properties_before', 'content', 'properties_after', 'settings_after', 'site_after')
# These parameters are recognized solely to discard grants, never used as auth.
SAS_KEYS = frozenset('sv ss srt sp st se spr sip si sr sig skoid sktid skt ske sks skv saoid suoid scid ses rscc rscd rsce rscl rsct'.split())
REASONS = frozenset(('complete', 'native_unavailable', 'unsupported_hosting', 'settings_unbound',
    'unsupported_package_reference', 'package_selection_mismatch', 'package_reference_changed',
    'source_version_changed', 'archive_or_detector_incomplete', 'redaction_incomplete'))


class Incomplete(ValueError):
    """Only fixed codes; never attach native values or exception text."""


def identity(target):
    canonical = deepcopy(target)
    canonical['site_resource_id'] = canonical['site_resource_id'].casefold()
    canonical['blob']['resource_id'] = canonical['blob']['resource_id'].casefold()
    return KIND + ':' + _fingerprint(json.dumps(canonical, sort_keys=True, separators=(',', ':')))


def preflight(options, scopes, named_checks, *, shared_service_account=False):
    """Credential-free validation; call before credential construction/discovery.

    Inventories, private kinds, wildcard checks and frameworks grant no authority.
    Even disabled supplied selections must be structurally valid.
    """
    if (not isinstance(options, dict) or 'content_secret_scans' in options
            and type(options['content_secret_scans']) is not bool
            or type(shared_service_account) is not bool):
        raise Incomplete('invalid_selection')
    named = (isinstance(named_checks, list) and all(isinstance(c, str) for c in named_checks)
             and '*' not in named_checks and CHECK in named_checks)
    authorized = options.get('content_secret_scans') is True and named
    if shared_service_account and (options.get('content_secret_scans') is True or OPTION in options):
        raise Incomplete('shared_service_account_forbidden')
    if OPTION not in options and not authorized:
        return []
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not storage.SCOPE.fullmatch(s) for s in scopes)
            or len({s.casefold() for s in scopes}) != len(scopes)
            or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
        raise Incomplete('invalid_selection')
    seen = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {'site_resource_id', 'blob'}:
            raise Incomplete('invalid_selection')
        site = target['site_resource_id']
        match = settings._RESOURCE.fullmatch(site) if isinstance(site, str) and len(site) <= 512 else None
        try:
            service, scope, *rest = storage.parse(target['blob'])
        except Exception:
            raise Incomplete('invalid_selection') from None
        if (not match or '/.' in site or service != 'blob'
                or target['blob']['format'] != 'zip' or not target['blob']['object'].endswith('.zip')
                or scope.casefold() != match[1].casefold()
                or scope.casefold() not in {s.casefold() for s in scopes}
                or site.casefold() in seen):
            raise Incomplete('invalid_selection')
        seen.add(site.casefold())
    return deepcopy(targets) if authorized else []


def _seal(value):
    return _fingerprint(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False))


def authentic(envelope):
    """Same-process receipt seal; no portable/replayed snapshot admission."""
    try:
        value = {k: v for k, v in envelope.items() if k != 'seal'}
        return isinstance(envelope['seal'], str) and hmac.compare_digest(envelope['seal'], _seal(value))
    except Exception:
        return False


def _hosting(data, site):
    # Bind the exact native slot identity before accepting any hosting facts.
    match = settings._RESOURCE.fullmatch(site)
    if match is None:
        raise Incomplete('unsupported_hosting')
    slot = match[4] is not None
    expected_type = 'microsoft.web/sites/slots' if slot else 'microsoft.web/sites'
    expected_name = match[3] + '/' + match[4] if slot else site.rsplit('/', 1)[1]
    if (not isinstance(data, dict) or str(data.get('id', '')).casefold() != site.casefold()
            or str(data.get('type', '')).casefold() != expected_type
            or str(data.get('name', '')).casefold() != expected_name.casefold()
            or not isinstance(data.get('properties'), dict)):
        raise Incomplete('unsupported_hosting')
    kind = data.get('kind')
    if not isinstance(kind, str):
        raise Incomplete('unsupported_hosting')
    parts = [k.strip().casefold() for k in kind.split(',')]
    kinds = set(parts)
    if 'functionapp' in kinds:
        if slot:
            # This bounded slot slice accepts only classic Windows Function code.
            # Flex, containers, Linux and unresolved host declarations stay unknown.
            props = data['properties']
            config = props.get('siteConfig')
            if (parts != ['functionapp'] or type(props.get('reserved')) is not bool
                    or props['reserved'] is not False or props.get('functionAppConfig') is not None
                    or not isinstance(config, dict) or not isinstance(config.get('windowsFxVersion'), str)
                    or config['windowsFxVersion'].upper().startswith('DOCKER|')):
                raise Incomplete('unsupported_hosting')
        elif _site(data, site).get('hosting') != 'classic':
            raise Incomplete('unsupported_hosting')
        hosting = 'function'
    else:
        props = data['properties']
        config = props.get('siteConfig')
        if (kind.casefold() != 'app' or props.get('reserved') is not False
                or props.get('functionAppConfig') is not None
                or not isinstance(config, dict) or config.get('windowsFxVersion') != ''):
            raise Incomplete('unsupported_hosting')
        hosting = 'app_service'
    # Existing production-site projection stays unchanged. The slot's full
    # native metadata must remain stable over the Blob read window.
    return (hosting, _seal(data)) if slot else hosting


def _association(data, target):
    site, blob = target['site_resource_id'], target['blob']
    if (str(data.get('id', '')).casefold() != (site + '/config/appsettings').casefold()
            or str(data.get('type', '')).casefold() != ('microsoft.web/sites/slots/config' if settings._RESOURCE.fullmatch(site)[4] is not None else 'microsoft.web/sites/config')
            or data.get('name') != 'appsettings' or not isinstance(data.get('properties'), dict)
            or not 1 <= len(data['properties']) <= settings.MAX_SETTINGS):
        raise Incomplete('settings_unbound')
    seen, size = set(), 0
    for key, value in data['properties'].items():
        if (not isinstance(key, str) or not 1 <= len(key) <= 512 or key.casefold() in seen
                or any(ord(c) < 32 or ord(c) == 127 for c in key) or not isinstance(value, str)):
            raise Incomplete('settings_unbound')
        seen.add(key.casefold())
        raw = value.encode('utf-8', errors='strict')
        size += len(raw)
        if (len(raw) > settings.MAX_VALUE or size > settings.MAX_CONTENT
                or any(ord(c) < 32 and c not in '\r\n\t' or ord(c) == 127 for c in value)):
            raise Incomplete('settings_unbound')
    if any(k.casefold() == 'website_run_from_package' and k != 'WEBSITE_RUN_FROM_PACKAGE' for k in data['properties']):
        raise Incomplete('settings_unbound')
    value = data['properties'].get('WEBSITE_RUN_FROM_PACKAGE')
    if (not isinstance(value, str) or not 1 <= len(value) <= 8192
            or any(ord(c) <= 32 or ord(c) >= 127 for c in value) or '\\' in value):
        raise Incomplete('unsupported_package_reference')
    try:
        url = urlsplit(value)
        host, route = storage.data_route(blob)
        if (url.scheme != 'https' or url.netloc != host or url.fragment
                or url.path != route.split('?', 1)[0] or re.search(r'%(?![0-9a-fA-F]{2})', url.query)):
            raise Incomplete('package_selection_mismatch')
        pairs = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=32)
        params = dict(pairs)
        if len(params) != len(pairs) or set(params) - SAS_KEYS - {'versionid'}:
            raise Incomplete('unsupported_package_reference')
        if params.get('versionid') != blob.get('version'):
            raise Incomplete('package_selection_mismatch')
    except Incomplete:
        raise
    except Exception:
        raise Incomplete('unsupported_package_reference') from None
    # Only HMAC locators survive. Raw SAS values, unrelated settings and URLs die here.
    return {'reference_locator': 'package-reference:' + _fingerprint(value),
            'object_identity': storage.identity(blob),
            'selection_mode': 'versioned' if 'version' in blob else 'current'}


def _web_read(reader, transport, state, receipts, target, operation):
    storage.remaining(reader, state)
    if state['calls'] >= MAX_CALLS:
        raise Incomplete('native_unavailable')
    state['calls'] += 1
    site = target['site_resource_id']
    is_settings = operation.startswith('settings_')
    method = 'POST' if is_settings else 'GET'
    path = site + ('/config/appsettings/list' if is_settings else '') + '?api-version=' + SITE_VERSION
    receipt = {'id': 'package-web-read:' + uuid4().hex, 'identity': identity(target),
        'capture': state['capture'], 'scope': storage.parse(target['blob'])[1], 'operation': operation,
        'method': method, 'origin': 'arm', 'version': SITE_VERSION, 'status': 'unavailable',
        'bytes': 0, 'bound': False, 'tenant': None, 'principal': None,
        'request': 'package-web-request:' + _fingerprint(method + '\n' + path), 'native_request': None}
    receipts.append(receipt)
    connection = response = None
    try:
        token = storage._token(transport, storage.ARM, state)
        receipt.update(**state['authority'])
        connection = http.client.HTTPSConnection('management.azure.com', timeout=storage.remaining(reader, state))
        connection.set_debuglevel(0)
        connection.request(method, path, body=None, headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Content-Length': '0'})
        del token
        response = connection.getresponse()
        if (type(response.status) is not int or response.status != 200
                or response.getheader('Content-Encoding') not in (None, '', 'identity')
                or response.getheader('Transfer-Encoding') is not None or response.getheader('Content-Range') is not None
                or (response.getheader('Content-Type') or '').split(';')[0].strip().lower() != 'application/json'):
            raise Incomplete('native_unavailable')
        length = response.getheader('Content-Length')
        request_id = response.getheader('x-ms-request-id')
        if (not isinstance(length, str) or not re.fullmatch(r'[0-9]{1,10}', length)
                or not 1 <= int(length) <= storage.MAX_ARM
                or not isinstance(request_id, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', request_id)):
            raise Incomplete('native_unavailable')
        receipt['native_request'] = 'package-web-response:' + _fingerprint(request_id)
        raw = bytearray()
        while True:
            timeout = storage.remaining(reader, state)
            if getattr(connection, 'sock', None) is not None:
                connection.sock.settimeout(timeout)
            chunk = response.read(min(16384, storage.MAX_ARM + 1 - len(raw)))
            if not isinstance(chunk, bytes):
                raise Incomplete('native_unavailable')
            raw.extend(chunk)
            state['bytes'] += len(chunk)
            receipt['bytes'] = len(raw)
            if len(raw) > storage.MAX_ARM or state['bytes'] > storage.MAX_TOTAL:
                raise Incomplete('native_unavailable')
            if not chunk:
                break
        if len(raw) != int(length):
            raise Incomplete('native_unavailable')
        native = storage._json(bytes(raw))
        if (not isinstance(native, dict) or set(native) & {'error', 'nextLink', 'value', 'continuationToken',
                'partial', '_partial', '_coverage', 'hasMore', 'resultTruncated'}):
            raise Incomplete('native_unavailable')
        projected = _association(native, target) if is_settings else _hosting(native, site)
        receipt.update(status='collected', bound=True)
        return projected
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()


def _one(reader, transport, state, target, receipts):
    blob = target['blob']
    scope = storage.parse(blob)[1]
    start = len(receipts)
    marker = {'identity': identity(target), 'scope': scope, 'capture': state['capture'],
        'association_complete': False, 'complete': False, 'reason': 'native_unavailable',
        'verification': 'not_attempted', 'coverage': 'selected_configured_stored_package_only',
        'runtime_bytes': 'unknown', 'continuous_immutability': 'unknown',
        'tenant': None, 'principal': None, 'hosting': None, 'reference_locator': None,
        'object_identity': storage.identity(blob), 'selection_mode': 'versioned' if 'version' in blob else 'current',
        'version_locator': None, 'etag_locator': None, 'object_bytes': 0, 'expanded_bytes': 0,
        'members': 0, 'parts': [], 'leaks': [], 'source_requests': []}
    try:
        def read(operation, host, route, method, cap, **kw):
            return reader.call(storage._read, reader, transport, state, receipts, blob,
                               operation, host, route, method, cap, **kw)
        sub = read('subscription', 'management.azure.com', scope + '?api-version=' + storage.SUB_VERSION, 'GET', storage.MAX_ARM)
        storage._bound_subscription(sub, scope, state)
        receipts[-1]['bound'] = True
        del sub
        account = read('account', 'management.azure.com', blob['resource_id'] + '?api-version=' + storage.ARM_VERSION, 'GET', storage.MAX_ARM)
        storage._bound_account(account, blob)
        receipts[-1]['bound'] = True
        del account
        def web(op):
            return reader.call(_web_read, reader, transport, state, receipts, target, op)
        hosting = web('site_before')
        before_ref = web('settings_before')
        host, route = storage.data_route(blob)
        before = read('properties_before', host, route, 'HEAD', storage.MAX_OBJECT)
        raw = read('content', host, route, 'GET', storage.MAX_OBJECT, expected=before)
        after = read('properties_after', host, route, 'HEAD', storage.MAX_OBJECT)
        if before != after:
            raise Incomplete('source_version_changed')
        after_ref = web('settings_after')
        after_hosting = web('site_after')
        if before_ref != after_ref or hosting != after_hosting:
            raise Incomplete('package_reference_changed')
        marker.update(**state['authority'], **before_ref, hosting=hosting[0] if isinstance(hosting, tuple) else hosting, association_complete=True,
            object_bytes=len(raw), etag_locator='package-etag:' + _fingerprint(before['etag']),
            version_locator='package-version:' + _fingerprint(json.dumps(before, sort_keys=True)))
        # Shared parser and REAL dual scanners preserve their native receipt identity:
        # part paths bind to the exact selected storage identity, never to site aliases.
        marker['reason'] = 'archive_or_detector_incomplete'
        storage._inspect(reader, state, blob, marker, raw)
        del raw
        if reader.storage_source_secret_overflow:
            raise Incomplete('redaction_incomplete')
        marker.update(complete=True, reason='complete')
    except Incomplete as exc:
        marker['reason'] = str(exc) if str(exc) in REASONS else 'native_unavailable'
    except Exception:
        pass  # Native/scanner error text is private, including URLs and values.
    marker['source_requests'] = [r['id'] for r in receipts[start:]]
    return marker


def collect(reader, transport, scopes, options, named_checks, *, customer_context_id,
            credential_context_id, shared_service_account=False):
    """Standalone proposal entry; no registry, Azure hooks, cache, auth or cloud setup.

    Caller owns the same-process context IDs and invokes preflight before auth.
    This isolated proposal must not share a reader with a mixed inventory run:
    integration needs the existing final UNION redactor before any metadata export.
    """
    targets = preflight(options, scopes, named_checks, shared_service_account=shared_service_account)
    if not targets:
        return None
    if (any(not isinstance(v, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', v)
            for v in (customer_context_id, credential_context_id))
            or reader.collections or hasattr(reader, 'storage_source_secret_redactions')):
        raise Incomplete('isolated_reader_required')
    capture = 'package-capture:' + uuid4().hex
    state = {'capture': capture, 'deadline': time.monotonic() + MAX_SECONDS, 'bytes': 0,
             'calls': 0, 'expanded': 0, 'members': 0, 'authority': None}
    envelope = {'schema': SCHEMA, 'authorized': True, 'capture': capture,
        'customer_context_id': customer_context_id, 'credential_context_id': credential_context_id,
        'selection': {s: [identity(t) for t in targets if storage.parse(t['blob'])[1].casefold() == s.casefold()] for s in scopes},
        'results': [], 'receipts': []}
    reader.storage_source_secret_redactions = set()
    reader.storage_source_secret_overflow = False
    try:
        with private_native_logs():
            for target in targets:
                envelope['results'].append(_one(reader, transport, state, target, envelope['receipts']))
        if reader.storage_source_secret_overflow:
            for marker in envelope['results']:
                marker.update(complete=False, reason='redaction_incomplete', parts=[], leaks=[])
        envelope['seal'] = _seal(envelope)
        return envelope
    finally:
        reader.storage_source_secret_redactions.clear()
        del reader.storage_source_secret_redactions
        del reader.storage_source_secret_overflow
