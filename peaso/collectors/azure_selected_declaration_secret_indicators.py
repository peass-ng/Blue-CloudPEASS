"""Unregistered bounded selected AppConfig/ADF/Synapse literal-read proposal.

No enumeration, execution, protected-value reads, URL following or verification.
Ephemeral HTTP bodies bypass generic request caches; only opaque proofs survive.
"""
from copy import deepcopy
import http.client
import json
import re
import time
from urllib.parse import quote
from uuid import uuid4

from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from .azure_selected_secret_integration_20261020 import remember

ARM = 'https://management.azure.com'
APP_CONFIG = 'https://azconfig.io'
SYNAPSE = 'https://dev.azuresynapse.net'
GUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
SCOPE = re.compile('/subscriptions/' + GUID + r'\Z', re.I)
SEG = r'[A-Za-z0-9_][A-Za-z0-9_.()-]{0,89}'
BASE = r'(/subscriptions/' + GUID + r')/resourceGroups/' + SEG + '/providers/'
PROFILES = {
    'app_configuration': {'kind': 'azure_app_configuration_selected_values',
        'check': 'azure.review.app_configuration.selected_value_secret_indicators',
        'option': 'selected_azure_app_configuration_values', 'title': 'Selected App Configuration literal values have no detected secrets',
        'service': 'Microsoft.AppConfiguration'},
    'data_factory': {'kind': 'azure_data_factory_selected_declarations',
        'check': 'azure.review.data_factory.selected_declaration_secret_indicators',
        'option': 'selected_azure_data_factory_declarations', 'title': 'Selected Data Factory inline declarations have no detected secrets',
        'service': 'Microsoft.DataFactory'},
    'synapse': {'kind': 'azure_synapse_selected_pipelines',
        'check': 'azure.review.synapse.selected_pipeline_secret_indicators',
        'option': 'selected_azure_synapse_pipelines', 'title': 'Selected Synapse pipeline inline declarations have no detected secrets',
        'service': 'Microsoft.Synapse'},
}
KINDS = tuple(p['kind'] for p in PROFILES.values())
MARKER = 'SelectedDeclarationSecretIndicators'
SCHEMA = 'azure-selected-declaration-secrets-v1'
MAX_TARGETS = 8  # Per profile; total across profiles is also8.
MAX_CALLS = 32
MAX_WIRE = 2 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_CONTENT = 256 * 1024
MAX_VALUES = 2048
MAX_SECONDS = 120
MAX_LEAKS = 256
MAX_LOCATIONS = 512
ETAG = re.compile(r'[A-Za-z0-9_.:/+=-]{1,256}\Z')


class Incomplete(ValueError):
    """Fixed nonsensitive code only."""


def enabled(options, profile):
    return options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'), list) and PROFILES[profile]['kind'] in options['_content_secret_scan_kinds']


def parse(profile, target):
    if not isinstance(target, dict) or set(target) != ({'resource_id', 'key', 'label'} if profile == 'app_configuration' else {'resource_id'}):
        raise Incomplete('invalid_selection')
    rid = target['resource_id']
    patterns = {
        'app_configuration': r'Microsoft\.AppConfiguration/configurationStores/([A-Za-z0-9][A-Za-z0-9_-]{3,48}[A-Za-z0-9])',
        'data_factory': r'Microsoft\.DataFactory/factories/([A-Za-z0-9][A-Za-z0-9-]{1,61}[A-Za-z0-9])/(pipelines|dataflows)/(' + SEG + ')',
        'synapse': r'Microsoft\.Synapse/workspaces/([a-z0-9][a-z0-9-]{1,48}[a-z0-9])/pipelines/(' + SEG + ')',
    }
    match = re.fullmatch(BASE + patterns[profile], rid, re.I) if isinstance(rid, str) and len(rid) <= 1024 else None
    if not match or any(s in ('.', '..') for s in rid.split('/')):
        raise Incomplete('invalid_selection')
    if profile == 'app_configuration':
        for field in ('key', 'label'):
            value = target[field]
            if field == 'label' and value is None:
                continue
            if (not isinstance(value, str) or not 1 <= len(value.encode()) <= 512
                    or any(ord(c) < 32 or ord(c) == 127 for c in value) or any(c in value for c in '*\\,')):
                raise Incomplete('invalid_selection')
    typ = {'app_configuration': 'Microsoft.AppConfiguration/configurationStores',
        'data_factory': 'Microsoft.DataFactory/factories/' + (match[3] if profile == 'data_factory' else ''),
        'synapse': 'Microsoft.Synapse/workspaces/pipelines'}[profile]
    return match[1], rid, typ


def selected_targets(options, scopes, profile=None):
    """Pure root hook/hosted validator; no credential discovery or endpoint input."""
    if (not isinstance(options, dict) or 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
        raise Incomplete('invalid_selection')
    profiles = [profile] if profile is not None else list(PROFILES)
    result = {}; count = 0
    for name in profiles:
        option = PROFILES[name]['option']
        if option not in options and not enabled(options, name):
            result[name] = []; continue
        targets = options.get(option)
        if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
                or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
                or len({s.casefold() for s in scopes}) != len(scopes)
                or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
            raise Incomplete('invalid_selection')
        seen = set()
        for target in targets:
            scope, rid, _ = parse(name, target)
            key = (rid.casefold(), target.get('key'), target.get('label'))
            if scope.casefold() not in {s.casefold() for s in scopes} or key in seen:
                raise Incomplete('invalid_selection')
            seen.add(key)
        result[name] = deepcopy(targets); count += len(targets)
    if count > MAX_TARGETS:
        raise Incomplete('invalid_selection')
    return result[profile] if profile is not None else result


def identity(profile, target):
    # ARM id is case-insensitive; AppConfig key and label are case-sensitive.
    return PROFILES[profile]['kind'] + ':' + _fingerprint(json.dumps({**target, 'resource_id': target['resource_id'].casefold()}, sort_keys=True))


def remaining(reader, state):
    reader.check_cancelled()
    left = state['deadline'] - time.monotonic()
    if left <= 0:
        raise Incomplete('deadline')
    return min(left, 10)


def _pairs(pairs):
    data = {}
    for k, v in pairs:
        if k in data:
            raise Incomplete('duplicate_field')
        data[k] = v
    return data


def _read(reader, transport, state, receipts, ident, scope, operation, host, path, audience, etag=None):
    """Only caller-derived fixed GETs; no generic cache, redirects or error bodies."""
    remaining(reader, state)
    host_class = ('arm' if audience == ARM and host == 'management.azure.com' else
        'app_configuration' if audience == APP_CONFIG and re.fullmatch(r'[a-z0-9][a-z0-9_-]{3,48}[a-z0-9]\.azconfig\.io', host) else
        'synapse' if audience == SYNAPSE and re.fullmatch(r'[a-z0-9][a-z0-9-]{1,48}[a-z0-9]\.dev\.azuresynapse\.net', host) else None)
    if host_class is None or not path.startswith('/') or path.startswith('//') or any(c in path for c in '\r\n'):
        raise Incomplete('untrusted_route')
    if state['calls'] >= MAX_CALLS:
        raise Incomplete('call_limit')
    state['calls'] += 1
    proof = {'id': 'declaration-read-' + str(len(receipts) + 1), 'identity': ident, 'scope': scope,
        'operation': operation, 'method': 'GET', 'host_class': host_class, 'host_binding': _fingerprint(host), 'audience': audience,
        'request_digest': _fingerprint(path), 'capture': state['capture'], 'status': 'unavailable',
        'bytes': 0, 'tenant_id': None, 'identity_bound': False, 'etag_binding': None}
    receipts.append(proof); connection = response = None
    try:
        token = transport.token(audience)
        tenant = getattr(transport, 'verified_tenant', None)
        if (not isinstance(token, str) or not token or any(c in token for c in '\r\n')
                or not isinstance(tenant, str) or not re.fullmatch(GUID, tenant, re.I)
                or str(getattr(transport, 'tenant', '')).casefold() != tenant.casefold()):
            raise Incomplete('tenant_unbound')
        proof['tenant_id'] = tenant
        connection = http.client.HTTPSConnection(host, timeout=remaining(reader, state)); connection.set_debuglevel(0)
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json, application/vnd.microsoft.appconfig.kv+json', 'Accept-Encoding': 'identity', 'Content-Length': '0'}
        if etag is not None:
            headers['If-Match'] = '"' + etag + '"'
        connection.request('GET', path, body=None, headers=headers); del token
        response = connection.getresponse()
        if (response.status != 200 or response.getheader('Content-Encoding') not in (None, '', 'identity')
                or response.getheader('Link') or response.getheader('Location')):
            raise Incomplete('read_unavailable')
        mime = (response.getheader('Content-Type') or '').split(';')[0].strip().lower()
        if mime not in ('application/json', 'application/vnd.microsoft.appconfig.kv+json'):
            raise Incomplete('encoding')
        length = response.getheader('Content-Length')
        if length is not None and (not re.fullmatch(r'[0-9]{1,8}', length) or not 0 < int(length) <= MAX_WIRE):
            raise Incomplete('byte_limit')
        chunks = []; total = 0
        while True:
            timeout = remaining(reader, state)
            if getattr(connection, 'sock', None) is not None:
                connection.sock.settimeout(timeout)
            chunk = response.read(16384)
            if not chunk: break
            total += len(chunk); state['bytes'] += len(chunk); proof['bytes'] = total
            if total > MAX_WIRE or state['bytes'] > MAX_TOTAL:
                raise Incomplete('byte_limit')
            chunks.append(chunk)
        if not total or length is not None and total != int(length):
            raise Incomplete('body_incomplete')
        data = json.loads(b''.join(chunks).decode('utf-8'), object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('nonfinite')))
        if not isinstance(data, dict) or any(k in data for k in ('error', 'nextLink', '@nextLink', 'continuationToken', 'partial', '_partial', '_coverage')):
            raise Incomplete('body_incomplete')
        native_etag = data.get('etag')
        header_etag = response.getheader('ETag')
        if operation in ('key', 'key_bound', 'declaration', 'pipeline'):
            if not isinstance(native_etag, str) or not ETAG.fullmatch(native_etag):
                raise Incomplete('etag_unavailable')
            if header_etag is not None and header_etag != '"' + native_etag + '"':
                raise Incomplete('etag_contradiction')
            if operation in ('key', 'key_bound') and header_etag != '"' + native_etag + '"':
                raise Incomplete('etag_unavailable')
            if etag is not None and native_etag != etag:
                raise Incomplete('etag_changed')
            proof['etag_binding'] = _fingerprint(native_etag)
        proof['status'] = 'collected'
        return data
    except Exception:
        raise Incomplete('read_unavailable') from None
    finally:
        if response is not None: response.close()
        if connection is not None: connection.close()


def _bound(data, rid, typ):
    if (not isinstance(data.get('id'), str) or data['id'].casefold() != rid.casefold()
            or not isinstance(data.get('type'), str) or data['type'].casefold() != typ.casefold()
            or not isinstance(data.get('name'), str) or data['name'].casefold() != rid.rsplit('/', 1)[1].casefold()
            or not isinstance(data.get('properties'), dict)):
        raise Incomplete('identity_unbound')
    return data['properties']


class Projection:
    def __init__(self): self.values = []; self.nodes = 0; self.refs = 0; self.total = 0
    def tree(self, value, depth=0):
        self.nodes += 1
        if depth > 24 or self.nodes > 8192: raise Incomplete('projection_limit')
        if isinstance(value, dict):
            typ = value.get('type', '')
            if not isinstance(typ, str): raise Incomplete('malformed_type')
            if typ.casefold() == 'expression': self.refs += 1
            if typ.casefold() in ('securestring', 'secureobject', 'azurekeyvaultsecret') or typ.casefold().endswith('reference'):
                self.refs += 1; return
            for key, child in value.items():
                if key.casefold() in ('encryptedcredential', 'encryptedcredentials', 'protectedsettings', 'secureinput', 'secureoutput', 'linkedservicename', 'scriptpath', 'scripturi', 'scripturl', 'notebookpath'):
                    self.refs += 1; continue
                if key == 'type': continue
                self.tree(child, depth + 1)
        elif isinstance(value, list):
            for child in value: self.tree(child, depth + 1)
        elif isinstance(value, str):
            if re.search(r'(?i)^@Microsoft\.(?:KeyVault|AppConfiguration)\(|^\*{3,}$', value):
                self.refs += 1; return
            if value:
                raw = value.encode('utf-8'); self.total += len(raw)
                if len(self.values) >= MAX_VALUES or self.total > MAX_CONTENT: raise Incomplete('projection_limit')
                self.values.append(raw)
        elif value is not None and type(value) not in (int, float, bool): raise Incomplete('malformed_literal')


def project(profile, target, data):
    projection = Projection()
    if profile == 'app_configuration':
        if data.get('key') != target['key'] or data.get('label') != target['label']:
            raise Incomplete('key_label_unbound')
        content_type = data.get('content_type')
        if (content_type is not None and not isinstance(content_type, str)) or not isinstance(data.get('value'), str):
            raise Incomplete('value_unavailable')
        if content_type and ('keyvault' in content_type.casefold() or 'encrypted' in content_type.casefold()):
            raise Incomplete('protected_reference_excluded')
        projection.tree(data['value'])
    else:
        _, rid, typ = parse(profile, target); props = _bound(data, rid, typ)
        if rid.casefold().split('/')[-2] == 'dataflows':
            if props.get('type') != 'MappingDataFlow' or not isinstance(props.get('typeProperties'), dict):
                raise Incomplete('unsupported_dataflow')
            source = props['typeProperties']; script = source.get('scriptLines', source.get('script'))
            if (not isinstance(script, (str, list)) or not script
                    or isinstance(script, list) and any(not isinstance(line, str) for line in script)):
                raise Incomplete('inline_script_unavailable')
            projection.tree(script)
            # Native source/sink/transformation declarations may contain inline
            # literals or references. Never follow datasets/linked services.
            for name in ('sources', 'sinks', 'transformations'):
                if name in source:
                    if not isinstance(source[name], list) or any(not isinstance(row, dict) for row in source[name]):
                        raise Incomplete('malformed_dataflow')
                    projection.tree(source[name])
        else:
            activities = props.get('activities')
            if not isinstance(activities, list) or not activities: raise Incomplete('activities_unavailable')
            for activity in activities:
                if (not isinstance(activity, dict) or not isinstance(activity.get('name'), str) or not activity['name']
                        or not isinstance(activity.get('type'), str) or not activity['type']
                        or not isinstance(activity.get('typeProperties'), dict)):
                    raise Incomplete('malformed_activity')
                projection.tree(activity['typeProperties'])
            for name in ('parameters', 'variables'):
                if name in props:
                    if not isinstance(props[name], dict): raise Incomplete('malformed_defaults')
                    projection.tree(props[name])
    return projection


def _scan(reader, transport, profile, target, scope, state, receipts):
    ident = identity(profile, target); start = len(receipts)
    marker = {'schema': SCHEMA, 'identity': ident, 'scope': scope, 'profile': profile, 'capture': state['capture'],
        'complete': False, 'parts': [], 'leaks': [], 'source_requests': [], 'literal_count': 0,
        'reference_count': 0, 'verification': 'not_attempted'}
    try:
        _, rid, typ = parse(profile, target)
        def read(operation, host, path, audience, etag=None):
            return reader.call(_read, reader, transport, state, receipts, ident, scope, operation, host, path, audience, etag)
        sub = read('subscription', 'management.azure.com', scope + '?api-version=2022-12-01', ARM)
        if (str(sub.get('id', '')).casefold() != scope.casefold() or sub.get('subscriptionId', '').casefold() != scope.rsplit('/', 1)[1].casefold()
                or str(sub.get('tenantId', '')).casefold() != str(transport.verified_tenant).casefold() or sub.get('state') != 'Enabled'):
            raise Incomplete('subscription_unbound')
        receipts[-1]['identity_bound'] = True; del sub
        if profile == 'app_configuration':
            store = read('store', 'management.azure.com', rid + '?api-version=2024-06-01', ARM)
            props = _bound(store, rid, typ); name = rid.rsplit('/', 1)[1].lower(); host = name + '.azconfig.io'
            if props.get('endpoint') not in ('https://' + host, 'https://' + host + '/') or props.get('provisioningState') != 'Succeeded':
                raise Incomplete('endpoint_unbound')
            receipts[-1]['identity_bound'] = True; del store, props
            path = '/kv/' + quote(target['key'], safe='') + '?label=' + ('%00' if target['label'] is None else quote(target['label'], safe='')) + '&api-version=1.0'
            first = read('key', host, path, APP_CONFIG)
            project(profile, target, first); receipts[-1]['identity_bound'] = True
            etag = first['etag']; data = read('key_bound', host, path, APP_CONFIG, etag)
            # ETag reuse with a different body is an identity/coherence failure.
            if data != first: raise Incomplete('body_changed')
            del first, etag
        elif profile == 'synapse':
            workspace_id = rid.rsplit('/pipelines/', 1)[0] if '/pipelines/' in rid else '/'.join(rid.split('/')[:-2])
            workspace = read('workspace', 'management.azure.com', workspace_id + '?api-version=2021-06-01', ARM)
            props = _bound(workspace, workspace_id, 'Microsoft.Synapse/workspaces')
            host = workspace_id.rsplit('/', 1)[1].lower() + '.dev.azuresynapse.net'
            endpoint = props.get('connectivityEndpoints', {}).get('dev')
            if endpoint not in (host, 'https://' + host, 'https://' + host + '/') or props.get('provisioningState') != 'Succeeded':
                raise Incomplete('endpoint_unbound')
            receipts[-1]['identity_bound'] = True; del workspace, props
            data = read('pipeline', host, '/pipelines/' + quote(rid.rsplit('/', 1)[1], safe='') + '?api-version=2020-12-01', SYNAPSE)
        else:
            data = read('declaration', 'management.azure.com', rid + '?api-version=2018-06-01', ARM)
        projection = project(profile, target, data); receipts[-1]['identity_bound'] = True; del data
        marker.update(literal_count=len(projection.values), reference_count=projection.refs)
        payload = b'\n\n'.join(projection.values)
        if not payload or len(payload) > MAX_CONTENT: raise Incomplete('content_unavailable')
        result = scan_content(payload, ident + '.inline_literals', timeout=remaining(reader, state) / 2,
            _redact_values=lambda values: remember(reader, 'configuration_secret_redactions', values))
        marker['parts'] = [{'bytes': len(payload), 'engines': deepcopy(result['engines']), 'complete': result['complete']}]
        leaks = merge_leaks(result['leaks']); bounded = []; locations = 0
        for leak in leaks:
            if len(bounded) >= MAX_LEAKS or locations + len(leak['locations']) > MAX_LOCATIONS: break
            bounded.append(leak); locations += len(leak['locations'])
        marker['leaks'] = bounded; limited = len(bounded) != len(leaks)
        del payload, projection.values
        remaining(reader, state)
        marker['complete'] = result['complete'] is True and not projection.refs and not limited
    except Exception:
        marker['complete'] = False
    marker['source_requests'] = [r['id'] for r in receipts[start:]]
    return {'id': ident, MARKER: marker, '_provenance': {'scope': scope, 'capture': state['capture'], 'source_requests': marker['source_requests'][:]}}


def collect(reader, transport, scopes, wanted, options):
    targets = selected_targets(options, scopes)
    if not hasattr(reader, 'configuration_secret_redactions'): reader.configuration_secret_redactions = set()
    reader.declaration_secret_metadata = {}
    state = {'capture': 'declaration-capture:' + uuid4().hex, 'deadline': time.monotonic() + MAX_SECONDS, 'bytes': 0, 'calls': 0}
    for profile, details in PROFILES.items():
        kind = details['kind']
        if kind not in wanted: continue
        receipts = []
        reader.declaration_secret_metadata.update({kind + '_authorized': enabled(options, profile), kind + '_capture': state['capture'],
            kind + '_selection': {s: [identity(profile, t) for t in targets[profile] if parse(profile, t)[0].casefold() == s.casefold()] for s in scopes}, kind + '_receipts': receipts})
        if not enabled(options, profile): continue
        for scope in scopes:
            selected = [t for t in targets[profile] if parse(profile, t)[0].casefold() == scope.casefold()]
            if selected:
                def fetch(selected=selected, scope=scope, profile=profile, receipts=receipts):
                    yield [_scan(reader, transport, profile, t, scope, state, receipts) for t in selected]
                reader.run([(kind, scope, details['service'], fetch)])


def final_snapshot(reader, snapshot):
    """Proposed root hook: merge this ledger BEFORE existing5-reader union."""
    snapshot.setdefault('metadata', {}).update(getattr(reader, 'declaration_secret_metadata', {}))
    from .azure_selected_secret_integration_20261020 import final_snapshot as union
    return union(reader, snapshot)
