"""Optional exact native reads of selected Kubernetes text fields.

Proposal: reuses the installed literal transport, receipts, offline detectors and
redaction. No list, Secret, exec, reference resolution or registry access.
"""
from types import FunctionType
from peaso.collectors import k8s_literal_secret_indicators as base
from peaso.collectors.k8s_selected_log_sample_secret_indicators import private_native_logs, _wire_debug_enabled

KIND = 'k8s_selected_text_content'
CHECK = 'k8s.review.selected_text_content.secret_indicators'
OPTION = 'selected_k8s_text_resources'
MARKER = 'SelectedKubernetesTextSecretIndicators'
SCHEMA = 'k8s-selected-text-secrets-v1'
Incomplete = base.Incomplete
NATIVE_KINDS = {
    'Event': ('v1', 'events', None),
    'Ingress': ('networking.k8s.io/v1', 'ingresses', None),
    'Gateway': ('gateway.networking.k8s.io/v1', 'gateways', None),
    'CustomResourceDefinition': ('apiextensions.k8s.io/v1', 'customresourcedefinitions', None),
}


def _path(target):
    version, plural, _ = NATIVE_KINDS[target['kind']]
    prefix = '/api/v1' if version == 'v1' else '/apis/' + version
    if target['kind'] == 'CustomResourceDefinition':
        if target['namespace'] != 'cluster':
            raise Incomplete('invalid_cluster_scoped_selector')
        return prefix + '/' + plural + '/' + target['name']
    return prefix + '/namespaces/' + target['namespace'] + '/' + plural + '/' + target['name']


def _extract(document, target):
    if not isinstance(document, dict):
        raise Incomplete('malformed_native_response')
    kind = target['kind']
    meta = document.get('metadata')
    if (document.get('apiVersion') != NATIVE_KINDS[kind][0] or document.get('kind') != kind
            or any(field in document for field in ('items', 'continue', 'partial', '_partial', '_coverage', 'hasMore'))
            or not isinstance(meta, dict)
            or any(field in meta for field in ('continue', 'remainingItemCount', '_partial', '_coverage'))
            or meta.get('name') != target['name'] or meta.get('deletionTimestamp') is not None
            or (meta.get('namespace') not in (None, '') if kind == 'CustomResourceDefinition'
                else meta.get('namespace') != target['namespace'])
            or any(not isinstance(meta.get(field), str) or not 1 <= len(meta[field]) <= 253
                or any(ord(char) < 33 or ord(char) > 126 for char in meta[field])
                for field in ('uid', 'resourceVersion'))):
        raise Incomplete('native_identity_unresolved')
    values = [target['cluster_id'], target['namespace'], target['name'], meta['uid'], meta['resourceVersion']]
    count = 0

    def obj(parent, field):
        value = parent.get(field, {})
        if not isinstance(value, dict):
            raise Incomplete('malformed_selected_field')
        return value

    def seq(parent, field):
        value = parent.get(field, [])
        if not isinstance(value, list) or len(value) > base.MAX_LITERALS:
            raise Incomplete('malformed_selected_field')
        return value

    def add(value):
        nonlocal count
        if not isinstance(value, str) or '\x00' in value or len(value.encode('utf-8')) > base.MAX_VALUE:
            raise Incomplete('unsupported_selected_text')
        if value:
            values.append(value)
            count += 1
        if count > base.MAX_LITERALS:
            raise Incomplete('literal_count_limit')

    def annotations():
        for key, value in sorted(obj(meta, 'annotations').items(), key=lambda pair: str(pair[0])):
            if not isinstance(key, str) or not key or len(key) > 253:
                raise Incomplete('malformed_annotation')
            add(key)
            add(value)

    annotations()
    if kind != 'Event' and 'spec' not in document:
        raise Incomplete('missing_selected_spec')
    if kind == 'Event':
        for field in ('message', 'reason', 'action', 'reportingComponent'):
            if field in document:
                add(document[field])
        source = obj(document, 'source')
        if 'component' in source:
            add(source['component'])
    elif kind == 'Ingress':
        spec = obj(document, 'spec')
        for rule in seq(spec, 'rules'):
            if not isinstance(rule, dict):
                raise Incomplete('malformed_selected_field')
            if 'host' in rule:
                add(rule['host'])
            for path in seq(obj(rule, 'http'), 'paths'):
                if not isinstance(path, dict):
                    raise Incomplete('malformed_selected_field')
                if 'path' in path:
                    add(path['path'])
        for tls in seq(spec, 'tls'):
            if not isinstance(tls, dict):
                raise Incomplete('malformed_selected_field')
            for host in seq(tls, 'hosts'):
                add(host)
    elif kind == 'Gateway':
        spec = obj(document, 'spec')
        for address in seq(spec, 'addresses'):
            if not isinstance(address, dict):
                raise Incomplete('malformed_selected_field')
            if 'value' in address:
                add(address['value'])
        for listener in seq(spec, 'listeners'):
            if not isinstance(listener, dict):
                raise Incomplete('malformed_selected_field')
            for field in ('name', 'hostname'):
                if field in listener:
                    add(listener[field])
    else:
        spec = obj(document, 'spec')
        for field in ('group',):
            if field in spec:
                add(spec[field])
        names = obj(spec, 'names')
        for field in ('kind', 'plural', 'singular', 'listKind'):
            if field in names:
                add(names[field])
        for version in seq(spec, 'versions'):
            if not isinstance(version, dict):
                raise Incomplete('malformed_selected_field')
            if 'name' in version:
                add(version['name'])
            schema = obj(version, 'schema')
            openapi = obj(schema, 'openAPIV3Schema')
            if 'description' in openapi:
                add(openapi['description'])
        webhook = obj(obj(spec, 'conversion'), 'webhook')
        config = obj(webhook, 'clientConfig')
        if 'url' in config:
            add(config['url'])
    if not count:
        raise Incomplete('no_selected_text')
    payload = '\n'.join(values).encode('utf-8')
    if len(payload) > base.MAX_CONTENT:
        raise Incomplete('literal_byte_limit')
    return payload, meta['uid'], meta['resourceVersion'], count, 0


_GLOBALS = {**vars(base), '__name__': __name__, 'KIND': KIND, 'CHECK': CHECK,
            'OPTION': OPTION, 'MARKER': MARKER, 'SCHEMA': SCHEMA,
            'NATIVE_KINDS': NATIVE_KINDS, '_path': _path, '_extract': _extract}
for _name in ('enabled', 'selected_targets', 'identity', '_remaining', '_pairs', '_read', 'collect'):
    _original = getattr(base, _name)
    _GLOBALS[_name] = FunctionType(_original.__code__, _GLOBALS, _name,
                                   _original.__defaults__, _original.__closure__)
enabled = _GLOBALS['enabled']
_base_targets = _GLOBALS['selected_targets']


def selected_targets(options, scopes):
    targets = _base_targets(options, scopes)
    if any(target['kind'] == 'CustomResourceDefinition' and target['namespace'] != 'cluster'
           for target in targets):
        raise Incomplete('invalid_cluster_scoped_selector')
    return targets


_GLOBALS['selected_targets'] = selected_targets
identity = _GLOBALS['identity']
_native_read = _GLOBALS['_read']


def _read(reader, api, target, state):
    client = getattr(getattr(api, 'api', api), 'api_client', None)
    pool = getattr(getattr(client, 'rest_client', None), 'pool_manager', None)
    if _wire_debug_enabled(getattr(pool, 'pool', None)):
        raise Incomplete('native_wire_debug_enabled')
    return _native_read(reader, api, target, state)


_GLOBALS['_read'] = _read


def collect(reader, api, options, scopes, cluster):
    if enabled(options):
        with private_native_logs():
            return _GLOBALS['collect'](reader, api, options, scopes, cluster)
    return _GLOBALS['collect'](reader, api, options, scopes, cluster)


redact_output = base.redact_output
