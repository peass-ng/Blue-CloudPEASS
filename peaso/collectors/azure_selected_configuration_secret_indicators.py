"""Default-off exact ARM configuration reads, ephemeral plaintext, offline scans.

No enumeration, execution, arbitrary URLs, secret-store dereference or writes.
Only opaque locators, finite counts and canonical redacted findings survive.
"""

from peaso.secret_evidence import scan_with_source, target_source
import base64
from copy import deepcopy
import http.client
import json
import re
import time
from uuid import uuid4

from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint, redact_matches

KIND = 'azure_configuration_selected_content'
CHECK = 'azure.review.configuration.selected_content_secret_indicators'
OPTION = 'selected_azure_configuration_content'
MARKER = 'SelectedArmConfigurationSecretIndicators'
SCHEMA = 'azure-selected-arm-configuration-v1'
HOST = 'management.azure.com'
MAX_TARGETS = 8
MAX_CALLS = 16
MAX_WIRE = 2 * 1024 * 1024
MAX_CONTENT = 256 * 1024
MAX_USERDATA = 64 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_VALUES = 2048
MAX_LEAKS = 256
MAX_LOCATIONS = 512
MAX_SECONDS = 120
GUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
SCOPE = re.compile(r'/subscriptions/' + GUID + r'\Z', re.I)
SEGMENT = r'[A-Za-z0-9_()-][A-Za-z0-9_.();=-]{0,126}'
BASE = r'(/subscriptions/' + GUID + r')/resourceGroups/' + SEGMENT + r'/providers/'
# Surface -> native type, exact route pattern, stable API version. APIM variants
# share the PolicyContract schema but retain their distinct native child types.
SURFACES = {
    'aci_literals': ('Microsoft.ContainerInstance/containerGroups', r'Microsoft\.ContainerInstance/containerGroups/' + SEGMENT, '2023-05-01'),
    'container_app_literals': ('Microsoft.App/containerApps', r'Microsoft\.App/containerApps/' + SEGMENT, '2024-03-01'),
    'logic_workflow': ('Microsoft.Logic/workflows', r'Microsoft\.Logic/workflows/' + SEGMENT, '2016-06-01'),
    'vm_userdata': ('Microsoft.Compute/virtualMachines', r'Microsoft\.Compute/virtualMachines/' + SEGMENT, '2025-04-01'),
    'vmss_model_userdata': ('Microsoft.Compute/virtualMachineScaleSets', r'Microsoft\.Compute/virtualMachineScaleSets/' + SEGMENT, '2025-04-01'),
    'vm_extension_settings': ('Microsoft.Compute/virtualMachines/extensions', r'Microsoft\.Compute/virtualMachines/' + SEGMENT + r'/extensions/' + SEGMENT, '2025-04-01'),
    'image_builder_inline': ('Microsoft.VirtualMachineImages/imageTemplates', r'Microsoft\.VirtualMachineImages/imageTemplates/' + SEGMENT, '2022-07-01'),
    'automation_runbook': ('Microsoft.Automation/automationAccounts/runbooks', r'Microsoft\.Automation/automationAccounts/' + SEGMENT + r'/runbooks/' + SEGMENT, '2023-11-01'),
    'automation_variable': ('Microsoft.Automation/automationAccounts/variables', r'Microsoft\.Automation/automationAccounts/' + SEGMENT + r'/variables/' + SEGMENT, '2023-11-01'),
    'apim_policy': ('Microsoft.ApiManagement/service/policies', r'Microsoft\.ApiManagement/service/' + SEGMENT + r'(?:/apis/' + SEGMENT + r'(?:/operations/' + SEGMENT + r')?)?/policies/policy', '2024-05-01'),
}


class Incomplete(ValueError):
    """Stable non-sensitive errors only."""


def enabled(options):
    return (options.get('content_secret_scans') is True
            and isinstance(options.get('_content_secret_scan_kinds'), list)
            and KIND in options['_content_secret_scan_kinds'])


def parse(target):
    if (not isinstance(target, dict) or set(target) != {'surface', 'resource_id'}
            or not isinstance(target['surface'], str) or target['surface'] not in SURFACES
            or not isinstance(target['resource_id'], str) or len(target['resource_id']) > 1024):
        raise Incomplete('invalid_configuration_selection')
    surface, rid = target['surface'], target['resource_id']
    typ, pattern, version = SURFACES[surface]
    match = re.fullmatch(BASE + pattern, rid, re.I)
    if not match or '/.' in rid or any(p in ('.', '..') for p in rid.split('/')):
        raise Incomplete('invalid_configuration_selection')
    if surface == 'apim_policy':
        typ = 'Microsoft.ApiManagement/service' + ('/apis' if '/apis/' in rid.casefold() else '') + (
            '/operations' if '/operations/' in rid.casefold() else '') + '/policies'
    return surface, match[1], rid, typ, version


def selected_targets(options, scopes):
    if (not isinstance(options, dict) or 'content_secret_scans' in options
            and type(options['content_secret_scans']) is not bool):
        raise Incomplete('invalid_configuration_selection')
    if OPTION not in options and not enabled(options):
        return []
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
            or len({s.casefold() for s in scopes}) != len(scopes)
            or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
        raise Incomplete('invalid_configuration_selection')
    seen = set()
    for target in targets:
        _, scope, rid, _, _ = parse(target)
        if scope.casefold() not in {s.casefold() for s in scopes} or rid.casefold() in seen:
            raise Incomplete('invalid_configuration_selection')
        seen.add(rid.casefold())
    return deepcopy(targets)


def identity(target):
    return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True).casefold())


def route(target, content=False):
    surface, _, rid, _, version = parse(target)
    return (rid + ('/content' if content else '') + '?api-version=' + version
            + ('&$expand=userData' if surface in ('vm_userdata', 'vmss_model_userdata') else '')
            + ('&format=rawxml' if surface == 'apim_policy' else ''))


def remaining(reader, state):
    reader.check_cancelled()
    left = state['deadline'] - time.monotonic()
    if left <= 0:
        raise Incomplete('configuration_deadline')
    return min(left, 10)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Incomplete('duplicate_native_field')
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('nonfinite_native_field')))


def _read(reader, transport, target, state, receipts, scope, content=False):
    """Dedicated bounded streaming GET, bypassing generic caches and redirects."""
    remaining(reader, state)
    if state['calls'] >= MAX_CALLS:
        raise Incomplete('configuration_call_limit')
    state['calls'] += 1
    surface, _, _, _, version = parse(target)
    receipt = {'id': 'arm-config-read-' + str(len(receipts) + 1), 'identity': identity(target),
        'scope': scope, 'surface': surface, 'method': 'GET', 'host': HOST, 'api_version': version,
        'operation': 'published_content' if content else 'selected_resource',
        'request_digest': _fingerprint(route(target, content)), 'capture': state['capture'],
        'status': 'unavailable', 'http_status': None, 'bytes': 0, 'identity_bound': False,
        'tenant_id': None, 'tenant_bound': False}
    receipts.append(receipt)
    connection = response = None
    try:
        token = transport.token('https://' + HOST)
        tenant = getattr(transport, 'verified_tenant', None)
        if (not isinstance(token, str) or not token or '\n' in token or '\r' in token
                or not isinstance(tenant, str) or not re.fullmatch(GUID, tenant, re.I)
                or str(getattr(transport, 'tenant', '')).casefold() != tenant.casefold()):
            raise Incomplete('authenticated_tenant_unbound')
        receipt.update(tenant_id=tenant, tenant_bound=True)
        connection = http.client.HTTPSConnection(HOST, timeout=remaining(reader, state))
        connection.set_debuglevel(0)
        connection.request('GET', route(target, content), body=None, headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'text/powershell' if content else 'application/json',
            'Accept-Encoding': 'identity', 'Content-Length': '0'})
        del token
        response = connection.getresponse()
        receipt['http_status'] = response.status
        if response.status != 200 or response.getheader('Content-Encoding') not in (None, '', 'identity'):
            raise Incomplete('native_read_unavailable')
        mime = (response.getheader('Content-Type') or '').split(';')[0].strip().lower()
        if mime not in (('text/powershell', 'text/plain') if content else ('application/json',)):
            raise Incomplete('unsupported_native_encoding')
        length = response.getheader('Content-Length')
        if length is not None and (not re.fullmatch('[0-9]{1,8}', length) or not 0 < int(length) <= MAX_WIRE):
            raise Incomplete('native_byte_limit')
        chunks, size = [], 0
        while True:
            timeout = remaining(reader, state)
            if getattr(connection, 'sock', None) is not None:
                connection.sock.settimeout(timeout)
            chunk = response.read(16384)
            if not chunk:
                break
            size += len(chunk); state['bytes'] += len(chunk); receipt['bytes'] = size
            if size > MAX_WIRE or state['bytes'] > MAX_TOTAL:
                raise Incomplete('native_byte_limit')
            chunks.append(chunk)
        if not size or length is not None and int(length) != size:
            raise Incomplete('native_body_incomplete')
        raw = b''.join(chunks)
        data = raw.decode('utf-8', errors='strict') if content else _json(raw)
        if not content and (not isinstance(data, dict) or any(k in data for k in
                ('error', 'nextLink', 'continuationToken', '_coverage', '_partial', 'partial', 'hasMore'))):
            raise Incomplete('native_body_incomplete')
        receipt['status'] = 'collected'
        return data
    except Exception:
        raise Incomplete('native_read_unavailable') from None
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()


def _bound(data, target):
    surface, _, rid, typ, _ = parse(target)
    # Automation's documented models allow absent type, but any supplied type
    # must match. Their native full id + named endpoint bind the resource kind.
    native_type = data.get('type')
    if (not isinstance(data.get('id'), str) or data['id'].casefold() != rid.casefold()
            or native_type is None and surface not in ('automation_runbook', 'automation_variable')
            or native_type is not None and (not isinstance(native_type, str) or native_type.casefold() != typ.casefold())
            or not isinstance(data.get('name'), str) or data['name'].casefold() != rid.rsplit('/', 1)[1].casefold()
            or not isinstance(data.get('properties'), dict)):
        raise Incomplete('native_identity_unbound')
    return data['properties']


class Projection:
    def __init__(self):
        self.values = []; self.references = 0; self.unresolved = False; self.size = 0

    def text(self, value):
        if not isinstance(value, str):
            self.unresolved = True; return
        raw = value.encode('utf-8', errors='strict')
        if any(ord(c) < 32 and c not in '\t\r\n' or ord(c) == 127 for c in value):
            self.unresolved = True; return
        if re.search(r'(?i)(?:\*{3,}|\[redacted\]|<redacted>|<hidden>)', value):
            self.unresolved = True
        self.size += len(raw) + 2
        if self.size > MAX_CONTENT or len(self.values) >= MAX_VALUES:
            raise Incomplete('content_byte_limit')
        if raw:
            self.values.append(raw)

    def tree(self, value, depth=0):
        if depth > 32:
            raise Incomplete('native_depth_limit')
        if isinstance(value, dict):
            for key, member in value.items():
                self.text(key); self.tree(member, depth + 1)
        elif isinstance(value, list):
            for member in value:
                self.tree(member, depth + 1)
        elif isinstance(value, str):
            self.text(value)
        elif value is not None and type(value) not in (bool, int, float):
            self.unresolved = True

    def ref(self):
        self.references += 1; self.unresolved = True


def _containers(projection, containers, aci=False):
    if not isinstance(containers, list) or not containers or len(containers) > 128:
        projection.unresolved = True; return
    for container in containers:
        if not isinstance(container, dict) or not isinstance(container.get('name'), str):
            projection.unresolved = True; continue
        props = container.get('properties') if aci else container
        if not isinstance(props, dict):
            projection.unresolved = True; continue
        for key in ('command',) if aci else ('command', 'args'):
            values = props.get(key, [])
            if not isinstance(values, list):
                projection.unresolved = True; continue
            for value in values:
                projection.text(value)
        env = props.get('environmentVariables' if aci else 'env', [])
        if not isinstance(env, list):
            projection.unresolved = True; continue
        for row in env:
            if not isinstance(row, dict) or not isinstance(row.get('name'), str):
                projection.unresolved = True; continue
            reference = 'secureValue' if aci else 'secretRef'
            if reference in row:
                projection.ref()
                if 'value' in row:
                    projection.unresolved = True
            elif 'value' in row:
                projection.text(row['value'])
            else:
                projection.unresolved = True


def project(surface, props):
    """Scan only the declared selected surface, never unrelated response fields."""
    p = Projection()
    if surface in ('aci_literals', 'container_app_literals'):
        template = props if surface == 'aci_literals' else props.get('template')
        if not isinstance(template, dict):
            raise Incomplete('literal_template_unavailable')
        _containers(p, template.get('containers'), surface == 'aci_literals')
        if 'initContainers' in template:
            _containers(p, template['initContainers'], surface == 'aci_literals')
    elif surface == 'logic_workflow':
        definition = props.get('definition')
        if not isinstance(definition, dict) or not definition:
            raise Incomplete('workflow_definition_unavailable')
        p.tree(definition)
        # Definitions can reference parameters, connectors and external code.
        # Scan the definition only, without resolving parameter values or links.
        text = json.dumps(definition)
        if re.search(r'(?i)(parameters\s*\(|integrationaccount|workflowreference|scripturi|contentlink)', text):
            p.ref()
    elif surface in ('vm_userdata', 'vmss_model_userdata'):
        native = props if surface == 'vm_userdata' else props.get('virtualMachineProfile', {})
        encoded = native.get('userData') if isinstance(native, dict) else None
        if not isinstance(encoded, str) or not encoded or len(encoded) > MAX_USERDATA * 2:
            raise Incomplete('userdata_unavailable')
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode() != encoded or len(raw) > MAX_USERDATA:
            raise Incomplete('userdata_encoding_unsupported')
        p.text(raw.decode('utf-8', errors='strict'))
    elif surface == 'vm_extension_settings':
        settings = props.get('settings')
        if not isinstance(settings, dict) or not settings:
            raise Incomplete('public_settings_unavailable')
        p.tree(settings)
        if any(k.casefold() in ('fileuris', 'scripturi', 'scripturl') for k in settings):
            p.ref()
    elif surface == 'image_builder_inline':
        customizers = props.get('customize')
        if not isinstance(customizers, list) or not customizers or len(customizers) > 128:
            raise Incomplete('customizers_unavailable')
        for customizer in customizers:
            if not isinstance(customizer, dict):
                p.unresolved = True; continue
            if customizer.get('type') in ('Shell', 'PowerShell'):
                if 'scriptUri' in customizer:
                    p.ref()
                if isinstance(customizer.get('inline'), list):
                    for value in customizer['inline']:
                        p.text(value)
                else:
                    p.unresolved = True
            else:
                p.ref()
    elif surface == 'automation_variable':
        if props.get('isEncrypted') is not False:
            raise Incomplete('encrypted_or_unknown_variable_excluded')
        value = props.get('value')
        if not isinstance(value, str):
            raise Incomplete('variable_value_unavailable')
        p.tree(_json(value.encode('utf-8')))
    elif surface == 'apim_policy':
        if props.get('format') != 'rawxml' or not isinstance(props.get('value'), str):
            raise Incomplete('inline_policy_unavailable')
        value = props['value']
        # No XML evaluation or entity expansion. Unknown/external fragments
        # cannot make a negative detection a complete clean result.
        p.text(value)
        if (not re.search(r'<policies(?:\s|>)', value) or '<!DOCTYPE' in value.upper()
                or '<!ENTITY' in value.upper()):
            p.unresolved = True
        if re.search(r'\{\{|<\s*(?:base|include-fragment)\b', value):
            p.ref()
    else:
        raise Incomplete('unsupported_surface')
    return p


def _scan(reader, transport, target, scope, state, receipts):
    surface, _, _, _, _ = parse(target); ident = identity(target)
    marker = {'schema': SCHEMA, 'identity': ident, 'scope': scope, 'surface': surface,
        'capture': state['capture'], 'complete': False, 'reason': 'incomplete',
        'verification': 'not_attempted', 'parts': [], 'leaks': [], 'source_requests': [],
        'literal_count': 0, 'reference_count': 0}
    start = len(receipts)
    try:
        data = reader.call(_read, reader, transport, target, state, receipts, scope)
        props = _bound(data, target); receipts[-1]['identity_bound'] = True
        if surface == 'automation_runbook':
            if props.get('runbookType') not in ('PowerShell', 'PowerShellWorkflow', 'PowerShell72', 'Python2', 'Python3') or props.get('state') != 'Published':
                raise Incomplete('published_text_runbook_unavailable')
            del data, props
            text = reader.call(_read, reader, transport, target, state, receipts, scope, True)
            receipts[-1]['identity_bound'] = True
            projection = Projection(); projection.text(text); del text
        else:
            projection = project(surface, props); del props
        marker.update(literal_count=len(projection.values), reference_count=projection.references)
        payload = b'\n\n'.join(projection.values)
        if not payload or len(payload) > MAX_CONTENT:
            raise Incomplete('literal_content_unavailable')
        result = scan_with_source(scan_content, payload, ident + '.selected_literals',
            timeout=remaining(reader, state) / 2,
            _redact_values=lambda values: reader.configuration_secret_redactions.update(values), source=target_source(target, resource_id=ident, scope=scope, location_kind='configuration'), native=data if surface != 'automation_runbook' else None)
        marker['parts'] = [{'bytes': len(payload), 'engines': deepcopy(result['engines']),
                            'complete': result['complete']}]
        del payload
        marker['leaks'] = merge_leaks(result['leaks'])
        if (len(marker['leaks']) > MAX_LEAKS or
                sum(len(l['locations']) for l in marker['leaks']) > MAX_LOCATIONS):
            raise Incomplete('finding_limit')
        remaining(reader, state)
        marker['complete'] = result['complete'] is True and not projection.unresolved
        marker['reason'] = 'complete' if marker['complete'] else 'coverage_incomplete'
    except Exception:
        marker['reason'] = 'incomplete'
    marker['source_requests'] = [r['id'] for r in receipts[start:]]
    return {'id': ident, MARKER: marker, '_provenance': {'scope': scope,
        'source_requests': list(marker['source_requests']), 'capture': state['capture']}}


def collect(reader, transport, scopes, wanted, options):
    if KIND not in wanted:
        return
    targets = selected_targets(options, scopes)
    capture = 'arm-config-capture:' + uuid4().hex
    reader.configuration_secret_redactions = set()
    reader.configuration_secret_metadata = {KIND + '_authorized': enabled(options),
        KIND + '_selection': {s: [identity(t) for t in targets if parse(t)[1].casefold() == s.casefold()] for s in scopes},
        KIND + '_capture': capture, KIND + '_receipts': []}
    if not enabled(options):
        return
    state = {'deadline': time.monotonic() + MAX_SECONDS, 'bytes': 0, 'calls': 0, 'capture': capture}
    receipts = reader.configuration_secret_metadata[KIND + '_receipts']
    for scope in scopes:
        names = [t for t in targets if parse(t)[1].casefold() == scope.casefold()]
        if names:
            def fetch(names=names, scope=scope):
                yield [_scan(reader, transport, t, scope, state, receipts) for t in names]
            # Serial jobs share hard bytes/calls/deadline; scanner subprocesses
            # are bounded and offline. Content never enters Reader._read.
            reader.run([(KIND, scope, 'Microsoft.Resources', fetch)])


def final_snapshot(reader, snapshot):
    """Union scrub mixed-inventory metadata too; clear ephemeral values finally."""
    values = getattr(reader, 'configuration_secret_redactions', set())
    try:
        if values:
            from peaso.snapshot import seal
            snapshot = seal(redact_matches(snapshot, values))
        return snapshot
    finally:
        values.clear()
