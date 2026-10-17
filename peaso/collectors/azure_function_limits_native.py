"""Strict ARM Function/APIM configuration joins; never invokes a function.

An explicit operation policy that replaces inheritance can prove absence of a
rate limit. A configured limit cannot prove enforcement: no active-probe result
is synthesized. Unresolved routes, slots, workspaces or policies remain UNKNOWN.
"""
from datetime import datetime, timezone
import copy
import re
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

ARM = 'https://management.azure.com'
WEB_VERSION = '2025-03-01'
APIM_VERSION = '2024-05-01'
KIND = 'function_app'
NATIVE_TYPES = {KIND}
METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'}


def required_types(wanted, options=None):
    if KIND not in wanted:
        return set()
    parent = (options or {}).get('compliance_policy')
    raw = parent.get('sw15') if isinstance(parent, dict) else None
    return {'app_service', 'api_management', 'apim_native'} if isinstance(raw, dict) else {'app_service'}


def complete(reader, kind, scope):
    rows = [c for c in reader.collections if c['type'] == kind and c['scope'].casefold() == scope.casefold()]
    if len(rows) != 1 or rows[0]['status'] not in ('collected', 'empty'):
        raise ValueError('complete parent inventory unavailable')
    value = rows[0]['items']
    if not isinstance(value, list) or (rows[0]['status'] == 'empty') != (not value):
        raise ValueError('parent inventory contradictory')
    return value


def identity(row, parent, suffix):
    value = row.get('id') if isinstance(row, dict) else None
    if (not isinstance(value, str) or not re.fullmatch(re.escape(parent) + suffix, value, re.I)
            or any(p in ('.', '..') for p in value.split('/')) or '\\' in value):
        raise ValueError('foreign native identity')
    return value


def url(value):
    if not isinstance(value, str):
        raise ValueError('literal backend route unavailable')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.port is not None or parsed.query or parsed.fragment
            or not re.fullmatch(r'[A-Za-z0-9.-]+', parsed.hostname)
            or not re.fullmatch(r'/[A-Za-z0-9/_-]*', parsed.path or '/')
            or any(p in ('.', '..') for p in parsed.path.split('/'))):
        raise ValueError('dynamic or ambiguous backend route')
    return parsed.hostname.casefold(), parsed.path.rstrip('/')


def policy_projection(raw, operation_id):
    """Only a tiny metadata-only XML grammar is retained, never arbitrary XML."""
    identity(raw, operation_id, r'/policies/policy')
    props = raw.get('properties')
    if not isinstance(props, dict) or props.get('format') != 'rawxml':
        raise ValueError('raw operation policy unavailable')
    text = props.get('value')
    if (not isinstance(text, str) or len(text) > 65536 or '<!' in text
            or '<?' in text or '@' in text or '{{' in text or '}}' in text):
        raise ValueError('policy expression or declaration unresolved')
    root = ET.fromstring(text)
    if root.tag != 'policies' or root.attrib:
        raise ValueError('policy root unresolved')
    names = [child.tag for child in root]
    if set(names) != {'inbound', 'backend', 'outbound', 'on-error'} or len(names) != 4:
        raise ValueError('complete independent policy sections required')
    for section in root:
        if section.attrib or (section.text or '').strip():
            raise ValueError('policy section unresolved')
        for child in section:
            if section.tag == 'inbound' and child.tag == 'rate-limit-by-key':
                if (set(child.attrib) - {'calls', 'renewal-period', 'counter-key', 'id'}
                        or not re.fullmatch(r'[1-9][0-9]*', child.get('calls', ''))
                        or not re.fullmatch(r'[1-9][0-9]*', child.get('renewal-period', ''))
                        or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', child.get('counter-key', ''))):
                    raise ValueError('rate counter unresolved')
            elif not (section.tag == 'backend' and child.tag == 'forward-request' and not child.attrib):
                raise ValueError('policy inheritance or behavior unsupported')
            child.attrib.pop('id', None)
            if len(child) or (child.text or '').strip() or (child.tail or '').strip():
                raise ValueError('policy content unsupported')
    return ET.tostring(root, encoding='unicode')


def owner_policy(options, scopes):
    """Keep the complete shared authority when the Function family is present."""
    from .azure_sw15_policy import normalize, FUNCTION
    try:
        raw = normalize(options, scopes)
    except ValueError:
        return None
    return raw if raw is not None and FUNCTION <= set(raw) else None


def collect(reader, request, scopes, wanted, options):
    if KIND not in wanted:
        return
    reader.native_function_policy = owner_policy(options, scopes)
    def consume():
        with reader.lock:
            if reader.budget.max_items is not None and reader.total >= reader.budget.max_items:
                raise ValueError('resource_limit')
            reader.total += 1
    def paged(parent, segment, version):
        seen = set()
        for page in reader.pages(request, ARM+parent+'/'+segment+'?api-version='+version):
            for row in page:
                rid = identity(row, parent, '/'+re.escape(segment)+r'/[^/?#%\s]+')
                if rid.casefold() in seen:
                    raise ValueError('duplicate native child')
                seen.add(rid.casefold())
                yield row
    def detail(rid, version):
        value = reader.call(request, ARM+rid+'?api-version='+version)
        identity(value, rid, '')
        if not isinstance(value.get('properties'), dict):
            raise ValueError('native detail properties absent')
        return value
    def function_rows(site):
        rid = site['id']
        if list(paged(rid, 'slots', WEB_VERSION)):
            raise ValueError('deployment slots require separate mapping')
        host = site['properties'].get('defaultHostName')
        if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9-]+\.azurewebsites\.net', host):
            raise ValueError('native Function hostname unresolved')
        result = []
        for row in paged(rid, 'functions', WEB_VERSION):
            consume()
            props = row.get('properties')
            if (not isinstance(props, dict) or str(props.get('function_app_id', '')).casefold() != rid.casefold()
                    or type(props.get('isDisabled')) is not bool):
                raise ValueError('Function native parent/state unresolved')
            bindings = props.get('config', {}).get('bindings')
            if not isinstance(bindings, list) or any(not isinstance(b, dict) or not isinstance(b.get('type'), str) for b in bindings):
                raise ValueError('Function trigger inventory unresolved')
            triggers = [b for b in bindings if b['type'].casefold() == 'httptrigger']
            if not triggers or props['isDisabled']:
                continue
            if len(triggers) != 1 or triggers[0].get('direction') != 'in':
                raise ValueError('HTTP trigger ambiguous')
            methods = triggers[0].get('methods')
            if not isinstance(methods, list) or not methods or any(not isinstance(m, str) or m.upper() not in METHODS for m in methods):
                raise ValueError('HTTP method metadata unresolved')
            route = url(props.get('invoke_url_template'))
            if route[0] != host.casefold():
                raise ValueError('Function invoke origin foreign')
            result.append((row['id'], route, {m.upper() for m in methods}))
        if not result:
            raise ValueError('no native HTTP Function mapping')
        return result
    def evidence(site, scope):
        functions = function_rows(site)
        services = complete(reader, 'api_management', scope)
        facts = complete(reader, 'apim_native', scope)
        service_ids = {identity(s, scope, r'/resourceGroups/[^/?#%\s]+/providers/Microsoft.ApiManagement/service/[^/?#%\s]+').casefold() for s in services}
        if len(service_ids) != len(services) or {f['id'].casefold() for f in facts} != service_ids or len(facts) != len(services):
            raise ValueError('APIM service coverage differs')
        operations, mapped, seen_apis = [], set(), set()
        for fact in facts:
            if fact.get('_coverage', {}).get('revisions', {}).get('status') != 'collected':
                raise ValueError('APIM online revision coverage incomplete')
            if list(paged(fact['id'], 'workspaces', APIM_VERSION)):
                raise ValueError('APIM workspace APIs require separate inventory')
            online = fact.get('online_api_ids')
            if not isinstance(online, list) or any(not isinstance(a, str) for a in online):
                raise ValueError('APIM online API identities absent')
            for aid in online:
                identity({'id': aid}, fact['id'], r'/apis/[^/?#%\s]+')
                if aid.casefold() in seen_apis:
                    raise ValueError('duplicate online API identity')
                seen_apis.add(aid.casefold())
                api = detail(aid, APIM_VERSION)
                protocols = api['properties'].get('protocols')
                if not isinstance(protocols, list) or not protocols or any(p not in ('http', 'https') for p in protocols):
                    raise ValueError('non-HTTP API mapping unsupported')
                backend = url(api['properties'].get('serviceUrl'))
                for operation in paged(aid, 'operations', APIM_VERSION):
                    consume()
                    props = operation.get('properties')
                    if not isinstance(props, dict) or props.get('method') not in METHODS:
                        raise ValueError('APIM operation method unresolved')
                    path = props.get('urlTemplate')
                    if not isinstance(path, str) or not re.fullmatch(r'/[A-Za-z0-9/_-]*', path):
                        raise ValueError('APIM dynamic route unresolved')
                    route = (backend[0], backend[1]+path.rstrip('/'))
                    matches = [fid for fid, target, methods in functions if route == target and props['method'] in methods]
                    if backend[0] != functions[0][1][0]:
                        continue
                    if len(matches) != 1:
                        raise ValueError('Function operation mapping incomplete')
                    oid = operation['id']
                    raw = reader.call(request, ARM+oid+'/policies/policy?format=rawxml&api-version='+APIM_VERSION)
                    xml = policy_projection(raw, oid)
                    operations.append({'operation_id': oid, 'function_id': matches[0], 'exposed': True,
                        'expressions_resolved': True, 'effective_policy_xml': xml,
                        '_provenance': {'source_operation': 'ApiOperationPolicy_Get', 'read_only': True,
                            'api_version': APIM_VERSION, 'request_uri': ARM+oid+'/policies/policy'}})
                    mapped.add((matches[0].casefold(), props['method']))
        if mapped != {(fid.casefold(), method) for fid, _, methods in functions for method in methods} or not operations:
            raise ValueError('not every HTTP Function has an exact APIM mapping')
        return {'status': 'collected', 'resource_id': site['id'], 'observed_at': datetime.now(timezone.utc).isoformat(),
                'operations_complete': True, 'function_mapping_complete': True, 'policy_tree_complete': True,
                'inheritance_resolved': True, 'operations': operations,
                '_provenance': {'read_only': True, 'source_operation': 'Functions_List+Apis_Get+ApiOperation_ListByApi+ApiOperationPolicy_Get',
                    'semantics': 'Literal native route and independent operation policy only; rate enforcement not tested'}}
    jobs = []
    for scope in scopes:
        def fetch(scope=scope):
            seen = set()
            for parent in complete(reader, 'app_service', scope):
                rid = identity(parent, scope, r'/resourceGroups/[^/?#%\s]+/providers/Microsoft.Web/sites/[^/?#%\s]+')
                if rid.casefold() in seen or not isinstance(parent.get('kind'), str):
                    raise ValueError('site identity or kind ambiguous')
                seen.add(rid.casefold())
                if 'functionapp' not in {k.strip().casefold() for k in parent['kind'].split(',')}:
                    continue
                native = detail(rid, WEB_VERSION)
                if not isinstance(native.get('kind'), str) or 'functionapp' not in {k.strip().casefold() for k in native['kind'].split(',')}:
                    raise ValueError('native Function kind mismatch')
                site = {'id': rid, 'kind': native['kind'], 'type': 'Microsoft.Web/sites',
                        'properties': {'defaultHostName': native['properties'].get('defaultHostName')},
                        '_provenance': {'source_operation': 'WebApps_Get', 'api_version': WEB_VERSION,
                                        'read_only': True}}
                try:
                    if reader.native_function_policy is None:
                        raise ValueError('approved Function policy missing')
                    site['invocationEvidence'] = evidence(site, scope)
                except Exception:
                    site['invocationEvidence'] = {'status': 'not_collected', 'resource_id': rid,
                        'reason': 'native_function_apim_route_or_policy_unresolved'}
                yield [site]
        jobs.append((KIND, scope, 'Microsoft.Web', fetch))
    reader.run(jobs)
