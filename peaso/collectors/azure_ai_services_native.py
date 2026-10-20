"""Read-only ARM configuration for the four reviewed AI Services source gaps."""
from copy import deepcopy
import re
from urllib.parse import urlsplit, parse_qs

ARM = 'https://management.azure.com'
VERSION = '2024-10-01'
MONITOR_VERSION = '2021-05-01-preview'
TYPE = 'Microsoft.CognitiveServices/accounts'
KINDS = {name: 'cognitive_account_' + name for name in ('audit_logging', 'managed_identity', 'outbound_restriction', 'prompt_shield')}
NATIVE_TYPES = tuple(KINDS.values())
CHILDREN = {
    'audit_logging': (('diagnosticSettings', 'providers/Microsoft.Insights/diagnosticSettings', MONITOR_VERSION),
                      ('diagnosticCategories', 'providers/Microsoft.Insights/diagnosticSettingsCategories', MONITOR_VERSION)),
    'prompt_shield': (('deployments', 'deployments', VERSION), ('raiPolicies', 'raiPolicies', VERSION)),
}


def _pages(reader, request, url, version):
    def bound_request(target, *, body=None, audience=ARM):
        parts = urlsplit(target)
        query = parse_qs(parts.query, keep_blank_values=True)
        if (body is not None or audience != ARM or parts.scheme != 'https' or parts.netloc != 'management.azure.com'
                or query.get('api-version') != [version]
                or any(key.casefold() not in ('api-version', '$skiptoken', 'skiptoken') for key in query)):
            raise ValueError('unbound or narrowed AI Services continuation')
        return request(target, body=None, audience=ARM)
    yield from reader.pages(bound_request, url)


def account_id(value, scope):
    if (not isinstance(scope, str) or not re.fullmatch(r'/subscriptions/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', scope, re.I)
            or not isinstance(value, str) or any(c in value for c in '?%#\\')
            or not re.fullmatch(re.escape(scope) + r'/resourceGroups/[A-Za-z0-9_.()-]+/providers/Microsoft\.CognitiveServices/accounts/[A-Za-z0-9][A-Za-z0-9_.-]{1,63}', value, re.I)
            or any(s in ('.', '..') for s in value.split('/'))):
        raise ValueError('unbound AI Services account')
    return value.casefold()


def child_id(row, parent, path):
    expected_type = TYPE + '/' + path if not path.startswith('providers/') else path.removeprefix('providers/')
    if (not isinstance(row, dict) or not isinstance(row.get('id'), str)
            or not re.fullmatch(re.escape(parent + '/' + path) + r'/[A-Za-z0-9][A-Za-z0-9_.()-]*', row['id'], re.I)
            or not isinstance(row.get('name'), str)
            or row['name'].casefold() != row['id'].rsplit('/', 1)[-1].casefold()
            or str(row.get('type', '')).casefold() != expected_type.casefold()
            or not isinstance(row.get('properties'), dict)):
        raise ValueError('unbound AI Services child')
    return row['id'].casefold()


def _project(row, path):
    fields = {
        'deployments': ('provisioningState', 'capabilities', 'raiPolicyName'),
        'raiPolicies': ('contentFilters',),
        'providers/Microsoft.Insights/diagnosticSettings': ('logs', 'workspaceId', 'storageAccountId', 'eventHubAuthorizationRuleId', 'eventHubName', 'marketplacePartnerId'),
        'providers/Microsoft.Insights/diagnosticSettingsCategories': ('categoryType', 'categoryGroups'),
    }[path]
    props = {k: deepcopy(v) for k, v in row['properties'].items() if k in fields}
    for key, allowed in (('logs', ('category', 'categoryGroup', 'enabled')),
                         ('contentFilters', ('name', 'source', 'enabled', 'blocking'))):
        if isinstance(props.get(key), list):
            props[key] = [{k: deepcopy(v) for k, v in entry.items() if k in allowed} if isinstance(entry, dict) else entry
                          for entry in props[key]]
    return {k: deepcopy(row[k]) for k in ('id', 'name', 'type')} | {'properties': props}


def collect(reader, request, scopes, wanted):
    selected = {name: kind for name, kind in KINDS.items() if kind in wanted}
    if not selected:
        return
    for scope in scopes:
        def accounts():
            seen = set()
            for page in _pages(reader, request, ARM + scope + '/providers/' + TYPE + '?api-version=' + VERSION, VERSION):
                rows = []
                for row in page:
                    rid = account_id(row.get('id') if isinstance(row, dict) else None, scope)
                    if rid in seen:
                        raise ValueError('duplicate AI Services account')
                    seen.add(rid)
                    value = reader.call(request, ARM + row['id'] + '?api-version=' + VERSION)
                    if (not isinstance(value, dict) or account_id(value.get('id'), scope) != rid
                            or value.get('name', '').casefold() != rid.rsplit('/', 1)[-1]
                            or str(value.get('type', '')).casefold() != TYPE.casefold()
                            or not isinstance(value.get('properties'), dict)):
                        raise ValueError('AI Services account GET identity mismatch')
                    # Native omission remains omission. No SDK defaults or policy guesses.
                    safe = {k: deepcopy(value[k]) for k in ('id', 'name', 'type', 'kind', 'identity') if k in value}
                    if isinstance(safe.get('identity'), dict):
                        safe['identity'] = {k: v for k, v in safe['identity'].items() if k in ('type', 'tenantId', 'principalId', 'userAssignedIdentities')}
                    safe['properties'] = {k: deepcopy(v) for k, v in value['properties'].items()
                        if k in ('provisioningState', 'restrictOutboundNetworkAccess', 'allowedFqdnList')}
                    safe['_ai_services_native'] = {'scope': scope, 'account_id': rid, 'method': 'GET', 'api_version': VERSION, 'complete': True}
                    rows.append(safe)
                yield rows
        inventory = reader._read(('ai_services_account_inventory', scope, TYPE, accounts))
        for name, kind in selected.items():
            collection = {k: deepcopy(v) for k, v in inventory.items() if k != 'type'} | {'type': kind}
            for item in collection['items']:
                for field, path, version in CHILDREN.get(name, ()):
                    rid = item['id']
                    def fetch(rid=rid, path=path, version=version):
                        seen = set()
                        for page in _pages(reader, request, ARM + rid + '/' + path + '?api-version=' + version, version):
                            projected = []
                            for row in page:
                                ident = child_id(row, rid, path)
                                if ident in seen:
                                    raise ValueError('duplicate AI Services child')
                                seen.add(ident)
                                projected.append(_project(row, path))
                            yield projected
                    child = reader._read(('ai_services_' + field, rid, TYPE, fetch))
                    item.setdefault('_coverage', {})[field] = {k: deepcopy(child[k]) for k in ('status', 'error') if k in child}
                    if child['status'] in ('collected', 'empty'):
                        item[field] = child['items']
            reader.collections.append(collection)
            reader.progress(scope=scope, settled=collection)
