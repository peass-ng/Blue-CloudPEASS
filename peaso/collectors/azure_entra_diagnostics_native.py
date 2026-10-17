"""Native tenant diagnostic settings and independently read destination identity."""
from __future__ import annotations

import re

ARM = 'https://management.azure.com'
KIND = 'entra_diagnostic_setting'
_GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', re.I)
_SETTING = re.compile(r'/providers/microsoft\.aadiam/diagnosticsettings/[^/?#%\s]+', re.I)
_ARM = re.compile(r'/subscriptions/[^/?#%\s]+/resourceGroups/[^/?#%\s]+/providers/[^/?#%\s]+(?:/[^/?#%\s]+){2,}', re.I)
_VERSIONS = {
    'workspaceId': ('microsoft.operationalinsights/workspaces', '2023-09-01'),
    'storageAccountId': ('microsoft.storage/storageaccounts', '2023-05-01'),
    'eventHubAuthorizationRuleId': ('microsoft.eventhub/namespaces/authorizationrules', '2024-01-01'),
    'serviceBusRuleId': ('microsoft.servicebus/namespaces/authorizationrules', '2024-01-01'),
}


def setting_id(value):
    # The actual tenant LIST uses a provider-relative identity; normalize only
    # this fixed native provider path, never arbitrary relative URLs.
    if isinstance(value, str) and value.lower().startswith('providers/microsoft.aadiam/'):
        value = '/' + value
    if not isinstance(value, str) or not _SETTING.fullmatch(value) or value.rsplit('/', 1)[-1] in ('.', '..'):
        raise ValueError('invalid tenant diagnostic identity')
    return value


def _destination(value, field):
    if not isinstance(value, str) or not _ARM.fullmatch(value) or any(part in ('.', '..') for part in value.split('/')):
        raise ValueError('invalid diagnostic destination identity')
    tail = re.split('/providers/', value, maxsplit=1, flags=re.I)[1].split('/')
    if len(tail) % 2 != 1 or '/'.join([tail[0], *tail[1::2]]).casefold() != _VERSIONS[field][0]:
        raise ValueError('diagnostic destination type differs')
    return value


def collect(reader, request, scopes, wanted, transport):
    if KIND not in wanted:
        return
    from .azure import AzureReadError
    bindings = {}
    for scope in scopes:
        try:
            subscription = reader.call(request, ARM + scope + '?api-version=2022-12-01')
            tenant = getattr(transport, 'verified_tenant', None)
            if (not isinstance(tenant, str) or not _GUID.fullmatch(tenant) or not isinstance(subscription, dict)
                    or str(subscription.get('id', '')).casefold() != scope.casefold()
                    or str(subscription.get('tenantId', '')).casefold() != tenant.casefold()):
                raise AzureReadError('tenant_subscription_authority_unverified')
            bindings[scope] = tenant
        except Exception as exc:
            tenant = getattr(transport, 'tenant', None)
            reader.unavailable(KIND, '/tenants/' + (tenant if isinstance(tenant, str) else 'unverified'), 'Microsoft.AADIAM', exc)
            return
    tenant = next(iter(bindings.values()), None)
    if tenant is None:
        return
    with reader.lock:
        if not hasattr(reader, 'native_subscription_tenants'):
            reader.native_subscription_tenants = {}
        reader.native_subscription_tenants.update(bindings)
    proof = {'tenant_id': tenant, 'tenant_verified': True, 'read_only': True,
             'source_operation': 'aadiam.diagnosticSettings.list', 'representation': 'full'}

    def fetch():
        seen = set()
        url = ARM + '/providers/Microsoft.aadiam/diagnosticSettings?api-version=2017-04-01'
        for page in reader.pages(request, url):
            for item in page:
                if not isinstance(item, dict):
                    raise ValueError('invalid tenant diagnostic identity')
                rid = setting_id(item.get('id'))
                if rid.casefold() in seen:
                    raise ValueError('duplicate tenant diagnostic setting')
                seen.add(rid.casefold())
                properties = item.get('properties')
                if not isinstance(properties, dict) or not isinstance(properties.get('logs'), list):
                    raise ValueError('incomplete tenant diagnostic logs')
                logs = []
                for log in properties['logs']:
                    if (not isinstance(log, dict) or not isinstance(log.get('enabled'), bool)
                            or not isinstance(log.get('category'), str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,127}', log['category'])):
                        raise ValueError('invalid tenant diagnostic category')
                    logs.append({'category': log['category'], 'enabled': log['enabled']})
                safe, evidence = {'logs': logs}, {}
                for field, (_, version) in _VERSIONS.items():
                    destination = properties.get(field)
                    if destination is None or destination == '':
                        continue
                    destination = _destination(destination, field)
                    detail = reader.call(request, ARM + destination + '?api-version=' + version)
                    if not isinstance(detail, dict) or str(detail.get('id', '')).casefold() != destination.casefold():
                        raise ValueError('diagnostic destination GET identity differs')
                    safe[field] = destination
                    evidence[destination.casefold()] = {'id': destination, 'exists': True,
                        '_provenance': {'source_operation': 'get', 'read_only': True}}
                yield [{'id': rid, 'properties': safe, 'destinationEvidence': list(evidence.values()),
                    '_coverage': {'destinationEvidence': {'status': 'collected' if evidence else 'empty'}},
                    '_provenance': dict(proof)}]
    before = len(reader.collections)
    reader.run([(KIND, '/tenants/' + tenant.casefold(), 'Microsoft.AADIAM', fetch)])
    for collection in reader.collections[before:]:
        collection['_provenance'] = dict(proof)
