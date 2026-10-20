"""Read exact ARM registry network declarations for the separate IP criterion.

Uses the common reader's call/page/resource/deadline limits. No registry data
plane, credentials, network probes or configuration writes are requested.
"""
from copy import deepcopy
import re

ARM = 'https://management.azure.com'
VERSION = '2023-07-01'
KIND = 'acr_public_network_evidence'
NATIVE_TYPES = (KIND,)
MARKER = '_acr_public_network_native'
MAX_RULES = 200
GUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'


def registry_id(value, scope):
    if (not isinstance(scope, str) or not re.fullmatch('/subscriptions/'+GUID, scope, re.I)
            or not isinstance(value, str) or not re.fullmatch(re.escape(scope)+r'/resourceGroups/[^/?#%\s\\]+/providers/Microsoft\.ContainerRegistry/registries/[a-z0-9]{5,50}', value, re.I)
            or any(ord(c) < 33 or ord(c) == 127 for c in value)
            or any(p in ('.', '..') for p in value.split('/'))):
        raise ValueError('registry identity outside selected subscription')
    return value


def required_types(wanted):
    return {'container_registry'} if KIND in wanted else set()


def project(raw, selected, scope):
    selected = registry_id(selected, scope)
    if (not isinstance(raw, dict) or registry_id(raw.get('id'), scope).casefold() != selected.casefold()
            or not isinstance(raw.get('type'), str) or raw['type'].casefold() != 'microsoft.containerregistry/registries'
            or not isinstance(raw.get('name'), str) or raw['name'].casefold() != selected.rsplit('/', 1)[-1].casefold()
            or not isinstance(raw.get('properties'), dict)):
        raise ValueError('registry GET identity or representation unresolved')
    props = raw['properties']
    projected = {key: deepcopy(props[key]) for key in ('publicNetworkAccess', 'networkRuleBypassOptions', 'provisioningState') if key in props}
    if 'networkRuleSet' in props:
        rules = props['networkRuleSet']
        if not isinstance(rules, dict):
            raise ValueError('network rule set malformed')
        projected['networkRuleSet'] = {key: deepcopy(rules[key]) for key in ('defaultAction',) if key in rules}
        if 'ipRules' in rules:
            values = rules['ipRules']
            if (not isinstance(values, list) or len(values) > MAX_RULES
                    or any(not isinstance(v, dict) for v in values)):
                raise ValueError('IP rule inventory malformed or over bound')
            projected['networkRuleSet']['ipRules'] = [
                {key: deepcopy(v[key]) for key in ('action', 'value') if key in v} for v in values]
    return {'id': raw['id'], 'parent_id': selected, 'type': raw['type'], 'properties': projected,
            '_provenance': {'scope': scope, 'source_operation': 'Registries_Get', 'read_only': True, 'api_version': VERSION},
            MARKER: {'scope': scope, 'resource_id': selected, 'method': 'GET', 'api_version': VERSION,
                     'request_uri': ARM+selected+'?api-version='+VERSION, 'complete': True}}


def collect(reader, request, scopes, wanted):
    if KIND not in wanted:
        return
    for scope in scopes:
        def fetch(scope=scope):
            parents = [c for c in reader.collections if c['type'] == 'container_registry' and c['scope'].casefold() == scope.casefold()]
            if len(parents) != 1 or parents[0]['status'] not in ('collected', 'empty'):
                raise ValueError('complete selected registry inventory unavailable')
            parent = parents[0]
            if not isinstance(parent['items'], list) or (parent['status'] == 'empty') != (not parent['items']):
                raise ValueError('selected registry inventory contradictory')
            selected = []
            for row in parent['items']:
                rid = registry_id(row.get('id'), scope)
                if (str(row.get('type', '')).casefold() != 'microsoft.containerregistry/registries'
                        or rid.casefold() in {v.casefold() for v in selected}):
                    raise ValueError('foreign or duplicate registry parent')
                selected.append(rid)
            for rid in selected:
                raw = reader.call(request, ARM+rid+'?api-version='+VERSION)
                yield [project(raw, rid, scope)]
        reader.collections.append(reader._read((KIND, scope, 'Microsoft.ContainerRegistry', fetch)))
