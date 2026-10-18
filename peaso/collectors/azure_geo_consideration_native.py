"""Explicit geographic risk decisions with native, universally scoped blocks.

No physical-location probes, sign-in simulations or principal partitions.
Complex conditional policies retain the existing evidence path.
"""
from datetime import datetime
import hashlib
import json
import re

from .azure_ca_consideration_native import digest as policy_digest

CID = 'azure.cis.exclusionary_geographic_access_policy_considered'
KEY = CID.replace('.', '|')
GUID = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
POLICIES = '/v1.0/identity/conditionalAccess/policies'
LOCATIONS = '/v1.0/identity/conditionalAccess/namedLocations'
CLIENTS = {'all', 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other'}


def _text(value, maximum=2048):
    if (not isinstance(value, str) or not value or len(value) > maximum or value != value.strip()
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('invalid geographic review text')
    return value


def _list(value, maximum=128):
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ValueError('geographic review scope required')
    for item in value: _text(item, 128)
    if len({v.casefold() for v in value}) != len(value): raise ValueError('duplicate geographic scope')
    return value


def _bindings(value, identity):
    if not isinstance(value, list) or not 1 <= len(value) <= 64: raise ValueError('review bindings required')
    seen = set()
    for entry in value:
        if (not isinstance(entry, dict) or set(entry) != {identity, 'configurationSha256'}
                or not isinstance(entry[identity], str) or re.fullmatch(GUID, entry[identity]) is None
                or entry[identity].casefold() in seen or not isinstance(entry['configurationSha256'], str)
                or re.fullmatch('[0-9a-f]{64}', entry['configurationSha256']) is None):
            raise ValueError('invalid geographic review binding')
        seen.add(entry[identity].casefold())


def validate_config(config):
    fields = {'userScope', 'requiredApplications', 'requiredClientAppTypes', 'consideration'}
    if not isinstance(config, dict) or set(config) != fields or config['userScope'] != 'all':
        raise ValueError('only explicitly approved all-user geographic scope supported')
    apps = _list(config['requiredApplications'])
    if apps != ['All'] and any(re.fullmatch(GUID, a) is None for a in apps): raise ValueError('invalid geographic app scope')
    clients = _list(config['requiredClientAppTypes'])
    if set(clients) - CLIENTS or ('all' in clients and clients != ['all']): raise ValueError('invalid geographic client scope')
    review = config['consideration']
    if not isinstance(review, dict): raise ValueError('explicit geographic consideration required')
    decision = review.get('decision')
    required = {'decision', 'rationale'}
    if decision == 'block':
        required |= {'prohibitedCountries', 'reviewedPolicies', 'reviewedLocations'}
    elif decision != 'noBlockRequired':
        raise ValueError('unsupported geographic decision')
    if set(review) != required: raise ValueError('unsupported geographic consideration field')
    _text(review['rationale'])
    if decision == 'block':
        countries = _list(review['prohibitedCountries'], maximum=256)
        if any(re.fullmatch('[A-Z]{2}', c) is None for c in countries): raise ValueError('invalid country code')
        _bindings(review['reviewedPolicies'], 'policyId')
        _bindings(review['reviewedLocations'], 'locationId')
    return config


def location_digest(location):
    if not isinstance(location, dict): raise ValueError('native location absent')
    fields = {key: location.get(key) for key in ('id', '@odata.type', 'countriesAndRegions',
        'countryLookupMethod', 'includeUnknownCountriesAndRegions')}
    value = json.dumps(fields, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    if len(value) > 262144: raise ValueError('location exceeds bounded review')
    return hashlib.sha256(value).hexdigest()


def _rows(values, endpoint, tenant):
    result = {}
    for row in values:
        if not isinstance(row, dict): raise ValueError('native Graph resource unavailable')
        rid, proof = row.get('id'), row.get('_provenance')
        if (not isinstance(rid, str) or re.fullmatch(GUID, rid) is None or rid.casefold() in result
                or not isinstance(proof, dict) or proof.get('endpoint') != endpoint
                or proof.get('read_only') is not True or proof.get('tenant_verified') is not True
                or str(proof.get('tenant_id', '')).casefold() != tenant):
            raise ValueError('native Graph authority unavailable')
        result[rid.casefold()] = row
    return result


def _other_empty(value, allowed):
    return isinstance(value, dict) and all(v in (None, [], {}) for k, v in value.items() if k not in allowed)


def _countries(location):
    if location.get('@odata.type') != '#microsoft.graph.countryNamedLocation': return None
    allowed = {'id', '@odata.type', 'countriesAndRegions', 'countryLookupMethod',
        'includeUnknownCountriesAndRegions', 'createdDateTime', 'modifiedDateTime', 'displayName', '_provenance'}
    if set(location) - allowed: return None
    # Graph explicitly documents these two omitted-field defaults.
    # https://learn.microsoft.com/en-us/graph/api/resources/countrynamedlocation
    if location.get('countryLookupMethod', 'clientIpAddress') != 'clientIpAddress': return None
    if type(location.get('includeUnknownCountriesAndRegions', False)) is not bool: return None
    countries = _list(location.get('countriesAndRegions'), maximum=256)
    if any(re.fullmatch('[A-Z]{2}', c) is None for c in countries): return None
    return set(countries)


def _block_locations(rule):
    allowed = {'id', 'state', 'conditions', 'grantControls', 'sessionControls', 'displayName',
        'createdDateTime', 'modifiedDateTime', 'templateId', '@odata.type', '@odata.context', '_provenance'}
    if set(rule) - allowed or rule.get('state') != 'enabled': return None
    conditions = rule.get('conditions')
    if not _other_empty(conditions, {'users', 'applications', 'clientAppTypes', 'locations'}): return None
    users = conditions.get('users')
    if not isinstance(users, dict) or users.get('includeUsers') != ['All'] or not _other_empty(users, {'includeUsers'}): return None
    apps = conditions.get('applications')
    if not isinstance(apps, dict) or apps.get('includeApplications') != ['All'] or not _other_empty(apps, {'includeApplications'}): return None
    if conditions.get('clientAppTypes') != ['all']: return None
    locations = conditions.get('locations')
    if not _other_empty(locations, {'includeLocations'}): return None
    included = _list(locations.get('includeLocations'))
    if any(re.fullmatch(GUID, loc) is None for loc in included): return None
    grant = rule.get('grantControls')
    if (not isinstance(grant, dict) or grant.get('builtInControls') != ['block']
            or grant.get('operator') not in {'AND', 'OR'} or not _other_empty(grant, {'builtInControls', 'operator'})
            or rule.get('sessionControls') not in (None, {})):
        return None
    return {loc.casefold() for loc in included}


def _date(value):
    date = datetime.fromisoformat(_text(value, 64).replace('Z', '+00:00'))
    if date.utcoffset() is None: raise ValueError('review timezone required')
    return date


def native_result(item, context, rules, locations, config):
    """Only a proven PASS; the caller keeps its legacy path for other cases."""
    try:
        validate_config(config)
        scope = context.get('scope')
        if (context.get('provider') != 'azure' or not isinstance(scope, str)
                or re.fullmatch('/tenants/' + GUID, scope) is None): return None
        tenant = scope.removeprefix('/tenants/').casefold()
        review = context.get('metadata', {}).get('compliance_policy', {}).get('sw13')
        if (not isinstance(review, dict) or review.get('status') != 'collected'
                or str(review.get('scope', '')).casefold() != scope.casefold()
                or review.get('checks', {}).get(KEY) != config): return None
        _text(review.get('authorized_by')); _text(review.get('document_id'))
        if not _date(review.get('observed_at')) <= _date(context.get('created_at')) < _date(review.get('expires_at')):
            return None
        policies = _rows(rules, POLICIES, tenant)
        if not isinstance(item, dict) or policies.get(str(item.get('id', '')).casefold()) != item: return None
        decision = config['consideration']
        if decision['decision'] == 'noBlockRequired':
            return 'PASS', {'review_document_id': review['document_id'], 'decision': 'noBlockRequired',
                'semantics': 'Explicit current authorized geographic risk decision; no enforced block claimed'}
        native_locations = _rows(locations, LOCATIONS, tenant)
        reviewed_locations = {}
        for approval in decision['reviewedLocations']:
            location = native_locations.get(approval['locationId'].casefold())
            if location is None or location_digest(location) != approval['configurationSha256']: return None
            countries = _countries(location)
            if countries is None: return None
            reviewed_locations[approval['locationId'].casefold()] = countries
        covered, qualifying = set(), []
        for approval in decision['reviewedPolicies']:
            rule = policies.get(approval['policyId'].casefold())
            if rule is None or policy_digest(rule) != approval['configurationSha256']: return None
            included = _block_locations(rule)
            if included is None: continue
            if not included <= set(reviewed_locations): return None
            for identity in included: covered.update(reviewed_locations[identity])
            qualifying.append(rule['id'])
        if not qualifying or not set(decision['prohibitedCountries']) <= covered: return None
        return 'PASS', {'review_document_id': review['document_id'], 'decision': 'block',
            'reviewed_block_policy_ids': sorted(qualifying), 'prohibited_countries': sorted(decision['prohibitedCountries']),
            'semantics': 'Explicit risk review and configured native country-location block; physical geolocation and live sign-ins unassessed'}
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def empty_result(context, collection, config):
    """A tenant risk decision can exist without any CA policy resource.

    No declared consideration keeps the existing EMPTY inventory behavior.
    Explicit but unproved decisions are UNKNOWN, never a made-up policy FAIL.
    The caller verifies a unique, genuinely empty primary inventory first.
    """
    if not isinstance(config, dict) or 'consideration' not in config:
        return None
    unknown = ('UNKNOWN', {'reason': 'empty native policy inventory does not prove a current authorized geographic decision'})
    try:
        validate_config(config)
        scope = context.get('scope')
        if context.get('provider') != 'azure' or not isinstance(scope, str) or re.fullmatch('/tenants/' + GUID, scope) is None:
            return unknown
        tenant = scope.removeprefix('/tenants/').casefold()
        metadata = context.get('metadata')
        if (not isinstance(metadata, dict) or metadata.get('tenant_verified') is not True
                or str(metadata.get('tenant_id', '')).casefold() != tenant
                or metadata.get('context_binding') != 'scan_local'):
            return unknown
        if (not isinstance(collection, dict) or collection.get('type') != 'conditional_access_policy'
                or collection.get('scope') != scope or collection.get('service') != 'Microsoft.Graph'
                or collection.get('status') != 'empty' or collection.get('items') != []
                or collection.get('error') or any(collection.get(k) for k in ('nextLink', '@odata.nextLink', 'continue'))):
            return unknown
        proof = collection.get('_provenance')
        if (not isinstance(proof, dict) or proof.get('tenant_verified') is not True
                or str(proof.get('tenant_id', '')).casefold() != tenant
                or ('read_only' in proof and proof['read_only'] is not True)
                or ('endpoint' in proof and proof['endpoint'] != POLICIES)
                or any(not isinstance(metadata.get(k), str) or not metadata[k] or proof.get(k) != metadata[k]
                    for k in ('credential_context_id', 'customer_context_id'))):
            return unknown
        review = metadata.get('compliance_policy', {}).get('sw13')
        if (not isinstance(review, dict) or review.get('status') != 'collected'
                or str(review.get('scope', '')).casefold() != scope.casefold()
                or review.get('checks', {}).get(KEY) != config):
            return unknown
        _text(review.get('authorized_by')); _text(review.get('document_id'))
        if not _date(review.get('observed_at')) <= _date(context.get('created_at')) < _date(review.get('expires_at')):
            return unknown
        if config['consideration']['decision'] != 'noBlockRequired':
            return unknown
        return 'PASS', {'review_document_id': review['document_id'], 'decision': 'noBlockRequired',
            'semantics': 'Current explicit tenant geographic risk decision; native policy inventory is empty and no enforced block is claimed'}
    except (ValueError, TypeError, KeyError, AttributeError):
        return unknown
