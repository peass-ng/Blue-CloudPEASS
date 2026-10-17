"""Current secret-version metadata via ARM, never data-plane GetSecret/value.

ARM Secrets_Get supplies an explicit version pointer; ListVersions supplies the
exact version attributes. Two uncached ARM observations must agree around the
complete paged list. No newest-created heuristic or access outcome is inferred.
"""
import copy
from datetime import datetime, timezone
import re
from urllib.parse import urlsplit

ARM = 'https://management.azure.com'
VAULT = 'https://vault.azure.net'
ARM_VERSION = '2023-07-01'
VAULT_VERSION = '2025-07-01'
NATIVE_TYPES = {'key_vault_secret', 'vault_secret'}
ATTRS = {'enabled', 'created', 'updated', 'exp', 'nbf'}
VERSION_ATTRS = ATTRS | {'recoveryLevel', 'recoverableDays'}


def required_types(wanted):
    return {'vault', 'secret_metadata'} if NATIVE_TYPES & set(wanted) else set()


def complete(reader, kind, scope):
    matches = [c for c in reader.collections if c['type'] == kind and c['scope'].casefold() == scope.casefold()]
    if len(matches) != 1 or matches[0]['status'] not in ('collected', 'empty'):
        raise ValueError('native secret parent inventory incomplete')
    rows = matches[0]['items']
    if not isinstance(rows, list) or (matches[0]['status'] == 'empty') != (not rows):
        raise ValueError('native secret inventory contradictory')
    return rows


def arm_id(value, scope, suffix):
    if (not isinstance(value, str) or not re.fullmatch(re.escape(scope)+suffix, value, re.I)
            or any(p in ('.', '..') for p in value.split('/')) or '\\' in value):
        raise ValueError('native secret ARM identity foreign')
    return value


def attrs(value, fields):
    if not isinstance(value, dict) or type(value.get('enabled')) is not bool or type(value.get('created')) is not int or value['created'] < 0:
        raise ValueError('secret lifecycle attributes missing')
    for key in ('created', 'updated', 'exp', 'nbf'):
        if key in value and (type(value[key]) is not int or value[key] < 0):
            raise ValueError('secret epoch malformed')
    return {k: copy.deepcopy(v) for k, v in value.items() if k in fields}


def collect(reader, transport, scopes, wanted):
    selected = sorted(NATIVE_TYPES & set(wanted))
    if not selected:
        return
    for scope in scopes:
        def fetch(scope=scope):
            seen_vaults, seen_secrets = set(), set()
            for vault in complete(reader, 'vault', scope):
                vid = arm_id(vault.get('id'), scope, r'/resourceGroups/[^/?#%\s]+/providers/Microsoft.KeyVault/vaults/[A-Za-z0-9-]{3,24}')
                if vid.casefold() in seen_vaults:
                    raise ValueError('duplicate native vault')
                seen_vaults.add(vid.casefold())
                origin = vault.get('properties', {}).get('vaultUri')
                if (not isinstance(origin, str) or not re.fullmatch(r'https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net/?', origin)
                        or urlsplit(origin).hostname.casefold() != vid.rsplit('/', 1)[-1].casefold()+'.vault.azure.net'):
                    raise ValueError('native vault endpoint binding invalid')
                origin = origin.rstrip('/')
                if hasattr(transport, 'allow_vault'):
                    transport.allow_vault(origin)
                for base in complete(reader, 'secret_metadata', vid):
                    sid = arm_id(base.get('id'), vid, r'/secrets/[A-Za-z0-9-]{1,127}')
                    if sid.casefold() in seen_secrets or str(base.get('parent_id', '')).casefold() != vid.casefold():
                        raise ValueError('duplicate or foreign native secret')
                    seen_secrets.add(sid.casefold())
                    name = sid.rsplit('/', 1)[-1]
                    uri = origin+'/secrets/'+name
                    if not isinstance(base.get('data_plane_id'), str) or base['data_plane_id'].casefold() != uri.casefold():
                        raise ValueError('native base secret URI binding invalid')
                    output = {key: copy.deepcopy(base[key]) for key in ('id', 'parent_id', 'type', 'name', 'data_plane_id', 'properties', 'vaultProperties') if key in base}
                    try:
                        arm_url = ARM+sid+'?api-version='+ARM_VERSION
                        version_url = uri+'/versions?api-version='+VAULT_VERSION
                        def read(url, *, body=None, audience=ARM):
                            if body is not None:
                                raise ValueError('secret metadata requires GET')
                            parsed = urlsplit(url)
                            if audience == ARM:
                                if url != arm_url:
                                    raise ValueError('unexpected ARM metadata endpoint')
                            elif (audience != VAULT or parsed.scheme != 'https' or parsed.netloc.casefold() != urlsplit(origin).netloc.casefold()
                                  or parsed.path != '/secrets/'+name+'/versions' or parsed.fragment or parsed.username or parsed.password):
                                raise ValueError('unexpected vault metadata endpoint')
                            raw = transport.request(url, body=None, audience=audience)
                            if not isinstance(raw, dict):
                                raise ValueError('secret metadata response malformed')
                            if audience == ARM:
                                rid = arm_id(raw.get('id'), vid, r'/secrets/'+re.escape(name))
                                if str(raw.get('type', '')).casefold() != 'microsoft.keyvault/vaults/secrets' or str(raw.get('name', '')).casefold() != name.casefold():
                                    raise ValueError('ARM secret resource type/name differs')
                                props = raw.get('properties')
                                if not isinstance(props, dict) or props.get('value') is not None:
                                    raise ValueError('ARM metadata response unexpected content')
                                return {'id': rid, 'parent_id': vid, 'name': raw['name'], 'type': raw['type'], 'properties': {
                                    'secretUri': props.get('secretUri'), 'secretUriWithVersion': props.get('secretUriWithVersion'),
                                    'attributes': attrs(props.get('attributes'), ATTRS)}}
                            rows = raw.get('value')
                            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                                raise ValueError('secret version list malformed')
                            return {'value': [{'id': row.get('id'), 'attributes': attrs(row.get('attributes'), VERSION_ATTRS)} for row in rows],
                                    **({'nextLink': raw['nextLink']} if raw.get('nextLink') else {})}
                        # Intentionally bypass the shared URL cache: consistency
                        # needs two independently accepted ARM reads.
                        before = reader.call(read, arm_url)
                        before_stamp = datetime.now(timezone.utc).isoformat()
                        if before['properties']['secretUri'].casefold() != uri.casefold():
                            raise ValueError('ARM current base URI differs')
                        current_id = before['properties']['secretUriWithVersion']
                        if not isinstance(current_id, str) or not re.fullmatch(re.escape(uri)+r'/[A-Za-z0-9-]+', current_id, re.I):
                            raise ValueError('ARM current version URI invalid')
                        versions, seen = [], set()
                        for page in reader.pages(read, version_url, audience=VAULT):
                            for version in page:
                                key = version['id']
                                if not isinstance(key, str) or not re.fullmatch(re.escape(uri)+r'/[A-Za-z0-9-]+', key, re.I) or key.casefold() in seen:
                                    raise ValueError('foreign or duplicate secret version')
                                seen.add(key.casefold())
                                with reader.lock:
                                    if reader.budget.max_items is not None and reader.total >= reader.budget.max_items:
                                        raise ValueError('resource_limit')
                                    reader.total += 1
                                versions.append(version)
                        after = reader.call(read, arm_url)
                        if before != after:
                            raise ValueError('ARM current metadata changed during observation')
                        matches = [version for version in versions if version['id'] == current_id]
                        if len(matches) != 1 or any(matches[0]['attributes'].get(k) != v for k, v in after['properties']['attributes'].items()):
                            raise ValueError('ARM attributes differ from exact listed version')
                        stamp = datetime.now(timezone.utc).isoformat()
                        proof = {'endpoint': 'arm/secrets/get', 'source_operation': 'Secrets_Get',
                                 'request_uri': ARM+sid, 'api_version': ARM_VERSION, 'read_only': True,
                                 'values_omitted': True, 'observed_at': stamp}
                        before['_provenance'] = {**proof, 'observed_at': before_stamp}
                        output['armCurrentMetadataBefore'] = before
                        after['_provenance'] = copy.deepcopy(proof)
                        output['armCurrentMetadata'] = after
                        output['currentVersion'] = {'id': current_id, 'attributes': copy.deepcopy(matches[0]['attributes']),
                            '_provenance': {**proof, 'attributes_source_operation': 'Secrets_ListVersions',
                                'attributes_request_uri': uri+'/versions', 'attributes_api_version': VAULT_VERSION}}
                        output['versions'] = versions
                        output.setdefault('properties', {})['attributes'] = copy.deepcopy(matches[0]['attributes'])
                        output['_coverage'] = {key: {'status': 'collected'} for key in ('armCurrentMetadataBefore', 'armCurrentMetadata', 'currentVersion', 'versions')}
                    except Exception:
                        output['_coverage'] = {key: {'status': 'not_collected'} for key in ('armCurrentMetadataBefore', 'armCurrentMetadata', 'currentVersion', 'versions')}
                    yield [output]
        result = reader._read(('native_secret_current_metadata', scope, 'Microsoft.KeyVault', fetch))
        # Both signed resource kinds identify the same native ARM secret, with
        # their own unchanged evaluators. This fanout is not compliance evidence.
        for kind in selected:
            value = copy.deepcopy(result)
            value['type'] = kind
            capacity = len(value['items']) if reader.budget.max_items is None else max(0, reader.budget.max_items-reader.total)
            if len(value['items']) > capacity:
                value['items'] = value['items'][:capacity]
                value.update(status='partial', error={'code': 'resource_limit'})
            reader.total += len(value['items'])
            reader.collections.append(value)
