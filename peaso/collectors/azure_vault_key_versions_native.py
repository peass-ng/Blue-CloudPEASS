"""Key Vault public-key/version metadata. No key use or import provenance inferred."""
import copy
import re
from urllib.parse import urlsplit

VAULT = 'https://vault.azure.net'
VERSION = '2025-07-01'
NATIVE_TYPES = {'vault_key'}
ATTRS = {'enabled', 'created', 'updated', 'exp', 'nbf', 'recoveryLevel', 'recoverableDays'}


def required_types(wanted):
    return {'vault'} if NATIVE_TYPES.intersection(wanted) else set()


def _attributes(value):
    if not isinstance(value, dict) or type(value.get('enabled')) is not bool:
        raise ValueError('key version enabled state unavailable')
    for field in ('created', 'updated', 'exp', 'nbf', 'recoverableDays'):
        if field in value and (type(value[field]) is not int or value[field] < 0):
            raise ValueError('key version attribute malformed')
    if 'recoveryLevel' in value and value['recoveryLevel'] not in {'Purgeable', 'Recoverable+Purgeable', 'Recoverable', 'Recoverable+ProtectedSubscription', 'CustomizedRecoverable+Purgeable', 'CustomizedRecoverable', 'CustomizedRecoverable+ProtectedSubscription'}:
        raise ValueError('key recovery level malformed')
    return {k: copy.deepcopy(v) for k, v in value.items() if k in ATTRS}


def _kid(value, origin, name=None, versioned=False):
    path = '/keys/' + (re.escape(name) if name else '[A-Za-z0-9-]{1,127}')
    if versioned:
        path += '/[A-Za-z0-9-]{1,127}'
    if not isinstance(value, str) or not re.fullmatch(re.escape(origin) + path, value):
        raise ValueError('foreign or malformed native key identity')
    return value


def collect(reader, transport, scopes, wanted):
    if 'vault_key' not in wanted:
        return
    for scope in scopes:
        def fetch(scope=scope):
            parents = [c for c in reader.collections if c['type'] == 'vault' and c['scope'].casefold() == scope.casefold()]
            if len(parents) != 1 or parents[0]['status'] not in ('collected', 'empty'):
                raise ValueError('vault parent inventory incomplete')
            vaults = parents[0]['items']
            if not isinstance(vaults, list) or (parents[0]['status'] == 'empty') != (not vaults):
                raise ValueError('vault parent inventory inconsistent')
            seen = set()
            for vault in vaults:
                rid = vault.get('id')
                if (not isinstance(rid, str) or not re.fullmatch(re.escape(scope) + r'/resourceGroups/[^/?#%\s\\]+/providers/Microsoft.KeyVault/vaults/[A-Za-z0-9-]{3,24}', rid, re.I)
                        or any(p in ('.', '..') for p in rid.split('/')) or rid.casefold() in seen
                        or str(vault.get('type', '')).casefold() != 'microsoft.keyvault/vaults'):
                    raise ValueError('vault ARM identity malformed or duplicate')
                seen.add(rid.casefold())
                origin = vault.get('properties', {}).get('vaultUri')
                if not isinstance(origin, str) or not re.fullmatch(r'https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net/?', origin):
                    raise ValueError('vault native endpoint malformed')
                origin = origin.rstrip('/')
                if urlsplit(origin).hostname.casefold() != rid.rsplit('/', 1)[1].casefold() + '.vault.azure.net':
                    raise ValueError('vault endpoint differs from ARM identity')
                transport.allow_vault(origin)
                def read(url, *, body=None, audience=VAULT):
                    parsed = urlsplit(url)
                    if (body is not None or audience != VAULT or parsed.scheme != 'https' or parsed.hostname != urlsplit(origin).hostname or parsed.port not in (None, 443)
                            or parsed.fragment or parsed.username or parsed.password
                            or not re.fullmatch(r'/keys(?:/[A-Za-z0-9-]{1,127}(?:/versions|/[A-Za-z0-9-]{1,127}))?', parsed.path)):
                        raise ValueError('untrusted key metadata endpoint')
                    raw = transport.request(url, body=None, audience=VAULT)
                    if not isinstance(raw, dict):
                        raise ValueError('key metadata response malformed')
                    if parsed.path == '/keys' or parsed.path.endswith('/versions'):
                        values = raw.get('value')
                        if not isinstance(values, list) or any(not isinstance(v, dict) for v in values):
                            raise ValueError('key metadata page malformed')
                        # Project before reader.call can retain any response.
                        result = {'value': [{'kid': v.get('kid'), 'attributes': _attributes(v.get('attributes'))} for v in values]}
                        if 'nextLink' in raw and raw['nextLink'] is not None:
                            link = raw['nextLink']
                            if not isinstance(link, str) or not link or link.strip() != link or any(ord(ch) <= 32 for ch in link):
                                raise ValueError('key metadata continuation malformed')
                            follow = urlsplit(link)
                            if (follow.scheme != 'https' or follow.hostname != parsed.hostname or follow.port not in (None, 443)
                                    or follow.path != parsed.path or follow.fragment or follow.username or follow.password):
                                raise ValueError('key metadata continuation foreign')
                            result['nextLink'] = link
                        return result
                    key = raw.get('key')
                    if not isinstance(key, dict) or key.get('kty') not in {'RSA', 'RSA-HSM', 'EC', 'EC-HSM', 'oct', 'oct-HSM'}:
                        raise ValueError('native key type unavailable')
                    public = {k: copy.deepcopy(key[k]) for k in ('kid', 'kty', 'crv', 'n', 'key_ops') if k in key}
                    if 'n' in public and (not isinstance(public['n'], str) or len(public['n']) > 2048 or not re.fullmatch('[A-Za-z0-9_-]+', public['n'])):
                        raise ValueError('native public modulus malformed')
                    if 'crv' in public and public['crv'] not in {'P-256', 'P-256K', 'P-384', 'P-521'}:
                        raise ValueError('native curve malformed')
                    if 'key_ops' in public and (not isinstance(public['key_ops'], list) or len(public['key_ops']) > 32 or any(not isinstance(v, str) or len(v) > 32 for v in public['key_ops'])):
                        raise ValueError('native operations malformed')
                    return {'key': public, 'attributes': _attributes(raw.get('attributes'))}
                versions, names, ids = [], set(), set()
                for page in reader.pages(read, origin + '/keys?api-version=' + VERSION, audience=VAULT):
                    for item in page:
                        kid = _kid(item.get('kid'), origin)
                        name = kid.rsplit('/', 1)[1]
                        if name.casefold() in names:
                            raise ValueError('duplicate native key')
                        names.add(name.casefold())
                        count = 0
                        for vpage in reader.pages(read, kid + '/versions?api-version=' + VERSION, audience=VAULT):
                            for item_version in vpage:
                                vid = _kid(item_version.get('kid'), origin, name, True)
                                if vid.casefold() in ids:
                                    raise ValueError('duplicate native key version')
                                ids.add(vid.casefold())
                                detail = reader.call(read, vid + '?api-version=' + VERSION, audience=VAULT)
                                if detail['key'].get('kid') != vid or detail['attributes'] != item_version['attributes']:
                                    raise ValueError('key version identity or attributes changed')
                                with reader.lock:
                                    if reader.budget.max_items is not None and reader.total >= reader.budget.max_items:
                                        raise ValueError('resource_limit')
                                    reader.total += 1
                                # The frozen evaluator models a vault aggregate. This
                                # normalized child identity retains its exact native kid.
                                versions.append({'id': rid + '/versions/' + name + '/' + vid.rsplit('/', 1)[1],
                                    'native_key_id': vid, 'attributes': detail['attributes'], 'key': detail['key'],
                                    '_provenance': {'source_operation': 'GetKey', 'request_uri': vid,
                                        'api_version': VERSION, 'read_only': True, 'private_material_omitted': True}})
                                count += 1
                        if not count:
                            raise ValueError('listed key has no complete version inventory')
                yield [{'id': rid, 'type': 'Microsoft.KeyVault/vaults', 'versions': versions,
                    '_coverage': {'versions': {'status': 'collected' if versions else 'empty'}},
                    '_provenance': {'source_operation': 'GetKeys/GetKeyVersions/GetKey', 'read_only': True,
                        'api_version': VERSION, 'private_material_omitted': True}}]
        reader.collections.append(reader._read(('vault_key', scope, 'Microsoft.KeyVault', fetch)))
