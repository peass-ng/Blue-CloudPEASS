"""Explicit owner subnet applicability, separate from native routing evidence."""
from copy import deepcopy
from datetime import datetime, timezone
import re

NAMESPACE = 'azure_subnet_firewall'
UUID = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
SEGMENT = r'[A-Za-z0-9_.()-]{1,90}'
SCOPE = r'/subscriptions/' + UUID
SUBNET = SCOPE + r'/resourceGroups/' + SEGMENT + r'/providers/Microsoft\.Network/virtualNetworks/' + SEGMENT + r'/subnets/' + SEGMENT
FIELDS = {'status', 'scope', 'authorized_by', 'document_id', 'observed_at', 'expires_at', 'subnet_ids'}


def _time(value):
    if not isinstance(value, str):
        raise ValueError('subnet scope approval timestamp unavailable')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError('subnet scope approval timestamp lacks timezone')
    return parsed


def normalize(options):
    parameters = options.get('compliance_parameters')
    if not isinstance(parameters, dict) or NAMESPACE not in parameters:
        return None
    value = parameters[NAMESPACE]
    if not isinstance(value, dict) or set(value) != FIELDS or value.get('status') != 'collected':
        raise ValueError('unsupported subnet applicability approval')
    scope = value.get('scope')
    if not isinstance(scope, str) or not re.fullmatch(SCOPE, scope, re.I):
        raise ValueError('invalid subnet approval subscription')
    for key in ('authorized_by', 'document_id'):
        text = value.get(key)
        if (not isinstance(text, str) or not 0 < len(text) <= 256 or text != text.strip()
                or any(ord(c) < 32 or ord(c) == 127 for c in text)):
            raise ValueError('subnet approval authority unavailable')
    if _time(value['observed_at']) >= _time(value['expires_at']):
        raise ValueError('invalid subnet approval validity window')
    ids = value.get('subnet_ids')
    if not isinstance(ids, list) or not 0 < len(ids) <= 256:
        raise ValueError('bounded explicit subnet scope required')
    seen = set()
    for rid in ids:
        if (not isinstance(rid, str) or not re.fullmatch(SUBNET, rid, re.I)
                or not rid.casefold().startswith(scope.casefold() + '/')
                or any(part in ('.', '..') for part in rid.split('/'))
                or rid.casefold() in seen):
            raise ValueError('foreign, duplicate or malformed approved subnet')
        seen.add(rid.casefold())
    return deepcopy(value)


def active(options):
    owner = normalize(options)
    if owner is None:
        return False
    return _time(owner['observed_at']) <= datetime.now(timezone.utc) < _time(owner['expires_at'])


def project(reader, scopes, options):
    """Apply current owner decisions only to matching complete native subnet rows.

    Missing decisions remain unknown. This does not approve any firewall,
    certify deployment or infer observed network behavior.
    """
    sources = [c for c in reader.collections if c.get('type') == 'subnet']
    for source in sources:
        for row in source.get('items', []):
            if isinstance(row, dict):
                row.pop('_policy', None)  # ARM cannot supply an operator decision.
    owner = normalize(options)
    if owner is None or owner['scope'].casefold() not in {s.casefold() for s in scopes}:
        return
    now = datetime.now(timezone.utc)
    if not _time(owner['observed_at']) <= now < _time(owner['expires_at']):
        return
    scope = owner['scope'].casefold()
    relevant = [c for c in sources if str(c.get('scope', '')).casefold().startswith(scope + '/')]
    matched = {}
    for source in relevant:
        if (source.get('service') != 'Microsoft.Network'
                or source.get('status') not in ('collected', 'empty')
                or not isinstance(source.get('items'), list)
                or (source['status'] == 'empty' and source['items'])):
            return
        parent = str(source['scope']).casefold()
        for row in source['items']:
            rid = row.get('id') if isinstance(row, dict) else None
            if (not isinstance(rid, str) or not re.fullmatch(SUBNET, rid, re.I)
                    or rid.casefold().rsplit('/subnets/', 1)[0] != parent
                    or rid.casefold() in matched):
                return
            matched[rid.casefold()] = row
    for rid in owner['subnet_ids']:
        row = matched.get(rid.casefold())
        if row is not None:
            row['_policy'] = {'source': 'approved_policy', 'status': 'collected', 'inScope': True,
                '_provenance': {'authority': 'explicit_operator_decision',
                    'scope': owner['scope'], 'authorized_by': owner['authorized_by'],
                    'document_id': owner['document_id'], 'observed_at': owner['observed_at'],
                    'expires_at': owner['expires_at']}}
