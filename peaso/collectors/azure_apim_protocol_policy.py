"""Project native APIM protocols under explicit, scoped approved rule parameters.

No network operations, implicit HTTPS rule, or invented protocol observations.
The existing signed SW23 evaluator remains the authority for the verdict.
"""
from __future__ import annotations
import copy
from datetime import datetime, timezone
import re

KIND = 'apim_api_evidence'
CID = 'azure_api_management_1_2_8_1_ba319cf'
SPEC = '0d01a758e49f3c58bbb3c169ba87576979a3bfe01c97bc33859ee849b8d45f78'
PROTOCOLS = {'http', 'https', 'ws', 'wss'}
SERVICE = re.compile(r'/subscriptions/[^/?#%\s]+/resourcegroups/[^/?#%\s]+/providers/microsoft\.apimanagement/service/[^/?#%\s]+', re.I)


def _object(value):
    if not isinstance(value, dict):
        raise ValueError('object unavailable')
    return value


def _time(value):
    if not isinstance(value, str):
        raise ValueError('timestamp unavailable')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.utcoffset() is None:
        raise ValueError('timestamp timezone unavailable')
    return result


def _unique(rows):
    found = {}
    for row in rows:
        _object(row)
        rid = row.get('id')
        if not isinstance(rid, str) or not rid or rid.casefold() in found:
            raise ValueError('missing or duplicate native identity')
        found[rid.casefold()] = row
    return found


def _mapping(value):
    _object(value)
    result = {}
    for key, row in value.items():
        if not isinstance(key, str) or key.casefold() in result:
            raise ValueError('ambiguous policy identity')
        result[key.casefold()] = _object(row)
    return result


def _inventory(collections, scope, kind):
    rows = [c for c in collections if c.get('type') == kind and str(c.get('scope', '')).casefold() == scope.casefold()]
    if len(rows) != 1 or rows[0].get('status') not in ('collected', 'empty'):
        raise ValueError('native inventory incomplete')
    items = rows[0].get('items')
    if not isinstance(items, list) or (rows[0]['status'] == 'empty' and items):
        raise ValueError('native inventory shape unavailable')
    return _unique(items)


def _children(fact):
    coverage = _object(fact.get('_coverage'))
    status = _object(coverage.get('apis')).get('status')
    rows = fact.get('apis')
    if status not in ('collected', 'empty') or not isinstance(rows, list) or status == 'empty' and rows:
        raise ValueError('API pages incomplete')
    apis = _unique(rows)
    if _object(coverage.get('revisions')).get('status') != 'collected':
        raise ValueError('API revision pages incomplete')
    online = fact.get('online_api_ids')
    if not isinstance(online, list) or any(not isinstance(x, str) for x in online):
        raise ValueError('online revision identities unavailable')
    lowered = [x.casefold() for x in online]
    if len(set(lowered)) != len(lowered) or not set(lowered) <= apis.keys():
        raise ValueError('online revision join unavailable')
    parent = fact['id']
    for api in apis.values():
        if not re.fullmatch(re.escape(parent) + r'/apis/[^/?#%\s]+', api['id'], re.I):
            raise ValueError('foreign API identity')
    return apis


def _approved(options, scope, instant):
    root = _object(_object(options.get('compliance_policy')).get('sw23'))
    if root.get('status') != 'collected' or str(root.get('scope', '')).casefold() != scope.casefold():
        raise ValueError('approved protocol scope unavailable')
    for key in ('authorized_by', 'document_id'):
        if not isinstance(root.get(key), str) or not root[key].strip():
            raise ValueError('approval identity unavailable')
    if not _time(root.get('observed_at')) <= _time(instant) < _time(root.get('expires_at')):
        raise ValueError('protocol approval is not current')
    return root, _mapping(root.get('apim_protocols'))


def project(reader, scopes, wanted, options, instant=None):
    """Append one exact evidence collection per scope; return its snapshot clock."""
    if KIND not in wanted:
        return instant
    instant = instant or datetime.now(timezone.utc).isoformat()
    source = list(reader.collections)
    for scope in scopes:
        envelope = {'type': KIND, 'scope': scope, 'service': 'Microsoft.ApiManagement', 'items': []}
        try:
            parents = _inventory(source, scope, 'api_management')
            facts = _inventory(source, scope, 'apim_native')
            if parents.keys() != facts.keys():
                raise ValueError('APIM parent inventory differs')
            if parents:
                approval, policies = _approved(options, scope, instant)
                if policies.keys() != parents.keys():
                    raise ValueError('approved service coverage differs')
            for sid, parent in parents.items():
                if not SERVICE.fullmatch(parent['id']) or not sid.startswith(scope.casefold() + '/'):
                    raise ValueError('APIM service identity unavailable')
                fact = facts[sid]
                if str(fact.get('parent_id', '')).casefold() != sid:
                    raise ValueError('APIM fact parent differs')
                apis = _children(fact)
                policy = policies[sid]
                if policy.get('proposed_spec_sha256') != SPEC:
                    raise ValueError('protocol rule is not bound to frozen specification')
                rules = _mapping(policy.get('apis'))
                if rules.keys() != apis.keys():
                    raise ValueError('approved API coverage differs')
                projected = []
                for aid, api in apis.items():
                    actual = _object(api.get('properties')).get('protocols')
                    if not isinstance(actual, list) or any(not isinstance(p, str) or p not in PROTOCOLS for p in actual) or len(set(actual)) != len(actual):
                        raise ValueError('native protocols unavailable or unsupported')
                    rule = rules[aid]
                    expected, forbidden = rule.get('expected_endpoint_type'), rule.get('forbidden_protocols')
                    if not isinstance(expected, str) or expected not in PROTOCOLS or not isinstance(forbidden, list) or any(not isinstance(p, str) or p not in PROTOCOLS for p in forbidden) or len(set(forbidden)) != len(forbidden) or expected in forbidden:
                        raise ValueError('approved protocol parameters unavailable or contradictory')
                    projected.append({'id': api['id'], 'properties': {'protocols': copy.deepcopy(actual)},
                                      'frozen_protocol_policy': {'frozen': True, 'scope_resolved': True,
                                          'expected_endpoint_type': expected, 'forbidden_protocols': list(forbidden)}})
                envelope['items'].append({'id': parent['id'] + '/complianceEvidence/apimProtocols', 'parent_id': parent['id'],
                    'payload': {'revision_coverage_complete': True, 'apis': {'collection_status': 'collected' if projected else 'empty', 'items': projected}},
                    '_provenance': {'schema_version': 1, 'read_only': True, 'complete': True, 'policy_approved': True,
                        'captured_at': instant, 'source_operation': 'APIs_LIST+API_revisions_LIST+missing_online_revision_GET',
                        'policy_document_id': approval['document_id'], 'policy_authorized_by': approval['authorized_by'],
                        'proposed_spec_sha256': SPEC}})
            envelope['status'] = 'collected' if envelope['items'] else 'empty'
            with reader.lock:
                available = None if reader.budget.max_items is None else max(0, reader.budget.max_items - reader.total)
                if available is not None and len(envelope['items']) > available:
                    envelope['items'] = envelope['items'][:available]
                    envelope.update(status='partial', error={'code': 'resource_limit'})
                reader.total += len(envelope['items'])
        except (ValueError, TypeError, KeyError, AttributeError):
            envelope.update(status='unknown', items=[], error={'code': 'apim_protocol_native_or_approved_policy_unavailable'})
        reader.collections.append(envelope)
    return instant
