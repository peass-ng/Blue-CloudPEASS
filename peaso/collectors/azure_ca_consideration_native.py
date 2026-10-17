"""Explicit operator consideration bound to a universal native device-flow block.

Pure metadata interpretation; no simulated sign-ins, principal partitions or
shared review inventory is manufactured. Complex policy contexts fall through.
"""
from datetime import datetime
import hashlib
import json
import re

CID = 'azure.cis.exclusionary_device_code_flow_policy_considered'
KEY = CID.replace('.', '|')
ENDPOINT = '/v1.0/identity/conditionalAccess/policies'
GUID = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
CLIENTS = {'all', 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other'}
RELEVANT = ('id', 'state', 'conditions', 'grantControls', 'sessionControls')


def _text(value, maximum=2048):
    if (not isinstance(value, str) or not value or len(value) > maximum or value != value.strip()
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('invalid device-flow consideration text')
    return value


def _date(value):
    value = datetime.fromisoformat(_text(value, 64).replace('Z', '+00:00'))
    if value.utcoffset() is None: raise ValueError('consideration date timezone missing')
    return value


def _list(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 128: raise ValueError('consideration scope list missing')
    for row in value: _text(row, 128)
    if len({r.casefold() for r in value}) != len(value): raise ValueError('duplicate consideration identity')
    return value


def validate_config(config):
    """Normative scope and a human decision; never client-supplied observations."""
    fields = {'userScope', 'requiredApplications', 'requiredClientAppTypes', 'consideration'}
    if not isinstance(config, dict) or set(config) != fields or config['userScope'] != 'all':
        raise ValueError('only explicitly approved all-user device scope supported')
    apps = _list(config['requiredApplications'])
    if apps != ['All'] and any(re.fullmatch(GUID, a) is None for a in apps): raise ValueError('unsupported application scope')
    clients = _list(config['requiredClientAppTypes'])
    if set(clients) - CLIENTS or ('all' in clients and clients != ['all']): raise ValueError('unsupported client scope')
    decision = config['consideration']
    if not isinstance(decision, dict) or set(decision) != {'decision', 'reviewedPolicies'} or decision['decision'] != 'block':
        raise ValueError('explicit device-flow block decision required')
    reviews = decision['reviewedPolicies']
    if not isinstance(reviews, list) or not 1 <= len(reviews) <= 64: raise ValueError('reviewed policy bindings required')
    seen = set()
    for review in reviews:
        if (not isinstance(review, dict) or set(review) != {'policyId', 'configurationSha256'}
                or not isinstance(review['policyId'], str) or re.fullmatch(GUID, review['policyId']) is None
                or review['policyId'].casefold() in seen or not isinstance(review['configurationSha256'], str)
                or re.fullmatch(r'[0-9a-f]{64}', review['configurationSha256']) is None):
            raise ValueError('invalid or duplicate reviewed policy binding')
        seen.add(review['policyId'].casefold())
    return config


def digest(rule):
    """Versioned relevant-field contract, excluding display names/provenance only.

    Entire conditions/grants/session objects participate, including unfamiliar
    fields. Omitted sessionControls is canonical null; no enforcement field is
    silently discarded by selecting only a known subset of nested conditions.
    """
    if not isinstance(rule, dict): raise ValueError('native policy missing')
    fields = {name: rule.get(name) for name in RELEVANT}
    encoded = json.dumps(fields, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    if len(encoded) > 262144: raise ValueError('native policy exceeds bounded review')
    return hashlib.sha256(encoded).hexdigest()


def _other_empty(obj, allowed):
    if not isinstance(obj, dict): return False
    return all(value in (None, [], {}) for key, value in obj.items() if key not in allowed)


def _universal(rule):
    if rule.get('state') != 'enabled': return False
    root_fields = {*RELEVANT, 'displayName', 'description', 'createdDateTime', 'modifiedDateTime', 'templateId', '_provenance', '@odata.context', '@odata.type'}
    if not _other_empty(rule, root_fields): return False
    conditions = rule.get('conditions')
    if not _other_empty(conditions, {'users', 'applications', 'clientAppTypes', 'authenticationFlows'}): return False
    users = conditions.get('users')
    if not isinstance(users, dict) or users.get('includeUsers') != ['All'] or not _other_empty(users, {'includeUsers'}): return False
    apps = conditions.get('applications')
    if not isinstance(apps, dict) or apps.get('includeApplications') != ['All'] or not _other_empty(apps, {'includeApplications'}): return False
    if conditions.get('clientAppTypes') != ['all']: return False
    flows = conditions.get('authenticationFlows')
    if not isinstance(flows, dict) or flows.get('transferMethods') != 'deviceCodeFlow' or not _other_empty(flows, {'transferMethods'}): return False
    grant = rule.get('grantControls')
    if (not isinstance(grant, dict) or grant.get('builtInControls') != ['block'] or grant.get('operator') not in ('AND', 'OR')
            or not _other_empty(grant, {'builtInControls', 'operator'})):
        return False
    if rule.get('sessionControls') not in (None, {}): return False
    # Redaction/partial-field metadata must never masquerade as empty conditions.
    return not any(k.startswith('_') and value not in (None, [], {}) for k, value in rule.items() if k != '_provenance')


def native_result(item, context, rules, config):
    """Return only a proved PASS, otherwise None for the legacy evidence path."""
    try:
        validate_config(config)
        scope = context.get('scope')
        if not isinstance(scope, str) or re.fullmatch('/tenants/' + GUID, scope) is None: return None
        tenant = scope.removeprefix('/tenants/').casefold()
        review = context.get('metadata', {}).get('compliance_policy', {}).get('sw13')
        if (not isinstance(review, dict) or review.get('status') != 'collected'
                or str(review.get('scope', '')).casefold() != scope.casefold()
                or review.get('checks', {}).get(KEY) != config): return None
        _text(review.get('authorized_by')); _text(review.get('document_id'))
        at, begin, end = _date(context.get('created_at')), _date(review.get('observed_at')), _date(review.get('expires_at'))
        if not begin <= at < end: return None
        native = {}
        for rule in rules:
            if not isinstance(rule, dict): return None
            rid, proof = rule.get('id'), rule.get('_provenance')
            if (not isinstance(rid, str) or re.fullmatch(GUID, rid) is None or rid.casefold() in native
                    or not isinstance(proof, dict) or proof.get('endpoint') != ENDPOINT
                    or proof.get('read_only') is not True or proof.get('tenant_verified') is not True
                    or str(proof.get('tenant_id', '')).casefold() != tenant): return None
            if rule.get('state') not in ('enabled', 'disabled', 'enabledForReportingButNotEnforced'): return None
            native[rid.casefold()] = rule
        if not isinstance(item, dict) or native.get(str(item.get('id', '')).casefold()) != item: return None
        qualified = []
        for approval in config['consideration']['reviewedPolicies']:
            rule = native.get(approval['policyId'].casefold())
            if rule is None or digest(rule) != approval['configurationSha256']: return None
            if _universal(rule): qualified.append(rule['id'])
        if not qualified: return None
        return 'PASS', {'review_document_id': review['document_id'], 'reviewed_universal_block_policy_ids': sorted(qualified),
            'semantics': 'Explicit operator consideration and current native universal user device-code block; no simulated sign-in or workload-identity claim'}
    except (ValueError, TypeError, KeyError, AttributeError):
        return None
