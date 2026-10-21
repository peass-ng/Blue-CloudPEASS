"""GCP network objects with provider-reported structural absence.

These checks describe current attachments, not traffic or historical usage.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from peaso.checks.facts import Unavailable, get, omitted


ADDRESS = 'gcp.network.address_reserved_without_users'
POLICY = 'gcp.network.firewall_policy_without_associations'
NEG = 'gcp.network.endpoint_group_without_endpoints'
HTTP_PROXY = 'gcp.network.http_proxy_forwarding_rule_reference'
HTTPS_PROXY = 'gcp.network.https_proxy_forwarding_rule_reference'
BACKEND = 'gcp.network.backend_service_has_members'


def _source(item, index, segment, paths):
    proof = get(item, '_provenance', dict)
    scope = get(proof, 'scope', str)
    if not re.fullmatch(r'projects/[a-z][a-z0-9-]{4,28}[a-z0-9]', scope):
        raise Unavailable('network resource project scope is unavailable')
    context = index.get('context', {})
    if context and (context.get('provider') != 'gcp' or context.get('scope') != scope):
        raise Unavailable('network resource belongs to another capture')
    if proof.get('representation') != 'full':
        raise Unavailable('full native network representation is unavailable')
    link = get(item, 'selfLink', str)
    parsed = urlsplit(link)
    prefix = f'/compute/v1/{scope}/'
    if (parsed.scheme != 'https' or parsed.hostname not in {'compute.googleapis.com', 'www.googleapis.com'}
            or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.query or parsed.fragment
            or not parsed.path.startswith(prefix) or not re.fullmatch(segment, parsed.path[len(prefix):])):
        raise Unavailable('network resource identity does not match its native project and kind')
    refs = get(proof, 'source_requests', list)
    ledger = context.get('metadata', {}).get('source_requests')
    if not refs or any(not isinstance(ref, str) or not ref for ref in refs) or not isinstance(ledger, list):
        raise Unavailable('network resource source requests are unavailable')
    receipts = [row for row in ledger if isinstance(row, dict) and row.get('id') in refs]
    if len(receipts) != len(refs) or {row.get('id') for row in receipts} != set(refs):
        raise Unavailable('network resource source requests are incomplete or duplicated')
    allowed = {'maxResults', 'pageToken', 'returnPartialSuccess'}
    if not any(row.get('scope') == scope and row.get('method') == 'GET' and row.get('status') == 'collected'
               and row.get('http_status') == 200 and isinstance(row.get('query'), dict)
               and not (set(row['query']) - allowed)
               and row.get('url') in {'https://compute.googleapis.com/compute/v1/' + scope + '/' + path for path in paths}
               for row in receipts):
        raise Unavailable('full unfiltered Compute list receipt is unavailable')
    return scope, link


def _lines(identity, observation, conclusion):
    return f'{identity}\n{observation}\n{conclusion}'


def evaluate_address(item, index):
    _, link = _source(item, index, r'(?:regions/[a-z0-9-]+|global)/addresses/[^/?#]+',
                      ('aggregated/addresses',))
    status = get(item, 'status', str)
    if status not in {'RESERVING', 'RESERVED', 'IN_USE'}:
        raise Unavailable('address status is unrecognized')
    users = omitted(item, 'users', [], list)
    if any(not isinstance(user, str) or not user for user in users):
        raise Unavailable('address users are malformed')
    if status == 'RESERVING':
        return 'UNKNOWN', {'reason': 'address reservation is in progress', 'address': link}
    if status == 'IN_USE' and not users or status == 'RESERVED' and users:
        raise Unavailable('address status and users disagree')
    unused = status == 'RESERVED'
    return ('FAIL' if unused else 'PASS'), {'address': link, 'status': status, 'users': users,
        'summary': _lines(link, f'Compute reports status {status} and {len(users)} resource user(s).',
            'The address has no current resource user.' if unused else 'The address has a current resource user.')}


def evaluate_policy(item, index):
    _, link = _source(item, index, r'(?:global|regions/[a-z0-9-]+)/firewallPolicies/[^/?#]+',
                      ('aggregated/firewallPolicies',))
    associations = omitted(item, 'associations', [], list)
    if any(not isinstance(row, dict) or not isinstance(row.get('attachmentTarget'), str)
           or not row['attachmentTarget'] for row in associations):
        raise Unavailable('firewall policy associations are malformed')
    unused = not associations
    targets = [row['attachmentTarget'] for row in associations]
    return ('FAIL' if unused else 'PASS'), {'policy': link, 'attachment_targets': targets,
        'summary': _lines(link, f'Compute reports {len(targets)} policy association(s).',
            'The policy has no current attachment.' if unused else 'The policy has a current attachment.')}


def evaluate_neg(item, index):
    _, link = _source(item, index, r'(?:global|regions/[a-z0-9-]+|zones/[a-z0-9-]+)/networkEndpointGroups/[^/?#]+',
                      ('aggregated/networkEndpointGroups', 'global/networkEndpointGroups'))
    kind = get(item, 'networkEndpointType', str)
    if kind in {'SERVERLESS', 'PRIVATE_SERVICE_CONNECT'}:
        return 'NOT_APPLICABLE', {'reason': 'endpoint count does not describe this managed endpoint type'}
    size = get(item, 'size', int)
    if size < 0:
        raise Unavailable('network endpoint count is malformed')
    return ('FAIL' if size == 0 else 'PASS'), {'endpoint_group': link, 'endpoint_count': size,
        'summary': _lines(link, f'Compute reports {size} network endpoint(s).',
            'The group currently has no endpoint.' if size == 0 else 'The group currently has an endpoint.')}


def _canonical(url, scope, segment):
    if not isinstance(url, str):
        raise Unavailable('Compute resource URL is malformed')
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in {'compute.googleapis.com', 'www.googleapis.com'}
            or parsed.port not in (None, 443) or parsed.username or parsed.password
            or parsed.query or parsed.fragment
            or not re.fullmatch('/compute/v1/' + re.escape(scope) + '/' + segment, parsed.path)):
        raise Unavailable('Compute resource URL does not match canonical project and kind')
    return parsed.path


def _forwarding_rules(index, scope):
    rows = index.get('collections', {}).get('forwarding_rule', [])
    if (not isinstance(rows, list) or len(rows) != 1 or rows[0].get('scope') != scope
            or rows[0].get('status') not in ('collected', 'empty')
            or not isinstance(rows[0].get('items'), list)):
        raise Unavailable('complete forwarding rule collection is unavailable')
    ledger = index.get('context', {}).get('metadata', {}).get('source_requests')
    refs = rows[0].get('source_requests')
    if not isinstance(ledger, list) or not isinstance(refs, list) or not refs:
        raise Unavailable('forwarding rule list receipts are unavailable')
    receipts = [r for r in ledger if isinstance(r, dict) and r.get('id') in refs]
    expected = {f'https://compute.googleapis.com/compute/v1/{scope}/aggregated/forwardingRules',
                f'https://compute.googleapis.com/compute/v1/{scope}/global/forwardingRules'}
    if (len(receipts) != len(refs) or {r.get('id') for r in receipts} != set(refs)
            or {r.get('url') for r in receipts} != expected
            or any(r.get('scope') != scope or r.get('method') != 'GET'
                   or r.get('status') != 'collected' or r.get('http_status') != 200
                   or not isinstance(r.get('query'), dict)
                   or set(r['query']) - {'maxResults', 'pageToken', 'returnPartialSuccess'} for r in receipts)):
        raise Unavailable('both unfiltered forwarding rule lists are not proven')
    projected = index.get('forwarding_rule', [])
    if (not isinstance(projected, list) or len(projected) != len(rows[0]['items'])
            or any(not isinstance(row, dict) or row.get('data') != raw
                   for row, raw in zip(projected, rows[0]['items']))):
        raise Unavailable('forwarding rule projection is incomplete')
    return rows[0]['items']


def evaluate_proxy(item, index, expected_kind=None):
    scope, link = _source(item, index, r'(?:global|regions/[a-z0-9-]+)/targetHttps?Proxies/[^/?#]+',
                          ('aggregated/targetHttpProxies', 'aggregated/targetHttpsProxies'))
    kind = get(item, '_proxy_type', str)
    if kind not in ('targetHttpProxies', 'targetHttpsProxies') or f'/{kind}/' not in link:
        raise Unavailable('target proxy kind disagrees with native identity')
    if expected_kind is not None and kind != expected_kind:
        return 'NOT_APPLICABLE', {'reason': 'target proxy belongs to the other HTTP protocol family'}
    target = _canonical(link, scope, r'(?:global|regions/[a-z0-9-]+)/' + kind + r'/[^/?#]+')
    rules = _forwarding_rules(index, scope)
    consumers = []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get('_provenance', {}).get('representation') != 'full':
            raise Unavailable('forwarding rule representation is incomplete')
        rule_link = get(rule, 'selfLink', str)
        _canonical(rule_link, scope, r'(?:global|regions/[a-z0-9-]+)/forwardingRules/[^/?#]+')
        ref = rule.get('target')
        if ref is None:
            continue
        parsed = urlsplit(ref) if isinstance(ref, str) else None
        if parsed is None or parsed.scheme != 'https' or parsed.hostname not in {'compute.googleapis.com', 'www.googleapis.com'} or parsed.query or parsed.fragment:
            raise Unavailable('forwarding rule target URL is malformed')
        if parsed.path == target:
            consumers.append(rule_link)
    if consumers:
        return 'PASS', {'target_proxy': link, 'forwarding_rules': consumers,
            'summary': _lines(link, f'{len(consumers)} forwarding rule(s) reference this exact proxy URL.',
                              'The proxy has an observed frontend reference.')}
    return 'UNKNOWN', {'target_proxy': link, 'reason': 'no local reference; cross-project proxy references are not excluded by reviewed sources'}


def evaluate_http_proxy(item, index):
    return evaluate_proxy(item, index, 'targetHttpProxies')


def evaluate_https_proxy(item, index):
    return evaluate_proxy(item, index, 'targetHttpsProxies')


def evaluate_backend(item, index):
    _, link = _source(item, index, r'(?:global|regions/[a-z0-9-]+)/backendServices/[^/?#]+',
                      ('aggregated/backendServices',))
    backends = omitted(item, 'backends', [], list)
    bindings = omitted(item, 'serviceBindings', [], list)
    if (any(not isinstance(row, dict) or not isinstance(row.get('group'), str) or not row['group'] for row in backends)
            or any(not isinstance(value, str) or not value for value in bindings)):
        raise Unavailable('backend membership is malformed')
    count = len(backends) + len(bindings)
    # A serverless or internet NEG is a backend group, so it is included above.
    return ('PASS' if count else 'FAIL'), {'backend_service': link, 'backend_count': len(backends),
        'service_binding_count': len(bindings),
        'summary': _lines(link, f'Compute reports {len(backends)} backend group(s) and {len(bindings)} service binding(s).',
            'The service has a declared member.' if count else 'The service has no declared member.')}


DECLARATIONS = (
    (ADDRESS, 'address', 'Reserved address has a resource user', evaluate_address,
     'Review the reservation owner and release an address with no intended consumer.'),
    (POLICY, 'firewall_policy', 'Firewall policy has an association', evaluate_policy,
     'Review policy ownership and attach it to its intended target or remove an obsolete policy.'),
    (NEG, 'network_endpoint_group', 'Network endpoint group contains endpoints', evaluate_neg,
     'Review the endpoint group owner and populate intended endpoints or remove an obsolete group.'),
    (HTTP_PROXY, 'target_proxy', 'HTTP target proxy has an observed forwarding rule', evaluate_http_proxy,
     'Review the target proxy and its forwarding rule ownership.'),
    (HTTPS_PROXY, 'target_proxy', 'HTTPS target proxy has an observed forwarding rule', evaluate_https_proxy,
     'Review the target proxy and its forwarding rule ownership.'),
    (BACKEND, 'backend_service', 'Backend service has a declared member', evaluate_backend,
     'Review the backend service owner and attach an intended backend or service binding.'),
)


def install(registry):
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_network_gcp_cases.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != CASES_SHA256:
        raise ValueError('GCP unused network cases changed')
    cases = json.loads(raw)
    if set(cases) != {ADDRESS, POLICY, NEG, HTTP_PROXY, HTTPS_PROXY, BACKEND}:
        raise ValueError('GCP unused network case IDs changed')
    CASES.update(cases)
    for cid, kind, title, evaluator, remediation in DECLARATIONS:
        registry.register(cid, 'gcp', 'hardening', kind, title, 'low', 'CM-8', remediation,
                          dependencies=(kind, 'forwarding_rule') if cid in (HTTP_PROXY, HTTPS_PROXY) else (kind,),
                          allow_incomplete_failure=True)(evaluator)


CASES_SHA256 = 'b98c8bedef3467c66d380205cd820e3e2c1af223fb290df391e659c366d7e4f4'
