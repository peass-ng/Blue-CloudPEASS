"""Read-only, request-bound Classic ELB TLS policy configuration, never creator history."""
import copy
import re

OPERATION = 'elb:DescribeLoadBalancerPolicies'
SSL_TYPE = 'SSLNegotiationPolicyType'
MAX_POLICIES = 1000
MAX_ATTRIBUTES = 1024
NON_SSL_TYPES = {'ProxyProtocolPolicyType', 'AppCookieStickinessPolicyType',
                 'LBCookieStickinessPolicyType', 'BackendServerAuthenticationPolicyType', 'PublicKeyPolicyType'}


def tls_names(item):
    listeners = item.get('ListenerDescriptions')
    if not isinstance(listeners, list):
        raise ValueError('listener inventory missing')
    names = set()
    for listener in listeners:
        if not isinstance(listener, dict) or not isinstance(listener.get('Listener'), dict):
            raise ValueError('listener malformed')
        protocol = listener['Listener'].get('Protocol')
        if protocol not in {'HTTP', 'TCP', 'HTTPS', 'SSL'}:
            raise ValueError('unknown listener protocol')
        if protocol not in {'HTTPS', 'SSL'}:
            continue
        values = listener.get('PolicyNames')
        if (not isinstance(values, list) or not values or len(values) != len(set(v for v in values if isinstance(v, str)))
                or any(not isinstance(v, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}', v) for v in values)):
            raise ValueError('TLS policy references missing or malformed')
        names.update(values)
    if len(names) > MAX_POLICIES:
        raise ValueError('TLS policy reference limit')
    return sorted(names)


def policy_rows(value, limit=MAX_POLICIES):
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError('policy inventory missing or exceeds limit')
    rows, seen = [], set()
    for row in value:
        if not isinstance(row, dict):
            raise ValueError('policy malformed')
        name, kind, attrs = row.get('PolicyName'), row.get('PolicyTypeName'), row.get('PolicyAttributeDescriptions')
        # Optional attributes on unrelated native policy types do not supply TLS evidence.
        if attrs is None and kind in NON_SSL_TYPES:
            attrs = []
        if kind == SSL_TYPE and not attrs:
            raise ValueError('SSL policy attributes unavailable')
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}', name)
                or name in seen or not isinstance(kind, str) or not kind or len(kind) > 255
                or not isinstance(attrs, list) or len(attrs) > MAX_ATTRIBUTES):
            raise ValueError('duplicate or malformed policy')
        seen.add(name)
        values = {}
        for attr in attrs:
            if not isinstance(attr, dict):
                raise ValueError('policy attribute malformed')
            key, val = attr.get('AttributeName'), attr.get('AttributeValue')
            if (not isinstance(key, str) or not key or len(key) > 255 or key in values
                    or not isinstance(val, str) or len(val) > 4096):
                raise ValueError('duplicate or malformed policy attribute')
            values[key] = val
        rows.append({'PolicyName': name, 'PolicyTypeName': kind,
                     'PolicyAttributeDescriptions': [{'AttributeName': k, 'AttributeValue': v} for k, v in sorted(values.items())]})
    return rows


def enrich(requests, session, region, item, account):
    # The shared reader enforces deadlines, retry limits, call budget and cache.
    # Missing detail is represented explicitly, never as an empty success.
    try:
        names = tls_names(item)
        if not names:
            return item
        lb = item.get('LoadBalancerName')
        if not isinstance(lb, str) or not lb or not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account):
            raise ValueError('load balancer account identity missing')
        captured = requests.observed_at.isoformat()
        limit = min(MAX_POLICIES, requests.max_items) if requests.max_items is not None else MAX_POLICIES
        for field, args in [('SSLPolicyDetails', {'LoadBalancerName': lb, 'PolicyNames': names}), ('SSLPolicyCatalog', {})]:
            raw = requests.detail(session, 'elb', region, 'describe_load_balancer_policies', **args)
            env = {'collection_status': raw.get('collection_status', 'not_collected')}
            if env['collection_status'] == 'collected':
                try:
                    if any(raw.get(k) for k in ('NextToken', 'NextMarker', 'Marker', 'nextToken', 'IsTruncated')):
                        raise ValueError('unhandled policy pagination')
                    rows = policy_rows(raw.get('PolicyDescriptions'), limit)
                    if field == 'SSLPolicyDetails' and {row['PolicyName'] for row in rows} != set(names):
                        raise ValueError('requested policy detail missing or foreign')
                    env.update(PolicyDescriptions=rows, _provenance={
                        'operation': OPERATION, 'account_id': account, 'region': region,
                        'request': copy.deepcopy(args), 'read_only': True, 'captured_at': captured})
                except (ValueError, TypeError):
                    env = {'collection_status': 'malformed', 'error': {'code': 'elb_policy_response_unresolved'}}
            elif 'error' in raw:
                env['error'] = copy.deepcopy(raw['error'])
            item[field] = env
    except (ValueError, TypeError, AttributeError):
        item['SSLPolicyDetails'] = {'collection_status': 'not_collected', 'error': {'code': 'elb_policy_scope_unresolved'}}
    return item
