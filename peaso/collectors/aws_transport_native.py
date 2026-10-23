"""Declared TLS policy joins for ALB/NLB listeners, REST domains and CloudFront.

These records describe endpoint configuration, never a network probe or a peer
certificate validation. A missing source family invalidates complete coverage.
"""
from __future__ import annotations

import re

SPECS = {'transport_endpoint': ('elbv2', 'describe_listeners', None)}
NATIVE_IDS = {'transport_endpoint': 'id'}
READ_ACTIONS = {('elbv2', 'describe_load_balancers'), ('elbv2', 'describe_listeners'),
                ('apigateway', 'get_domain_names'), ('cloudfront', 'list_distributions')}


def _result(rows=(), status=None, code=None):
    from .aws import ReadResult
    rows = list(rows)
    return ReadResult(rows, status or ('collected' if rows else 'empty'), {'code': code} if code else None)


def _arn(value, partition, service, account, region):
    return isinstance(value, str) and bool(re.fullmatch('arn:' + re.escape(partition) + ':' + service + ':'
        + re.escape(region) + ':' + re.escape(account) + ':.+', value))


def _distributions(requests, session, region):
    """Validate every CloudFront page, including documented omitted empty Items."""
    from .aws import _failure
    from .aws_facts_cb_ca import _home
    rows, params, seen, page = [], {}, set(), 0
    try:
        while requests.max_pages is None or page < requests.max_pages:
            page += 1
            response = requests.call(session, 'cloudfront', _home(region, 'us-east-1'), 'list_distributions', **params)
            listing = response.get('DistributionList')
            if (not isinstance(listing, dict) or type(listing.get('Quantity')) is not int
                    or listing['Quantity'] < 0 or type(listing.get('IsTruncated')) is not bool):
                return _result(rows, 'partial' if rows else 'malformed', 'transport_cloudfront_listing_malformed')
            items = listing.get('Items', [])
            if not isinstance(items, list) or len(items) != listing['Quantity'] or any(not isinstance(item, dict) for item in items):
                return _result(rows, 'partial' if rows else 'malformed', 'transport_cloudfront_count_mismatch')
            rows.extend(items)
            if requests.max_items is not None and len(rows) > requests.max_items:
                return _result(rows[:requests.max_items], 'partial', 'resource_limit')
            token = listing.get('NextMarker')
            if not listing['IsTruncated']:
                if token:
                    return _result(rows, 'partial' if rows else 'malformed', 'transport_cloudfront_pagination_inconsistent')
                return _result(rows)
            if not isinstance(token, str) or not token or token in seen:
                return _result(rows, 'partial' if rows else 'malformed', 'transport_cloudfront_cursor_invalid')
            seen.add(token)
            params = {'Marker': token}
        return _result(rows, 'partial' if rows else 'not_collected', 'page_limit')
    except Exception as exc:
        error = _failure(exc)
        return _result(rows, 'partial' if rows else error.status, error.code)


def endpoints(requests, session, region, account):
    partition = session.get_partition_for_region(region)
    scope = account + '/' + region
    rows, seen = [], set()
    def failure(read):
        return _result(rows, 'partial' if rows else read.status,
                       (read.error or {}).get('code', 'transport_source_inventory_incomplete'))
    def append(identity, kind, protocol, external, policy, operation, **extra):
        if identity in seen:
            raise ValueError('transport_endpoint_duplicate_identity')
        seen.add(identity)
        rows.append({'id': identity, 'SourceKind': kind, 'Protocol': protocol, 'External': external,
            'TLSPolicy': policy, 'Scope': scope, 'AccountId': account,
            '_provenance': {'source_operation': operation, 'read_only': True,
                            'semantics': 'configuration only; endpoint reachability and peer certificates unassessed'}, **extra})
    try:
        lbs = requests.pages(session, 'elbv2', region, 'describe_load_balancers', 'LoadBalancers')
        if lbs.status not in ('collected', 'empty'):
            return failure(lbs)
        for lb in lbs.items:
            arn = lb.get('LoadBalancerArn') if isinstance(lb, dict) else None
            if not _arn(arn, partition, 'elasticloadbalancing', account, region) or lb.get('Scheme') not in ('internet-facing', 'internal'):
                raise ValueError('transport_load_balancer_identity_invalid')
            listeners = requests.pages(session, 'elbv2', region, 'describe_listeners', 'Listeners', LoadBalancerArn=arn)
            if listeners.status not in ('collected', 'empty'):
                return failure(listeners)
            for listener in listeners.items:
                identity = listener.get('ListenerArn') if isinstance(listener, dict) else None
                protocol = listener.get('Protocol') if isinstance(listener, dict) else None
                # L4 passthrough cannot prove the application's TLS behavior.
                if protocol not in ('HTTP', 'HTTPS', 'TLS', 'TCP', 'UDP', 'TCP_UDP'):
                    raise ValueError('transport_listener_protocol_unresolved')
                if (not _arn(identity, partition, 'elasticloadbalancing', account, region)
                        or listener.get('LoadBalancerArn') != arn):
                    raise ValueError('transport_listener_parent_join_invalid')
                policy = listener.get('SslPolicy', '')
                if not isinstance(policy, str) or protocol in ('HTTPS', 'TLS') and not policy:
                    raise ValueError('transport_listener_tls_policy_missing')
                append(identity, 'elbv2_listener', protocol, lb['Scheme'] == 'internet-facing', policy,
                       'DescribeLoadBalancers+DescribeListeners', source_resource_arn=arn)
        domains = requests.pages(session, 'apigateway', region, 'get_domain_names', 'items')
        if domains.status not in ('collected', 'empty'):
            return failure(domains)
        for domain in domains.items:
            name = domain.get('domainName') if isinstance(domain, dict) else None
            types = domain.get('endpointConfiguration', {}).get('types') if isinstance(domain, dict) else None
            if (not isinstance(name, str) or len(name) > 253 or not re.fullmatch(r'(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', name)
                    or not isinstance(types, list) or not types or len(types) != len(set(types))
                    or not set(types) <= {'EDGE', 'REGIONAL', 'PRIVATE'}):
                raise ValueError('transport_api_domain_identity_invalid')
            if 'PRIVATE' in types and len(types) != 1:
                raise ValueError('transport_api_domain_scope_ambiguous')
            policy = domain.get('securityPolicy')
            if not isinstance(policy, str) or not policy:
                raise ValueError('transport_api_domain_tls_policy_missing')
            identifier = name
            if types == ['PRIVATE']:
                private_id = domain.get('domainNameId')
                if not isinstance(private_id, str) or not re.fullmatch(r'[A-Za-z0-9]+', private_id):
                    raise ValueError('transport_private_domain_identity_unavailable')
                identifier += '+' + private_id
            identity = f'arn:{partition}:apigateway:{region}::/domainnames/{identifier}'
            append(identity, 'apigateway_domain', 'HTTPS', 'PRIVATE' not in types, policy,
                   'GetDomainNames', endpoint_types=types)
        distributions = _distributions(requests, session, region)
        if distributions.status not in ('collected', 'empty'):
            return failure(distributions)
        for distribution in distributions.items:
            identity, identifier = distribution.get('ARN'), distribution.get('Id')
            if (not isinstance(identifier, str) or not re.fullmatch(r'[A-Z0-9]{1,64}', identifier)
                    or identity != f'arn:{partition}:cloudfront::{account}:distribution/{identifier}'):
                raise ValueError('transport_cloudfront_identity_invalid')
            default = distribution.get('DefaultCacheBehavior')
            cached = distribution.get('CacheBehaviors')
            if not isinstance(default, dict) or not isinstance(cached, dict) or type(cached.get('Quantity')) is not int:
                raise ValueError('transport_cloudfront_behaviors_missing')
            items = cached.get('Items', [])
            if not isinstance(items, list) or len(items) != cached['Quantity'] or any(not isinstance(item, dict) for item in items):
                raise ValueError('transport_cloudfront_behaviors_incomplete')
            protocols = [behavior.get('ViewerProtocolPolicy') for behavior in [default] + items]
            if any(protocol not in ('allow-all', 'https-only', 'redirect-to-https') for protocol in protocols):
                raise ValueError('transport_cloudfront_viewer_policy_unresolved')
            certificate = distribution.get('ViewerCertificate')
            policy = certificate.get('MinimumProtocolVersion') if isinstance(certificate, dict) else None
            if not isinstance(policy, str) or not policy:
                raise ValueError('transport_cloudfront_tls_policy_missing')
            append(identity, 'cloudfront_distribution', 'HTTP' if 'allow-all' in protocols else 'HTTPS', True,
                   policy, 'ListDistributions', source_scope=account + '/global')
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        code = str(exc) if isinstance(exc, ValueError) and str(exc).startswith('transport_') else 'transport_native_response_malformed'
        return _result(rows, 'partial' if rows else 'malformed', code)
    return _result(rows)


FETCHERS = {'transport_endpoint': endpoints}
