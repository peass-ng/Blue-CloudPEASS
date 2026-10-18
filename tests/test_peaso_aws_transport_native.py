"""Native transport declarations join their exact ELB, API Gateway and CDN scope."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT
from peaso.collectors import aws, aws_transport_native as native
from peaso.collectors.bulk_evidence import collect
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGION = 'eu-west-1'
SCOPE = ACCOUNT + '/' + REGION
LB = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/security/abcd'
LISTENER = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:listener/app/security/abcd/efgh'
CHECKS = ['aws.nist.sc_8_coverage', 'aws.nist.sc_8_1_coverage']
APPROVED = ['ELBSecurityPolicy-TLS13-1-2-2021-06', 'TLS_1_2', 'TLSv1.2_2021']


def distribution(identifier='E123ABC'):
    return {'Id': identifier, 'ARN': f'arn:aws:cloudfront::{ACCOUNT}:distribution/{identifier}',
        'Status': 'Deployed', 'LastModifiedTime': datetime(2026, 10, 14, tzinfo=timezone.utc),
        'DomainName': 'example.cloudfront.net', 'Aliases': {'Quantity': 0},
        'Origins': {'Quantity': 1, 'Items': [{'Id': 'origin', 'DomainName': 'origin.example.net',
            'CustomHeaders': {'Quantity': 1, 'Items': [{'HeaderName': 'X-Origin-Private', 'HeaderValue': 'never-export-this'}]}}]},
        'DefaultCacheBehavior': {'TargetOriginId': 'origin', 'ViewerProtocolPolicy': 'https-only'},
        'CacheBehaviors': {'Quantity': 0}, 'CustomErrorResponses': {'Quantity': 0},
        'Comment': 'private-unrelated-description', 'PriceClass': 'PriceClass_100', 'Enabled': True,
        'ViewerCertificate': {'ACMCertificateArn': f'arn:aws:acm:us-east-1:{ACCOUNT}:certificate/qa',
            'SSLSupportMethod': 'sni-only', 'MinimumProtocolVersion': 'TLSv1.2_2021'},
        'Restrictions': {'GeoRestriction': {'RestrictionType': 'none', 'Quantity': 0}},
        'WebACLId': '', 'HttpVersion': 'http2', 'IsIPV6Enabled': True, 'Staging': False}


def cf_page(items, **extra):
    return {'DistributionList': {'Marker': '', 'MaxItems': 100, 'Quantity': len(items),
        'IsTruncated': False, **({'Items': items} if items else {}), **extra}}


def decisions(read, *, policy=True, by_scope=False):
    snapshot = make_snapshot('aws', [SCOPE], [{'type': 'transport_endpoint', 'scope': SCOPE,
        'status': read.status, 'items': read.items}])
    module = SimpleNamespace(AWS_TYPES={'transport_endpoint'}, collect=lambda connector, requirements: snapshot)
    approved = {'status': 'collected', 'scope': SCOPE, 'approved_tls_policies': APPROVED}
    if by_scope: approved = {'by_scope': {SCOPE: approved}}
    snapshot = collect(module, {'provider': 'aws', 'options': {'compliance_policy': {'sw38_policy': approved}} if policy else {}},
                       ['transport_endpoint'])
    return [row['status'] for row in evaluate_snapshot(snapshot, checks=CHECKS)['findings']]


def setup_reads(sdk, mode):
    session, add = sdk
    elb, api, cf = add('elbv2'), add('apigateway'), add('cloudfront')
    if mode == 'elb_denied':
        elb.add_client_error('describe_load_balancers', 'AccessDenied', expected_params={})
        return session, (elb, api, cf)
    elb.add_response('describe_load_balancers', {'LoadBalancers': [] if mode == 'empty' else [{
        'LoadBalancerArn': LB, 'Scheme': 'internal' if mode == 'internal_only' else 'internet-facing', 'Type': 'application'}]}, {})
    if mode != 'empty':
        if mode == 'listener_denied':
            elb.add_client_error('describe_listeners', 'AccessDenied', expected_params={'LoadBalancerArn': LB})
            return session, (elb, api, cf)
        listener = {'ListenerArn': LISTENER, 'LoadBalancerArn': LB, 'Protocol': 'HTTP' if mode == 'http' else 'TCP' if mode == 'tcp' else 'HTTPS',
                    'Port': 443, 'SslPolicy': APPROVED[0]}
        if mode == 'foreign_listener': listener['LoadBalancerArn'] = LB.replace(ACCOUNT, '999999999999')
        elb.add_response('describe_listeners', {'Listeners': [listener]}, {'LoadBalancerArn': LB})
        if mode in ('tcp', 'foreign_listener'):
            return session, (elb, api, cf)
    if mode == 'domain_denied':
        api.add_client_error('get_domain_names', 'AccessDeniedException', expected_params={})
        return session, (elb, api, cf)
    domains = [] if mode in ('empty', 'internal_only') else [{'domainName': 'api.example.net',
        'securityPolicy': 'TLS_1_0' if mode == 'weak_domain' else 'TLS_1_2', 'endpointConfiguration': {'types': ['REGIONAL']}}]
    api.add_response('get_domain_names', {'items': domains}, {})
    if mode == 'cf_denied':
        cf.add_client_error('list_distributions', 'AccessDenied', expected_params={})
    else:
        item = distribution()
        if mode == 'cf_http': item['DefaultCacheBehavior']['ViewerProtocolPolicy'] = 'allow-all'
        if mode == 'cf_cache_http':
            item['CacheBehaviors'] = {'Quantity': 1, 'Items': [{'PathPattern': '/public/*', 'TargetOriginId': 'origin', 'ViewerProtocolPolicy': 'allow-all'}]}
        if mode == 'foreign_cf': item['ARN'] = item['ARN'].replace(ACCOUNT, '999999999999')
        if mode == 'cf_missing_policy': item['ViewerCertificate'].pop('MinimumProtocolVersion')
        cf.add_response('list_distributions', cf_page([] if mode in ('empty', 'internal_only') else [item]), {})
    return session, (elb, api, cf)


@pytest.mark.parametrize('mode', ['complete', 'empty', 'internal_only', 'http', 'weak_domain', 'cf_http', 'cf_cache_http',
    'elb_denied', 'listener_denied', 'domain_denied', 'cf_denied', 'tcp', 'foreign_listener', 'foreign_cf', 'cf_missing_policy'])
def test_native_endpoint_joins_and_actual_published_decisions(sdk, mode):
    session, stubs = setup_reads(sdk, mode)
    read = native.endpoints(aws.Requests({'retry_attempts': 1}), session, REGION, ACCOUNT)
    if mode in ('complete', 'empty', 'internal_only', 'http', 'weak_domain', 'cf_http', 'cf_cache_http'):
        assert read.status in ('collected', 'empty')
        expected = 'PASS' if mode == 'complete' else 'NOT_APPLICABLE' if mode in ('empty', 'internal_only') else 'FAIL'
        assert decisions(read) == [expected, expected]
        assert decisions(read, by_scope=True) == [expected, expected]
        assert decisions(read, policy=False) == ['UNKNOWN', 'UNKNOWN']
        serialized = json.dumps(read.items)
        assert 'never-export-this' not in serialized and 'private-unrelated-description' not in serialized
    else:
        assert read.status not in ('collected', 'empty')
        assert not any(value in ('PASS', 'NOT_APPLICABLE') for value in decisions(read))
    for stub in stubs: stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['complete', 'page_limit', 'repeated_cursor', 'second_page_denied'])
def test_cloudfront_pagination_is_bounded_and_verified_on_every_page(sdk, mode):
    session, add = sdk
    cf = add('cloudfront')
    cf.add_response('list_distributions', cf_page([distribution()], IsTruncated=True, NextMarker='next'), {})
    if mode == 'complete':
        cf.add_response('list_distributions', cf_page([]), {'Marker': 'next'})
    elif mode == 'repeated_cursor':
        cf.add_response('list_distributions', cf_page([], IsTruncated=True, NextMarker='next'), {'Marker': 'next'})
    elif mode == 'second_page_denied':
        cf.add_client_error('list_distributions', 'AccessDenied', expected_params={'Marker': 'next'})
    read = native._distributions(aws.Requests({'retry_attempts': 1, **({'max_pages': 1} if mode == 'page_limit' else {})}),
                                  session, REGION)
    assert (read.status == 'collected') is (mode == 'complete')
    cf.assert_no_pending_responses()


def test_full_native_transport_collector_to_scope_policy_decisions(sdk, monkeypatch):
    session, _ = setup_reads(sdk, 'complete')
    _, add = sdk
    sts = add('sts')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'test-pinned'))
    snapshot = collect(aws, {'provider': 'aws', 'scopes': [SCOPE], 'options': {'service_concurrency': 1,
        'compliance_policy': {'sw38_policy': {'status': 'collected', 'scope': SCOPE, 'approved_tls_policies': APPROVED}}}},
        ['transport_endpoint'])
    assert [row['status'] for row in evaluate_snapshot(snapshot, checks=CHECKS)['findings']] == ['PASS', 'PASS']
    assert snapshot['metadata']['calls'] == 5


@pytest.mark.parametrize('response', [{}, {'DistributionList': {'Marker': '', 'MaxItems': 100,
    'Quantity': 1, 'IsTruncated': False}}, {'DistributionList': {'Marker': '', 'MaxItems': 100,
    'Quantity': 0, 'IsTruncated': False, 'NextMarker': 'unhandled'}}])
def test_missing_or_inconsistent_distribution_pages_do_not_prove_absence(sdk, response):
    session, add = sdk
    cf = add('cloudfront')
    cf.add_response('list_distributions', response, {})
    read = native._distributions(aws.Requests({}), session, REGION)
    assert read.status not in ('collected', 'empty')
    cf.assert_no_pending_responses()


def test_private_api_domains_are_not_mislabeled_public(sdk):
    session, add = sdk
    elb, api, cf = add('elbv2'), add('apigateway'), add('cloudfront')
    elb.add_response('describe_load_balancers', {'LoadBalancers': []}, {})
    api.add_response('get_domain_names', {'items': [{'domainName': 'internal.example.net', 'domainNameId': 'abc123',
        'securityPolicy': 'TLS_1_2', 'endpointConfiguration': {'types': ['PRIVATE']}}]}, {})
    cf.add_response('list_distributions', cf_page([]), {})
    read = native.endpoints(aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == 'collected'
    assert read.items[0]['External'] is False
    assert read.items[0]['id'].endswith('/domainnames/internal.example.net+abc123')
    assert decisions(read) == ['NOT_APPLICABLE', 'NOT_APPLICABLE']
    for stub in (elb, api, cf): stub.assert_no_pending_responses()
