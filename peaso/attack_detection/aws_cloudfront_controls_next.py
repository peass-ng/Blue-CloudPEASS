"""Extract CloudFront edge-code and signing-key configuration from audit events."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def normalize_aws_cloudfront_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get('eventSource') != 'cloudfront.amazonaws.com' or record.get('eventName') != 'UpdateDistribution':
        return None
    if (record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    request = record.get('requestParameters')
    account = record.get('recipientAccountId')
    if not isinstance(request, Mapping) or not isinstance(account, str) or len(account) != 12 or not account.isdigit():
        return None
    config = request.get('distributionConfig')
    if not isinstance(config, Mapping) or not isinstance(request.get('id'), str) or not request['id']:
        return None
    response = record.get('responseElements')
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or isinstance(response, Mapping) and (response.get('errorCode') or response.get('errorMessage')))
    behaviors = [config.get('defaultCacheBehavior')]
    cache = config.get('cacheBehaviors')
    if isinstance(cache, Mapping) and isinstance(cache.get('items'), list):
        behaviors.extend(cache['items'])
    origins = config.get('origins')
    origin_items = origins.get('items') if isinstance(origins, Mapping) else None
    origin_by_id = {item['id']: item for item in origin_items
                    if isinstance(item, Mapping) and isinstance(item.get('id'), str)} if isinstance(origin_items, list) else {}
    default = config.get('defaultCacheBehavior')
    default_origin = default.get('targetOriginId') if isinstance(default, Mapping) else None
    function_associated = False
    key_group_trusted = False
    alternate_full_viewer_route = False
    for behavior in behaviors:
        if not isinstance(behavior, Mapping):
            continue
        functions = behavior.get('functionAssociations')
        if isinstance(functions, Mapping) and isinstance(functions.get('items'), list):
            function_associated |= any(
                isinstance(item, Mapping) and item.get('eventType') in {'viewer-request', 'viewer-response', 'origin-request', 'origin-response'}
                and isinstance(item.get('functionARN'), str)
                and item['functionARN'].startswith(f'arn:aws:cloudfront::{account}:function/')
                for item in functions['items'])
        groups = behavior.get('trustedKeyGroups')
        if isinstance(groups, Mapping) and groups.get('enabled') is True and isinstance(groups.get('items'), list):
            key_group_trusted |= any(isinstance(item, str) and bool(item) for item in groups['items'])
        target = behavior.get('targetOriginId')
        origin = origin_by_id.get(target) if isinstance(target, str) else None
        methods = behavior.get('allowedMethods')
        allowed = methods.get('items') if isinstance(methods, Mapping) else None
        alternate_full_viewer_route |= (
            behavior is not default and isinstance(behavior.get('pathPattern'), str)
            and bool(behavior['pathPattern']) and isinstance(target, str) and target != default_origin
            and isinstance(origin, Mapping) and isinstance(origin.get('customOriginConfig'), Mapping)
            and isinstance(origin.get('domainName'), str) and bool(origin['domainName'])
            and behavior.get('originRequestPolicyId') == '216adef6-5c7f-47e4-b989-5492eafa07d3'
            and behavior.get('cachePolicyId') == '4135ea2d-6df8-44a3-9df3-4b5a84be39ad'
            and isinstance(allowed, list) and 'POST' in allowed
        )
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': record.get('eventName'), 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': identity.get('arn'), 'target.id': request.get('id'),
            'request.cloudfront_function_associated': function_associated and not failed,
            'request.cloudfront_trusted_key_group_present': key_group_trusted and not failed,
            'request.cloudfront_alternate_full_viewer_route': alternate_full_viewer_route and not failed}
