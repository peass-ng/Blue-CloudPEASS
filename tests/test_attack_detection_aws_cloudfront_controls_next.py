"""Distribution config review reports configured edge code and trusted signers."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = '222233334444'
RULES = (
    Rule(id='function', title='function', description='function', level='medium', product='aws',
         technique_id='aws-cloudfront-edge-function-association', selection={
             'event.source': 'cloudfront.amazonaws.com', 'event.name': 'UpdateDistribution',
             'event.outcome': 'success', 'request.cloudfront_function_associated': True}),
    Rule(id='keys', title='keys', description='keys', level='medium', product='aws',
         technique_id='aws-cloudfront-trusted-key-group-hijack', selection={
             'event.source': 'cloudfront.amazonaws.com', 'event.name': 'UpdateDistribution',
             'event.outcome': 'success', 'request.cloudfront_trusted_key_group_present': True}),
    Rule(id='route', title='route', description='route', level='high', product='aws',
         technique_id='aws-cloudfront-alternate-origin-full-viewer-route', selection={
             'event.source': 'cloudfront.amazonaws.com', 'event.name': 'UpdateDistribution',
             'event.outcome': 'success', 'request.cloudfront_alternate_full_viewer_route': True}),
)


def event():
    return {'eventSource': 'cloudfront.amazonaws.com', 'eventName': 'UpdateDistribution',
            'eventCategory': 'Management', 'eventType': 'AwsApiCall',
            'managementEvent': True, 'readOnly': False,
            'recipientAccountId': ACCOUNT,
            'requestParameters': {'id': 'EDIS0001', 'distributionConfig': {
                'defaultCacheBehavior': {'functionAssociations': {'quantity': 1, 'items': [{
                    'eventType': 'viewer-request',
                    'functionARN': f'arn:aws:cloudfront::{ACCOUNT}:function/lab'}]},
                    'trustedKeyGroups': {'enabled': True, 'quantity': 1, 'items': ['KG123']}}}}}


def hits(item):
    return {x.technique_id for x in detect_aws_events([item], RULES)}


def test_present_associations_only_with_successful_management_update():
    item = event()
    assert hits(item) == {'aws-cloudfront-edge-function-association',
                          'aws-cloudfront-trusted-key-group-hijack'}
    assert hits({**item, 'errorCode': 'AccessDenied'}) == set()
    assert hits({**item, 'readOnly': True}) == set()
    assert hits({**item, 'eventName': 'CreateDistribution'}) == set()
    no_function = deepcopy(item)
    no_function['requestParameters']['distributionConfig']['defaultCacheBehavior']['functionAssociations'] = {'quantity': 0}
    assert hits(no_function) == {'aws-cloudfront-trusted-key-group-hijack'}
    no_keys = deepcopy(item)
    no_keys['requestParameters']['distributionConfig']['defaultCacheBehavior']['trustedKeyGroups'] = {'enabled': False, 'quantity': 0}
    assert hits(no_keys) == {'aws-cloudfront-edge-function-association'}
    other_account = deepcopy(item)
    other_account['requestParameters']['distributionConfig']['defaultCacheBehavior']['functionAssociations']['items'][0]['functionARN'] = 'arn:aws:cloudfront::111111111111:function/lab'
    assert hits(other_account) == {'aws-cloudfront-trusted-key-group-hijack'}


def test_alternate_origin_full_viewer_post_route_requires_all_parts():
    item = event()
    config = item['requestParameters']['distributionConfig']
    config['origins'] = {'quantity': 2, 'items': [
        {'id': 'base', 'domainName': 'example.org', 'customOriginConfig': {}},
        {'id': 'canary', 'domainName': 'canary.invalid', 'customOriginConfig': {}}]}
    config['defaultCacheBehavior']['targetOriginId'] = 'base'
    config['cacheBehaviors'] = {'quantity': 1, 'items': [{
        'pathPattern': '/canary*', 'targetOriginId': 'canary',
        'originRequestPolicyId': '216adef6-5c7f-47e4-b989-5492eafa07d3',
        'cachePolicyId': '4135ea2d-6df8-44a3-9df3-4b5a84be39ad',
        'allowedMethods': {'quantity': 7, 'items': ['GET', 'HEAD', 'OPTIONS', 'PUT', 'POST', 'PATCH', 'DELETE']}}]}
    full = hits(item)
    assert 'aws-cloudfront-alternate-origin-full-viewer-route' in full
    for key, value in [('originRequestPolicyId', 'other-policy'),
                       ('cachePolicyId', 'other-policy'), ('targetOriginId', 'base')]:
        copy = deepcopy(item)
        copy['requestParameters']['distributionConfig']['cacheBehaviors']['items'][0][key] = value
        assert 'aws-cloudfront-alternate-origin-full-viewer-route' not in hits(copy)
    no_post = deepcopy(item)
    no_post['requestParameters']['distributionConfig']['cacheBehaviors']['items'][0]['allowedMethods']['items'].remove('POST')
    assert 'aws-cloudfront-alternate-origin-full-viewer-route' not in hits(no_post)
