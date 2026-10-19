"""VPC network changes are matched against accepted, sanitized CloudTrail events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_vpc_network_lab_events.json').read_text())
FIELDS = {
    'request.vpc_specific_route_to_eni', 'request.vpc_nacl_public_ssh_allowed',
    'request.vpc_custom_dns_associated', 'request.vpc_endpoint_policy_broad_allow',
    'request.vpc_flow_logs_deleted',
}
RULES = tuple(Rule(id=f, title=f, description=f, level='medium', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)


def hits(events):
    return {hit.technique_id for hit in detect_aws_events(events, RULES)}


def event(name, predicate=lambda _: True):
    return copy.deepcopy(next(e for e in EVENTS if e['eventName'] == name and predicate(e)))


def test_real_network_changes_and_negative_controls():
    assert hits(EVENTS) == FIELDS
    for e in EVENTS:
        if not hits([e]):
            continue
        assert not hits([{**e, 'errorCode': 'UnauthorizedOperation'}])
        assert not hits([{**e, 'eventCategory': 'Data'}])
        assert not hits([{**e, 'readOnly': True}])

    # CloudTrail rounds both DHCP calls to the same second; input order is not reliable.
    create = event('CreateDhcpOptions')
    associate = event('AssociateDhcpOptions', lambda x: x['requestParameters']['dhcpOptionsId'] != 'default')
    assert hits([associate, create]) == {'request.vpc_custom_dns_associated'}
    assert not hits([associate])
    assert not hits([create, {**associate, 'errorCode': 'UnauthorizedOperation'}])
    assert not hits([create, {**associate, 'eventCategory': 'Data'}])
    assert not hits([create, {**associate, 'readOnly': True}])
    wrong = copy.deepcopy(associate)
    wrong['requestParameters']['dhcpOptionsId'] = 'dopt-00000000000000000'
    assert not hits([create, wrong])
    normal = copy.deepcopy(create)
    normal['requestParameters']['dhcpConfigurationSet']['items'][0]['valueSet']['items'][0]['value'] = 'AmazonProvidedDNS'
    normal['responseElements']['dhcpOptions']['dhcpConfigurationSet']['items'][0]['valueSet']['items'][0]['value'] = 'AmazonProvidedDNS'
    assert not hits([normal, associate])

    route = event('CreateRoute', lambda x: 'networkInterfaceId' in x['requestParameters'])
    route['requestParameters']['destinationCidrBlock'] = '10.0.0.0/16'
    assert not hits([route])
    assert not hits([event('CreateRoute', lambda x: 'gatewayId' in x['requestParameters'])])

    acl = event('ReplaceNetworkAclEntry')
    acl['requestParameters']['ruleAction'] = 'deny'
    assert not hits([acl])

    endpoint = event('ModifyVpcEndpoint')
    endpoint['requestParameters']['ModifyVpcEndpointRequest']['PolicyDocument'] = json.dumps({
        'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject',
                       'Resource': 'arn:aws:s3:::approved/*'}]})
    assert not hits([endpoint])

    flow = event('DeleteFlowLogs')
    flow['responseElements']['DeleteFlowLogsResponse']['unsuccessful'] = {'item': {'code': 'AccessDenied'}}
    assert not hits([flow])
