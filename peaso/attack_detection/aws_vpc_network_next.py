"""Normalize accepted VPC network changes and correlate newly created DHCP options."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import ipaddress
import json
import re
from typing import Any


NAMES = {'CreateRoute', 'ReplaceRoute', 'ReplaceNetworkAclEntry',
         'ModifyVpcEndpoint', 'DeleteFlowLogs'}


def _valid(record: Mapping[str, Any], names: set[str]) -> bool:
    return (record.get('eventSource') == 'ec2.amazonaws.com'
            and record.get('eventName') in names
            and record.get('eventCategory') == 'Management'
            and record.get('eventType') == 'AwsApiCall'
            and record.get('managementEvent') is True
            and record.get('readOnly') is False
            and not record.get('errorCode') and not record.get('errorMessage')
            and isinstance(record.get('requestParameters'), Mapping)
            and isinstance(record.get('responseElements'), Mapping)
            and isinstance(record.get('recipientAccountId'), str)
            and re.fullmatch(r'\d{12}', record['recipientAccountId']) is not None
            and isinstance(record.get('awsRegion'), str))


def _id(value: Any, prefix: str) -> bool:
    return isinstance(value, str) and re.fullmatch(prefix + r'-[0-9a-f]{8,17}', value) is not None


def _specific_cidr(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        network = ipaddress.ip_network(value, strict=True)
        return isinstance(network, ipaddress.IPv4Network) and network.prefixlen >= 24
    except ValueError:
        return False


def _broad_policy(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        document = json.loads(value)
    except (ValueError, TypeError):
        return False
    statements = document.get('Statement') if isinstance(document, Mapping) else None
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get('Effect') != 'Allow':
            continue
        principals = statement.get('Principal')
        if principals != '*' and principals != {'AWS': '*'}:
            continue
        actions = statement.get('Action')
        resources = statement.get('Resource')
        if (actions == '*' or actions == 's3:*' or isinstance(actions, list) and ('*' in actions or 's3:*' in actions)) and (resources == '*' or isinstance(resources, list) and '*' in resources):
            return True
    return False


def normalize_aws_vpc_network(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if not _valid(record, NAMES):
        return None
    name = record['eventName']
    request, response = record['requestParameters'], record['responseElements']
    endpoint = request.get('ModifyVpcEndpointRequest')
    endpoint = endpoint if isinstance(endpoint, Mapping) else {}
    endpoint_response = response.get('ModifyVpcEndpointResponse')
    endpoint_response = endpoint_response if isinstance(endpoint_response, Mapping) else {}
    deletion = request.get('DeleteFlowLogsRequest')
    deletion = deletion if isinstance(deletion, Mapping) else {}
    flow_id = deletion.get('FlowLogId')
    flow_id = flow_id.get('content') if isinstance(flow_id, Mapping) else None
    deletion_response = response.get('DeleteFlowLogsResponse')
    deletion_response = deletion_response if isinstance(deletion_response, Mapping) else {}
    port = request.get('portRange')
    port = port if isinstance(port, Mapping) else {}
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'ec2.amazonaws.com',
        'event.name': name, 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': record['recipientAccountId'], 'actor.id': identity.get('arn'),
        'target.id': request.get('routeTableId') or request.get('networkAclId')
            or endpoint.get('VpcEndpointId') or flow_id,
        'request.vpc_specific_route_to_eni': bool(
            name in {'CreateRoute', 'ReplaceRoute'}
            and _id(request.get('routeTableId'), 'rtb')
            and _id(request.get('networkInterfaceId'), 'eni')
            and _specific_cidr(request.get('destinationCidrBlock'))
            and response.get('_return') is True),
        'request.vpc_nacl_public_ssh_allowed': bool(
            name == 'ReplaceNetworkAclEntry' and _id(request.get('networkAclId'), 'acl')
            and type(request.get('ruleNumber')) is int and request['ruleNumber'] > 0
            and request.get('egress') is False and request.get('ruleAction') == 'allow'
            and request.get('aclProtocol') in ('6', 'tcp')
            and request.get('cidrBlock') == '0.0.0.0/0'
            and type(port.get('from')) is int and type(port.get('to')) is int
            and port['from'] <= 22 <= port['to'] and response.get('_return') is True),
        'request.vpc_endpoint_policy_broad_allow': bool(
            name == 'ModifyVpcEndpoint' and _id(endpoint.get('VpcEndpointId'), 'vpce')
            and _broad_policy(endpoint.get('PolicyDocument'))
            and endpoint_response.get('return') is True),
        'request.vpc_flow_logs_deleted': bool(
            name == 'DeleteFlowLogs' and _id(flow_id, 'fl')
            and deletion_response.get('unsuccessful') == ''),
    }


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def _custom_resolvers(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return []
    items = value.get('items')
    if not isinstance(items, list):
        return []
    for item in items:
        if not isinstance(item, Mapping) or item.get('key') != 'domain-name-servers':
            continue
        valset = item.get('valueSet')
        values = valset.get('items') if isinstance(valset, Mapping) else None
        if not isinstance(values, list):
            continue
        resolvers = [x.get('value') for x in values if isinstance(x, Mapping)]
        if (resolvers and all(isinstance(x, str) and x != 'AmazonProvidedDNS'
                              and bool(x) for x in resolvers)):
            return resolvers
    return []


def correlate_aws_vpc_custom_dns(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    events = []
    for record in records:
        if not _valid(record, {'CreateDhcpOptions', 'AssociateDhcpOptions'}):
            continue
        when = _when(record.get('eventTime'))
        if when is not None:
            events.append((when, 0 if record['eventName'] == 'CreateDhcpOptions' else 1, record))
    events.sort(key=lambda x: x[:2])
    created: dict[tuple[str, str, str], tuple[datetime, Mapping[str, Any], list[str]]] = {}
    results = []
    for when, _, event in events:
        name, request, response = event['eventName'], event['requestParameters'], event['responseElements']
        scope = (event['recipientAccountId'], event['awsRegion'])
        if name == 'CreateDhcpOptions':
            options = response.get('dhcpOptions')
            if not isinstance(options, Mapping) or options.get('ownerId') != scope[0]:
                continue
            option_id = options.get('dhcpOptionsId')
            resolvers = _custom_resolvers(request.get('dhcpConfigurationSet'))
            if (_id(option_id, 'dopt') and resolvers
                    and _custom_resolvers(options.get('dhcpConfigurationSet')) == resolvers):
                created[(*scope, option_id)] = (when, event, resolvers)
            continue
        option_id, vpc_id = request.get('dhcpOptionsId'), request.get('vpcId')
        prior = created.get((*scope, option_id)) if isinstance(option_id, str) else None
        if (prior is None or not _id(vpc_id, 'vpc') or response.get('_return') is not True
                or when < prior[0] or when - prior[0] > timedelta(hours=24)):
            continue
        actor = event.get('userIdentity')
        actor = actor if isinstance(actor, Mapping) else {}
        results.append({
            'cloud.provider': 'aws', 'event.source': 'ec2.amazonaws.com',
            'event.name': 'AssociateDhcpOptions', 'event.outcome': 'success',
            'event.id': event.get('eventID'), 'event.time': event.get('eventTime'),
            'account.id': scope[0], 'actor.id': actor.get('arn'), 'target.id': vpc_id,
            'request.vpc_custom_dns_associated': True,
            'correlation_evidence': {'create_dhcp_event_id': prior[1].get('eventID'),
                                     'resolver_count': len(prior[2])},
        })
    return results
