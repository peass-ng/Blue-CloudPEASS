"""Project Bedrock execution-role metadata before request-cache insertion."""
from __future__ import annotations

from copy import deepcopy
import re

PROFILE = 'bedrock-security-role-metadata-v1'
ACCOUNT_PROFILE = 'bedrock-agent-role-account-v1'
KIND = 'bedrock_agent_account_inventory'
SPECS = {KIND: ('bedrock-agent', 'list_agents', 'agentSummaries')}
GLOBAL_TYPES = {KIND}
NATIVE_IDS = {KIND: 'AccountId'}
PROJECTION_OPERATIONS = frozenset({('bedrock-agent', name) for name in
    ('list_agents', 'get_agent', 'list_agent_aliases', 'get_agent_alias', 'get_agent_version')})
READ_ACTIONS = set(PROJECTION_OPERATIONS) | {('ec2', 'describe_regions')}
OK = {'collected', 'empty'}
ID = re.compile(r'[A-Za-z0-9]{10}')
REGION = re.compile(r'[a-z]{2}(?:-[a-z]+)+-[0-9]')


def _pick(value, keys):
    return {key: deepcopy(value[key]) for key in keys if key in value}


def project_response(response, service, operation, arguments):
    """Retain role ARNs/IDs only; instructions and prompts never reach cache."""
    from .aws import ReadFailure
    from .aws_bedrock_reasoning_native import _output_shape
    from botocore.validate import validate_parameters
    from botocore.exceptions import ParamValidationError
    if (service, operation) not in PROJECTION_OPERATIONS or not isinstance(response, dict):
        raise ReadFailure('malformed', 'bedrock_security_operation_invalid')
    try:
        validate_parameters({key: value for key, value in response.items() if key != 'ResponseMetadata'},
                            _output_shape(service, operation))
    except ParamValidationError:
        raise ReadFailure('malformed', 'bedrock_security_metadata_invalid') from None
    out = {'_metadata_projection': PROFILE}
    if operation in {'list_agents', 'list_agent_aliases'}:
        field = 'agentSummaries' if operation == 'list_agents' else 'agentAliasSummaries'
        keys = ('agentId', 'agentName', 'agentStatus', 'latestAgentVersion', 'updatedAt', 'guardrailConfiguration') if operation == 'list_agents' else ('agentAliasId', 'agentAliasStatus')
        out[field] = [_pick(row, keys) for row in response[field]]
        if 'nextToken' in response:
            out['nextToken'] = response['nextToken']
        return out
    if operation in {'get_agent', 'get_agent_version'}:
        field = 'agent' if operation == 'get_agent' else 'agentVersion'
        row = response[field]
        if row['agentId'] != arguments.get('agentId'):
            raise ReadFailure('malformed', 'bedrock_security_agent_identity_mismatch')
        version_field = 'agentVersion' if operation == 'get_agent' else 'version'
        if operation == 'get_agent_version' and row[version_field] != arguments.get('agentVersion'):
            raise ReadFailure('malformed', 'bedrock_security_version_identity_mismatch')
        out[field] = _pick(row, ('agentId', 'agentArn', version_field, 'agentResourceRoleArn'))
        return out
    row = response['agentAlias']
    if row['agentId'] != arguments.get('agentId') or row['agentAliasId'] != arguments.get('agentAliasId'):
        raise ReadFailure('malformed', 'bedrock_security_alias_identity_mismatch')
    out['agentAlias'] = _pick(row, ('agentId', 'agentAliasId', 'agentAliasStatus'))
    out['agentAlias']['routingConfiguration'] = [_pick(route, ('agentVersion',)) for route in row.get('routingConfiguration', [])]
    return out


def agent_metadata(requests, session, region, item):
    """Keep the existing summary shape and append explicitly covered draft data."""
    out = deepcopy(item)
    identifier = item.get('agentId')
    if not isinstance(identifier, str) or ID.fullmatch(identifier) is None:
        out['AgentRoleMetadata'] = {'collection_status': 'malformed'}
        return out
    detail = requests.detail(session, 'bedrock-agent', region, 'get_agent',
                             agentId=identifier, _metadata_profile=PROFILE)
    if detail.get('collection_status') == 'collected' and isinstance(detail.get('agent'), dict):
        out['AgentRoleMetadata'] = {**detail['agent'], 'collection_status': 'collected'}
    else:
        out['AgentRoleMetadata'] = _pick(detail, ('collection_status', 'error', 'absent'))
    return out


def deployed_roles(requests, session, region, identifier):
    aliases = requests.pages(session, 'bedrock-agent', region, 'list_agent_aliases', 'agentAliasSummaries',
                             agentId=identifier, _metadata_profile=PROFILE)
    failures = []
    if aliases.status not in OK:
        failures.append(aliases.error or {'code': 'bedrock_alias_inventory_incomplete'})
    versions = set()
    seen = set()
    for alias in aliases.items:
        aid = alias.get('agentAliasId') if isinstance(alias, dict) else None
        if not isinstance(aid, str) or ID.fullmatch(aid) is None or aid in seen:
            failures.append({'code': 'bedrock_alias_identity_invalid'})
            continue
        seen.add(aid)
        detail = requests.detail(session, 'bedrock-agent', region, 'get_agent_alias',
                                 agentId=identifier, agentAliasId=aid, _metadata_profile=PROFILE)
        if detail.get('collection_status') != 'collected':
            failures.append(detail.get('error', {'code': 'bedrock_alias_detail_incomplete'}))
            continue
        routes = detail.get('agentAlias', {}).get('routingConfiguration')
        if not isinstance(routes, list):
            failures.append({'code': 'bedrock_alias_routes_malformed'})
            continue
        for route in routes:
            version = route.get('agentVersion') if isinstance(route, dict) else None
            if version == 'DRAFT':
                continue
            if not isinstance(version, str) or re.fullmatch(r'[1-9][0-9]{0,4}', version) is None:
                failures.append({'code': 'bedrock_alias_version_malformed'})
                continue
            versions.add(version)
    rows = []
    for version in sorted(versions):
        detail = requests.detail(session, 'bedrock-agent', region, 'get_agent_version',
                                 agentId=identifier, agentVersion=version, _metadata_profile=PROFILE)
        data = detail.get('agentVersion')
        if detail.get('collection_status') != 'collected' or not isinstance(data, dict):
            failures.append(detail.get('error', {'code': 'bedrock_version_detail_incomplete'}))
            continue
        if not isinstance(data.get('agentResourceRoleArn'), str):
            failures.append({'code': 'bedrock_version_role_missing'})
            continue
        rows.append({'agentVersion': version, 'agentResourceRoleArn': data['agentResourceRoleArn']})
    out = {'collection_status': 'partial' if failures else 'collected' if rows else 'empty', 'items': rows}
    if failures:
        out['error'] = failures[0]
    return out


def account_inventory(requests, session, region, account):
    """Discover enabled Regions and preserve a status for every attempted read."""
    from .aws import ReadResult
    discovered = requests.pages(session, 'ec2', region, 'describe_regions', 'Regions', AllRegions=False)
    proof = {'AccountId': account, 'profile': ACCOUNT_PROFILE,
             'EnabledRegions': {'collection_status': discovered.status, 'items': []}, 'RegionAgents': []}
    if discovered.error:
        proof['EnabledRegions']['error'] = discovered.error
    regions = []
    invalid = False
    for entry in discovered.items:
        name = entry.get('RegionName') if isinstance(entry, dict) else None
        if not isinstance(name, str) or REGION.fullmatch(name) is None or name in regions:
            invalid = True
            continue
        regions.append(name)
    if invalid or not regions:
        proof['EnabledRegions']['collection_status'] = 'malformed'
    proof['EnabledRegions']['items'] = [{'RegionName': name} for name in regions]
    complete = discovered.status == 'collected' and bool(regions) and not invalid
    for name in regions:
        agents = requests.pages(session, 'bedrock-agent', name, 'list_agents', 'agentSummaries', _metadata_profile=PROFILE)
        observation = {'Region': name, 'Agents': {'collection_status': agents.status, 'items': []}}
        if agents.error:
            observation['Agents']['error'] = agents.error
        complete = complete and agents.status in OK
        seen = set()
        for item in agents.items:
            identifier = item.get('agentId') if isinstance(item, dict) else None
            if not isinstance(identifier, str) or ID.fullmatch(identifier) is None or identifier in seen:
                complete = False
                observation['Agents']['collection_status'] = 'malformed'
                continue
            seen.add(identifier)
            enriched = agent_metadata(requests, session, name, item)
            enriched['DeployedRoleVersions'] = deployed_roles(requests, session, name, identifier)
            observation['Agents']['items'].append(enriched)
            complete = complete and enriched['AgentRoleMetadata'].get('collection_status') == 'collected' and enriched['DeployedRoleVersions']['collection_status'] in OK
        proof['RegionAgents'].append(observation)
    return ReadResult([proof], 'collected' if complete else 'partial', None if complete else {'code': 'bedrock_account_role_inventory_incomplete'})


FETCHERS = {KIND: account_inventory}
