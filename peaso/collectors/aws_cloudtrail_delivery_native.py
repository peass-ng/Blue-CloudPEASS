"""Native CloudTrail delivery-role simulation; never sends events or assumes roles.

The simulation is for the documented base log stream in one account/Region.
It is not evidence of event receipt, future numbered streams, SCPs or RCPs.
"""
import copy
import json
import re
from urllib.parse import unquote

ACTIONS = ['logs:CreateLogStream', 'logs:PutLogEvents']
SPECS = {
    'cloudtrail_trail': ('cloudtrail', 'describe_trails', 'trailList'),
    'cloudtrail_delivery_permission': ('cloudtrail', 'describe_trails', 'trailList'),
}
READ_ACTIONS = {('iam', 'get_role'), ('iam', 'get_context_keys_for_principal_policy'),
                ('iam', 'simulate_principal_policy'), ('cloudtrail', 'get_trail_status'),
                ('cloudtrail', 'get_event_selectors')}
NATIVE_IDS = {'cloudtrail_trail': 'TrailARN', 'cloudtrail_delivery_permission': 'role_arn'}
_REGION = r'[a-z]{2}(?:-[a-z]+)+-[0-9]+'
_ROLE = re.compile(r'arn:(aws):iam::([0-9]{12}):role/([A-Za-z0-9_+=,.@/-]+)')
_GROUP = re.compile(r'arn:(aws):logs:(' + _REGION + r'):([0-9]{12}):log-group:([A-Za-z0-9_./#-]{1,512})(?::\*)?')
_TRAIL = re.compile(r'arn:(aws):cloudtrail:(' + _REGION + r'):([0-9]{12}):trail/([A-Za-z0-9_.-]+)')


def validate_simulation_query(arguments):
    """The single read-only simulation exception cannot accept policy overrides."""
    if not isinstance(arguments, dict) or not set(arguments) <= {'PolicySourceArn', 'ActionNames', 'ResourceArns', 'ContextEntries', 'Marker'}:
        return False
    if not isinstance(arguments.get('PolicySourceArn'), str):
        return False
    role = _ROLE.fullmatch(arguments.get('PolicySourceArn', ''))
    resources = arguments.get('ResourceArns')
    if role is None or arguments.get('ActionNames') != ACTIONS or not isinstance(resources, list) or len(resources) != 1 or not isinstance(resources[0], str):
        return False
    stream = re.fullmatch(r'arn:aws:logs:(' + _REGION + r'):([0-9]{12}):log-group:[A-Za-z0-9_./#-]{1,512}:log-stream:([0-9]{12})_CloudTrail_(' + _REGION + r')', resources[0])
    if stream is None or stream.group(2) != stream.group(3) or stream.group(2) != role.group(2) or stream.group(1) != stream.group(4):
        return False
    if 'ContextEntries' in arguments and arguments['ContextEntries'] != [{'ContextKeyName': 'aws:RequestedRegion', 'ContextKeyValues': [stream.group(1)], 'ContextKeyType': 'string'}]:
        return False
    marker = arguments.get('Marker')
    return marker is None or isinstance(marker, str) and 0 < len(marker) <= 1000 and all(32 <= ord(c) <= 255 for c in marker)


def _detail(requests, session, service, region, operation, **arguments):
    from .aws import ReadFailure
    value = requests.detail(session, service, region, operation, **arguments)
    if not isinstance(value, dict) or value.get('collection_status') != 'collected':
        raise ReadFailure(value.get('collection_status', 'malformed') if isinstance(value, dict) else 'malformed',
                          (value.get('error') or {}).get('code', 'cloudtrail_delivery_detail_unavailable') if isinstance(value, dict) else 'cloudtrail_delivery_detail_unavailable')
    return value


def _read(requests, session, service, region, operation, expression, **arguments):
    from .aws import ReadFailure
    read = requests.pages(session, service, region, operation, expression, **arguments)
    if read.status not in {'collected', 'empty'}:
        raise ReadFailure((read.error or {}).get('cause_status', read.status), (read.error or {}).get('code', 'cloudtrail_delivery_list_incomplete'))
    if any(not isinstance(row, dict) for row in read.items):
        raise ValueError('malformed_native_rows')
    return read.items


def _result(items=(), status=None, code=None):
    from .aws import ReadResult
    rows = list(items)
    return ReadResult(rows, status or ('collected' if rows else 'empty'), {'code': code} if code else None)


def trails(requests, session, region, account):
    from .aws import ReadFailure
    try:
        rows = _read(requests, session, 'cloudtrail', region, 'describe_trails', 'trailList', includeShadowTrails=False)
        output, seen = [], set()
        for native in rows:
            arn = native.get('TrailARN');match = _TRAIL.fullmatch(arn or '')
            if match is None or match.group(2) != region or match.group(3) != account or native.get('HomeRegion') != region or arn in seen:
                raise ValueError('foreign_or_duplicate_home_trail')
            seen.add(arn)
            status = _detail(requests, session, 'cloudtrail', region, 'get_trail_status', Name=arn)
            if type(status.get('IsLogging')) is not bool:
                raise ValueError('cloudtrail_logging_state_missing')
            selectors = _detail(requests, session, 'cloudtrail', region, 'get_event_selectors', TrailName=arn)
            item = {key: copy.deepcopy(native[key]) for key in ('Name', 'TrailARN', 'HomeRegion', 'IsMultiRegionTrail', 'IsOrganizationTrail', 'KmsKeyId') if key in native}
            item.update({key: native.get(key, '') for key in ('CloudWatchLogsLogGroupArn', 'CloudWatchLogsRoleArn')})
            if any(not isinstance(item[key], str) for key in ('CloudWatchLogsLogGroupArn', 'CloudWatchLogsRoleArn')):
                raise ValueError('cloudtrail_destination_malformed')
            item['Status'] = {'collection_status': 'collected', 'IsLogging': status['IsLogging']}
            item['EventSelectors'] = {'collection_status': 'collected', **{key: copy.deepcopy(selectors[key]) for key in ('EventSelectors', 'AdvancedEventSelectors') if key in selectors}}
            item['_provenance'] = {'operations': ['DescribeTrails', 'GetTrailStatus', 'GetEventSelectors'], 'read_only': True, 'home_region_only': True}
            output.append(item)
        return _result(output)
    except ReadFailure as exc:
        return _result([], exc.status, exc.code)
    except (ValueError, TypeError, KeyError):
        return _result([], 'malformed', 'cloudtrail_native_trail_invalid')


def _strings(value):
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(not isinstance(x, str) or not x for x in values):
        raise ValueError('trust_policy_string_list_invalid')
    return values


def _wildcard(pattern, value):
    # IAM patterns use only * and ?. Shell bracket classes are not IAM syntax.
    return re.fullmatch(re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.'), value) is not None


def trust_valid(document, trail_arn, account):
    """Evaluate only CloudTrail AssumeRole statements and native source bindings."""
    if isinstance(document, str):
        if len(document) > 131072:
            raise ValueError('trust_policy_too_large')
        document = json.loads(unquote(document))
    if not isinstance(document, dict) or set(document) - {'Version', 'Statement', 'Id'}:
        raise ValueError('unsupported_trust_policy')
    statements = document.get('Statement')
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or not statements:
        raise ValueError('missing_trust_statements')
    allowed = denied = False
    for statement in statements:
        if not isinstance(statement, dict) or set(statement) - {'Sid', 'Effect', 'Principal', 'Action', 'Condition'}:
            raise ValueError('unsupported_trust_statement')
        effect = statement.get('Effect')
        if effect not in {'Allow', 'Deny'}:
            raise ValueError('invalid_trust_effect')
        actions = _strings(statement.get('Action'))
        if any(x not in {'sts:AssumeRole'} for x in actions):
            raise ValueError('unsupported_trust_action')
        principal = statement.get('Principal')
        if not isinstance(principal, dict) or set(principal) not in ({'Service'}, {'AWS'}):
            raise ValueError('unsupported_trust_principal')
        principals = _strings(next(iter(principal.values())))
        if 'Service' not in principal or 'cloudtrail.amazonaws.com' not in principals:
            if any('*' in x or '?' in x for x in principals):
                raise ValueError('unsupported_trust_principal_wildcard')
            continue
        conditions = statement.get('Condition', {})
        if not isinstance(conditions, dict):
            raise ValueError('malformed_trust_condition')
        matches = True
        for comparator, block in conditions.items():
            if comparator not in {'ArnEquals', 'ArnLike', 'StringEquals', 'StringLike'} or not isinstance(block, dict) or not block:
                raise ValueError('unsupported_trust_condition')
            for key, wanted in block.items():
                lowered = key.lower()
                actual = {'aws:sourcearn': trail_arn, 'aws:sourceaccount': account}.get(lowered)
                if actual is None:
                    raise ValueError('unresolved_trust_context')
                values = _strings(wanted)
                if any('${' in value for value in values):
                    raise ValueError('unresolved_trust_policy_variable')
                if lowered == 'aws:sourceaccount' and any(not re.fullmatch(r'[0-9]{12}', x) for x in values):
                    raise ValueError('unsupported_source_account_condition')
                matching = any(_wildcard(x, actual) if comparator.endswith('Like') else x == actual for x in values)
                matches = matches and matching
        if matches:
            allowed = allowed or effect == 'Allow'
            denied = denied or effect == 'Deny'
    return allowed and not denied


def permissions(requests, session, region, account):
    from .aws import ReadFailure
    parent = trails(requests, session, region, account)
    if parent.status not in {'collected', 'empty'}:
        return parent
    pairs = {}
    for trail in parent.items:
        role, group = trail['CloudWatchLogsRoleArn'], trail['CloudWatchLogsLogGroupArn']
        if not trail['Status']['IsLogging'] or not role or not group:
            continue
        pairs.setdefault((role, group), []).append(trail)
    output = []
    try:
        for (role, group), subjects in pairs.items():
            row = {'role_arn': role, 'log_group_arn': group, 'simulation_context_complete': False}
            trail = subjects[0]
            try:
                if len(subjects) != 1:
                    raise ValueError('ambiguous_shared_delivery_pair')
                if type(trail.get('IsOrganizationTrail')) is not bool or type(trail.get('IsMultiRegionTrail')) is not bool or trail['IsOrganizationTrail'] or trail['IsMultiRegionTrail']:
                    raise ValueError('organization_or_multiregion_stream_scope_unresolved')
                rm, gm = _ROLE.fullmatch(role), _GROUP.fullmatch(group)
                if rm is None or gm is None or rm.group(2) != account or gm.group(2) != region or gm.group(3) != account:
                    raise ValueError('foreign_or_invalid_delivery_destination')
                native_role = _detail(requests, session, 'iam', region, 'get_role', RoleName=rm.group(3).rsplit('/', 1)[-1]).get('Role')
                if not isinstance(native_role, dict) or native_role.get('Arn') != role or native_role.get('RoleName') != rm.group(3).rsplit('/', 1)[-1]:
                    raise ValueError('delivery_role_identity_mismatch')
                valid_trust = trust_valid(native_role.get('AssumeRolePolicyDocument'), trail['TrailARN'], account)
                keys = _detail(requests, session, 'iam', region, 'get_context_keys_for_principal_policy', PolicySourceArn=role).get('ContextKeyNames')
                if not isinstance(keys, list) or len(keys) != len(set(keys)) or any(not isinstance(x, str) for x in keys):
                    raise ValueError('simulation_context_keys_missing')
                if any(key.lower() != 'aws:requestedregion' for key in keys) or len(keys) > 1:
                    raise ValueError('unresolved_identity_policy_context')
                stream = f'arn:aws:logs:{region}:{account}:log-group:{gm.group(4)}:log-stream:{account}_CloudTrail_{region}'
                arguments = {'PolicySourceArn': role, 'ActionNames': ACTIONS, 'ResourceArns': [stream]}
                if keys:
                    arguments['ContextEntries'] = [{'ContextKeyName': 'aws:RequestedRegion', 'ContextKeyValues': [region], 'ContextKeyType': 'string'}]
                results = _read(requests, session, 'iam', region, 'simulate_principal_policy', 'EvaluationResults', **arguments)
                decisions = {}
                for result in results:
                    action = result.get('EvalActionName');decision = result.get('EvalDecision')
                    if action not in ACTIONS or action in decisions or result.get('EvalResourceName') != stream or decision not in {'allowed', 'explicitDeny', 'implicitDeny'}:
                        raise ValueError('simulation_result_binding_invalid')
                    if result.get('MissingContextValues') != []:
                        raise ValueError('simulation_missing_context')
                    detail = result.get('PermissionsBoundaryDecisionDetail')
                    if native_role.get('PermissionsBoundary') is not None and (not isinstance(detail, dict) or type(detail.get('AllowedByPermissionsBoundary')) is not bool):
                        raise ValueError('simulation_boundary_context_incomplete')
                    if isinstance(detail, dict) and detail.get('AllowedByPermissionsBoundary') is False and decision == 'allowed':
                        raise ValueError('simulation_boundary_decision_conflict')
                    organization = result.get('OrganizationsDecisionDetail')
                    if isinstance(organization, dict) and organization.get('AllowedByOrganizations') is False and decision == 'allowed':
                        raise ValueError('simulation_organization_decision_conflict')
                    for specific in result.get('ResourceSpecificResults', []):
                        if not isinstance(specific, dict) or specific.get('EvalResourceName') != stream or specific.get('MissingContextValues', []) != [] or specific.get('EvalResourceDecision') != decision:
                            raise ValueError('simulation_resource_context_invalid')
                    decisions[action] = decision
                if set(decisions) != set(ACTIONS):
                    raise ValueError('simulation_actions_incomplete')
                row.update(simulation_context_complete=True, trust_valid=valid_trust, decisions=decisions,
                           _provenance={'read_only': True, 'operations': ['DescribeTrails', 'GetTrailStatus', 'GetEventSelectors', 'GetRole', 'GetContextKeysForPrincipalPolicy', 'SimulatePrincipalPolicy'],
                                        'trail_arn': trail['TrailARN'], 'simulated_resource_arn': stream,
                                        'resource_basis': 'documented CloudTrail base log stream; numbered future streams unassessed',
                                        'effective_live_delivery_verified': False, 'SCP_RCP_verified': False})
            except (ValueError, TypeError, KeyError):
                row['_coverage'] = {'simulation_context_complete': {'status': 'not_collected', 'code': 'cloudtrail_delivery_native_context_unresolved'}}
            output.append(row)
        return _result(output)
    except ReadFailure as exc:
        return _result([], exc.status, exc.code)


FETCHERS = {'cloudtrail_trail': trails, 'cloudtrail_delivery_permission': permissions}
