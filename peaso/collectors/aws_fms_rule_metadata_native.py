"""FMS-managed WAF ACL metadata only; policy association remains unavailable."""
from functools import lru_cache
import re

KIND = 'fms_web_acl_rules'
PROFILE = 'fms-managed-web-acl-metadata-v1'
PROJECTION_OPERATIONS = frozenset({('wafv2', 'list_web_acls'), ('wafv2', 'get_web_acl')})
READ_ACTIONS = set(PROJECTION_OPERATIONS)
SPECS = {KIND: ('wafv2', 'list_web_acls', 'WebACLs')}
NATIVE_IDS = {KIND: 'WebACLArn'}
GLOBAL_TYPES = set()
ARRAYS = ('PreProcessFirewallManagerRuleGroups', 'PostProcessFirewallManagerRuleGroups')
FLAGS = ('ManagedByFirewallManager', 'RetrofittedByFirewallManager')
UUID = r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
ARN = re.compile(r'arn:(aws(?:-[a-z0-9-]+)?):wafv2:([a-z0-9-]+):([0-9]{12}):(regional|global)/webacl/([\w-]{1,128})/(' + UUID + r')')


def _invalid():
    from .aws import ReadFailure
    raise ReadFailure('malformed', 'fms_acl_metadata_invalid')


@lru_cache(maxsize=1)
def _model():
    import botocore.session
    return botocore.session.get_session().get_service_model('wafv2')


def _identity(row, scope):
    if not isinstance(row, dict) or scope not in {'REGIONAL', 'CLOUDFRONT'}: _invalid()
    arn, name, identifier = row.get('ARN'), row.get('Name'), row.get('Id')
    parsed = ARN.fullmatch(arn) if isinstance(arn, str) else None
    if (not parsed or parsed[4] != ('regional' if scope == 'REGIONAL' else 'global')
            or parsed[5] != name or parsed[6] != identifier
            or scope == 'CLOUDFRONT' and parsed[2] != 'us-east-1'):
        _invalid()
    return parsed


def project_response(response, service, operation, arguments):
    """Validate native full SDK response before removing statement/text fields."""
    from botocore.validate import validate_parameters
    from botocore.exceptions import ParamValidationError
    if service != 'wafv2' or (service, operation) not in PROJECTION_OPERATIONS or not isinstance(response, dict): _invalid()
    name = {'list_web_acls': 'ListWebACLs', 'get_web_acl': 'GetWebACL'}[operation]
    try:
        validate_parameters({k: v for k, v in response.items() if k != 'ResponseMetadata'},
                            _model().operation_model(name).output_shape)
    except ParamValidationError:
        _invalid()
    scope = arguments.get('Scope')
    result = {'_metadata_projection': PROFILE}
    if operation == 'list_web_acls':
        rows = response.get('WebACLs')
        if not isinstance(rows, list): _invalid()
        result['WebACLs'] = []
        for row in rows:
            _identity(row, scope)
            result['WebACLs'].append({k: row[k] for k in ('Name', 'Id', 'ARN')})
        if 'NextMarker' in response: result['NextMarker'] = response['NextMarker']
        return result
    row = response.get('WebACL')
    _identity(row, scope)
    if row['Name'] != arguments.get('Name') or row['Id'] != arguments.get('Id'): _invalid()
    safe = {k: row[k] for k in ('Name', 'Id', 'ARN')}
    for flag in FLAGS:
        if flag in row:
            if type(row[flag]) is not bool: _invalid()
            safe[flag] = row[flag]
    for field in ARRAYS:
        if field not in row: continue  # Retain omission, never invent configured absence.
        groups = row[field]
        if not isinstance(groups, list): _invalid()
        safe[field] = []
        for group in groups:
            if (not isinstance(group, dict) or not isinstance(group.get('Name'), str)
                    or re.fullmatch(r'[\w-]{1,128}', group['Name']) is None
                    or type(group.get('Priority')) is not int or group['Priority'] < 0): _invalid()
            safe[field].append({'Name': group['Name'], 'Priority': group['Priority']})
        # These are separate ordering domains. Ambiguity within one set is
        # invalid metadata; equal priorities between first/last sets are valid.
        if (len({group['Name'] for group in safe[field]}) != len(groups)
                or len({group['Priority'] for group in safe[field]}) != len(groups)): _invalid()
    result['WebACL'] = safe
    return result


def collect(requests, session, region, account):
    from .aws import ReadFailure, ReadResult
    if not isinstance(account, str) or re.fullmatch(r'[0-9]{12}', account) is None:
        return ReadResult([], 'malformed', {'code': 'fms_acl_account_invalid'})
    partition = session.get_partition_for_region(region)
    rows, seen = [], set()
    for scope in ('REGIONAL', 'CLOUDFRONT') if region == 'us-east-1' else ('REGIONAL',):
        listing = requests.pages(session, 'wafv2', region, 'list_web_acls', 'WebACLs',
                                 Scope=scope, Limit=100, _metadata_profile=PROFILE)
        if listing.status not in {'collected', 'empty'}:
            return ReadResult(rows, 'partial' if rows else listing.status, listing.error)
        for summary in listing.items:
            try:
                parsed = _identity(summary, scope)
                key = scope, summary['Id']
                if (parsed[1] != partition or parsed[2] != region or parsed[3] != account or key in seen): _invalid()
                seen.add(key)
            except ReadFailure as error:
                return ReadResult(rows, 'partial' if rows else error.status, {'code': error.code})
            detail = requests.detail(session, 'wafv2', region, 'get_web_acl', Name=summary['Name'],
                Id=summary['Id'], Scope=scope, _metadata_profile=PROFILE)
            if detail.get('collection_status') != 'collected':
                return ReadResult(rows, 'partial' if rows else detail.get('collection_status', 'unknown'),
                                  {'code': detail.get('error', {}).get('code', 'fms_acl_detail_unavailable')})
            acl = detail.get('WebACL')
            try:
                if detail.get('_metadata_projection') != PROFILE: _invalid()
                _identity(acl, scope)
                if acl['ARN'] != summary['ARN'] or acl['Name'] != summary['Name'] or acl['Id'] != summary['Id']: _invalid()
            except ReadFailure as error:
                return ReadResult(rows, 'partial' if rows else error.status, {'code': error.code})
            if not any(acl.get(flag) is True for flag in FLAGS): continue
            row = {'_resource_id': acl['ARN'], 'Id': acl['Id'], 'Name': acl['Name'], 'WebACLArn': acl['ARN'],
                'AccountId': account, 'Region': region, 'AclScope': scope, 'complete': False,
                'RulesInventoryStatus': 'collected', '_metadata_projection': PROFILE,
                '_coverage': {'PolicyId': {'status': 'not_collected', 'reason': 'native_acl_does_not_identify_owning_policy'},
                    'managedPolicyUniverse': {'status': 'not_collected', 'reason': 'target_policy_membership_unavailable'}},
                '_provenance': {'read_only': True, 'source_operation': 'ListWebACLs+GetWebACL',
                    'scope': scope, 'client_region': region,
                    'semantics': 'FMS-managed ACL native rule-group metadata only; policy association and policy-wide priorities unassessed'}}
            row.update({key: acl[key] for key in FLAGS + ARRAYS if key in acl})
            for field in ARRAYS:
                row['_coverage'][field] = {'status': 'collected' if field in acl else 'not_collected'}
            rows.append(row)
    if not rows:
        return ReadResult([], 'not_collected', {'code': 'fms_managed_acl_observations_unavailable'})
    return ReadResult(rows)


FETCHERS = {KIND: collect}
