"""Bounded Control Tower state joined to native organization and owner AI scope.

The owner classifies only the audited account. No account is inferred to use AI.
The supported management-account/us-east-1 path has cross-home-region listing
visibility; opt-in regional absence and member-account absence stay unavailable.
"""
import copy
import re

KIND = 'control_tower_landing_zone'
OPTION = 'aws_controltower'
SPECS = {KIND: ('controltower', 'list_landing_zones', 'landingZones')}
READ_ACTIONS = {('controltower', 'get_landing_zone'), ('organizations', 'describe_organization')}
NATIVE_IDS = {KIND: 'OrganizationId'}


def normalize(options, scopes=None):
    parameters = options.get('compliance_parameters', {})
    if not isinstance(parameters, dict):
        raise ValueError('compliance parameters must be an object')
    if OPTION not in parameters:
        return None
    value = parameters[OPTION]
    if not isinstance(value, dict) or set(value) != {'scope', 'organization_id', 'ai_account_ids'}:
        raise ValueError('Control Tower accepts only normative owner scope')
    scope, org, accounts = value['scope'], value['organization_id'], value['ai_account_ids']
    match = re.fullmatch(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9])', scope) if isinstance(scope, str) else None
    if (match is None or not isinstance(org, str) or not re.fullmatch(r'o-[a-z0-9]{10,32}', org)
            or not isinstance(accounts, list) or accounts != [match[1]]):
        raise ValueError('Control Tower requires the exact audited AI account and organization')
    if scopes is not None and list(scopes) != [scope]:
        raise ValueError('Control Tower owner scope differs from selected scope')
    return copy.deepcopy(value)


def project_response(response, operation):
    """Exclude manifests, email addresses and configuration bodies before cache."""
    from .aws import ReadFailure
    def fail():
        raise ReadFailure('malformed', 'controltower_native_response_invalid')
    if not isinstance(response, dict):
        fail()
    if operation == 'describe_organization':
        row = response.get('Organization')
        if not isinstance(row, dict):fail()
        return {'Organization': {k: copy.deepcopy(v) for k, v in row.items()
            if k in {'Id', 'Arn', 'MasterAccountId', 'MasterAccountArn', 'FeatureSet', 'AvailablePolicyTypes'}}}
    if operation == 'list_landing_zones':
        rows = response.get('landingZones')
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):fail()
        output = {'landingZones': [{'arn': row['arn']} if 'arn' in row else {} for row in rows]}
        if 'nextToken' in response:
            token = response['nextToken']
            if (not isinstance(token, str) or len(token) > 4096
                    or any(ord(c) < 32 or ord(c) == 127 for c in token)):fail()
            output['nextToken'] = token
        return output
    row = response.get('landingZone')
    if not isinstance(row, dict):fail()
    return {'landingZone': {k: copy.deepcopy(row[k]) for k in ('arn', 'status') if k in row}}


def collect(requests, session, region, account):
    from .aws import ReadFailure, ReadResult
    policy = getattr(requests, 'controltower_policy', None)
    if policy is None:
        return ReadResult([], 'not_collected', {'code': 'controltower_owner_ai_scope_required'})
    if policy['scope'] != account + '/' + region:
        return ReadResult([], 'not_collected', {'code': 'controltower_owner_scope_mismatch'})
    if region != 'us-east-1' or session.get_partition_for_region(region) != 'aws':
        return ReadResult([], 'not_collected', {'code': 'controltower_cross_region_visibility_unproven'})
    def detail(service, where, operation, **kwargs):
        value = requests.detail(session, service, where, operation, **kwargs)
        if value.get('collection_status') != 'collected':
            raise ReadFailure(value.get('collection_status', 'not_collected'),
                              (value.get('error') or {}).get('code', 'controltower_detail_incomplete'))
        return value
    try:
        org = detail('organizations', region, 'describe_organization').get('Organization')
        if (not isinstance(org, dict) or org.get('Id') != policy['organization_id']
                or org.get('MasterAccountId') != account
                or org.get('Arn') != f'arn:aws:organizations::{account}:organization/{policy["organization_id"]}'):
            raise ValueError('organization identity or management-account authority unavailable')
        listing = requests.pages(session, 'controltower', region, 'list_landing_zones', 'landingZones',
                                 _tokens=('nextToken', 'nextToken'))
        if listing.status not in ('collected', 'empty'):
            raise ReadFailure(listing.status, (listing.error or {}).get('code', 'controltower_listing_incomplete'))
        # The documented API exposes one landing-zone identifier per account.
        if len(listing.items) > 1:
            raise ValueError('ambiguous landing-zone inventory')
        zones = []
        for row in listing.items:
            arn = row.get('arn')
            match = re.fullmatch(r'arn:aws:controltower:([a-z]{2}(?:-[a-z0-9]+)+-[0-9]):'
                                + re.escape(account) + r':landingzone/[A-Za-z0-9-]{1,128}', arn) if isinstance(arn, str) else None
            if match is None or match[1] not in session.get_available_regions('controltower', partition_name='aws'):
                raise ValueError('foreign or unsupported landing-zone identity')
            zone = detail('controltower', match[1], 'get_landing_zone', landingZoneIdentifier=arn).get('landingZone')
            if (not isinstance(zone, dict) or zone.get('arn') != arn
                    or zone.get('status') not in {'ACTIVE', 'PROCESSING', 'FAILED'}):
                raise ValueError('landing-zone identity or state unavailable')
            zones.append({'Arn': arn, 'Status': zone['status']})
        return ReadResult([{'OrganizationId': org['Id'], 'InScopeAiAccountIds': policy['ai_account_ids'],
            'LandingZones': zones, '_provenance': {'owner_ai_classification': True,
            'organization_membership_source': 'DescribeOrganization',
            'landing_zone_sources': ['ListLandingZones', 'GetLandingZone'],
            'listing_region': region, 'management_account_verified': True,
            'regional_governance_or_workload_enforcement_proven': False}}], 'collected')
    except ReadFailure as exc:
        return ReadResult([], exc.status, {'code': exc.code})
    except (ValueError, TypeError, KeyError, AttributeError):
        return ReadResult([], 'malformed', {'code': 'controltower_native_identity_unavailable'})


FETCHERS = {KIND: collect}
