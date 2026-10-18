"""Native resource compliance assessments, without copying any tag values.

GetResources returns tagged or previously tagged resources, not an inventory of
every resource. This adapter never infers the compliance of unreturned resources.
https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html
"""
from copy import deepcopy
from functools import lru_cache
import re

KIND = 'resource_tag_policy_compliance'
SCHEMA = 'native-resource-tag-compliance-v1'
SERVICE = 'resourcegroupstaggingapi'
QUERY = {'IncludeComplianceDetails': True, 'ExcludeCompliantResources': False, 'ResourcesPerPage': 100}
SPECS = {KIND: (SERVICE, 'get_resources', 'ResourceTagMappingList')}
READ_ACTIONS = {(SERVICE, 'get_resources')}
NATIVE_IDS = {KIND: 'ResourceARN'}
GLOBAL_TYPES = set()
ARN = re.compile(r'arn:(aws(?:-[a-z0-9-]+)?):[a-z0-9-]+:([^:]*):([0-9]{12})?:(.+)')


def _arn(value):
    match = ARN.fullmatch(value) if isinstance(value, str) else None
    if match is None or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('invalid_tag_compliance_resource_arn')
    return match


@lru_cache(maxsize=128)
def partition_for_region(region):
    # Endpoint metadata only; constructing this resolver never resolves credentials.
    from boto3.session import Session
    return Session().get_partition_for_region(region)


def project_response(response, *, exclude_compliant_resources=False):
    """Project before shared Futures/cache; native Tags never survive this call."""
    if type(exclude_compliant_resources) is not bool or not isinstance(response, dict) or not isinstance(response.get('ResourceTagMappingList'), list):
        raise ValueError('invalid_tag_compliance_response')
    projected, seen = [], set()
    for row in response['ResourceTagMappingList']:
        if not isinstance(row, dict):
            raise ValueError('invalid_tag_compliance_resource')
        arn = row.get('ResourceARN')
        _arn(arn)
        if arn in seen:
            raise ValueError('duplicate_tag_compliance_resource')
        seen.add(arn)
        safe = {'ResourceARN': arn}
        if 'ComplianceDetails' in row:
            details = row['ComplianceDetails']
            if not isinstance(details, dict):
                raise ValueError('invalid_tag_compliance_details')
            allowed = {}
            if 'ComplianceStatus' in details:
                if type(details['ComplianceStatus']) is not bool:
                    raise ValueError('invalid_native_tag_compliance_status')
                allowed['ComplianceStatus'] = details['ComplianceStatus']
            for field in ('NoncompliantKeys', 'KeysWithNoncompliantValues'):
                if field not in details:
                    continue
                names = details[field]
                if (not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names)
                        or len(names) != len(set(names))):
                    raise ValueError('invalid_tag_compliance_keys')
                allowed[field] = list(names)
            if allowed.get('ComplianceStatus') is True and any(allowed.get(field) for field in ('NoncompliantKeys', 'KeysWithNoncompliantValues')):
                raise ValueError('contradictory_native_tag_compliance')
            safe['ComplianceDetails'] = allowed
        safe['_provenance'] = {'schema': SCHEMA, 'source_operation': 'GetResources', 'read_only': True,
                               'include_compliance_details': True, 'exclude_compliant_resources': exclude_compliant_resources}
        projected.append(safe)
    result = {'ResourceTagMappingList': projected}
    token = response.get('PaginationToken')
    if token is not None:
        if not isinstance(token, str) or len(token) > 4096 or any(ord(c) < 32 for c in token):
            raise ValueError('invalid_tag_compliance_pagination')
        result['PaginationToken'] = token
    return result


def fetch(requests, session, region, account):
    from .aws import ReadResult
    read = requests.pages(session, SERVICE, region, 'get_resources', 'ResourceTagMappingList', **QUERY)
    rows, seen = [], set()
    try:
        for row in read.items:
            match = _arn(row.get('ResourceARN'))
            if (match[1] != partition_for_region(region) or match[2] not in ('', region) or match[3] not in (None, account)
                    or row['ResourceARN'] in seen or row.get('_provenance', {}).get('schema') != SCHEMA):
                raise ValueError('foreign_or_unverified_tag_compliance_resource')
            seen.add(row['ResourceARN'])
            safe = deepcopy(row)
            safe['AccountId'], safe['Region'] = account, region
            rows.append(safe)
    except (ValueError, TypeError, AttributeError):
        return ReadResult(rows, 'partial' if rows else 'malformed', {'code': 'invalid_tag_compliance_scope_or_identity'})
    return ReadResult(rows, read.status, read.error)


FETCHERS = {KIND: fetch}
