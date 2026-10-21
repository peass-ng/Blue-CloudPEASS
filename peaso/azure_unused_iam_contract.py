"""Pure shared schema for Azure unused IAM collectors and native checks."""
from __future__ import annotations
from uuid import UUID

KIND = 'azure_unused_iam_evidence'
SCHEMA = 'azure-unused-iam-evidence-v1'
GRAPH = 'https://graph.microsoft.com'
BASE_KINDS = frozenset({'directory_group', 'directory_membership',
                       'directory_service_principal', 'directory_application'})
REPORTS = {
    'service_principal_activity': '/beta/reports/servicePrincipalSignInActivities',
    'credential_activity': '/beta/reports/appCredentialSignInActivities',
}
MAX_REPORT_ROWS = 100000
ACTIVITY_FIELDS = ('lastSignInDateTime', 'lastSignInRequestId',
                   'lastSuccessfulSignInDateTime', 'lastSuccessfulSignInRequestId')
FLOW_FIELDS = ('lastSignInActivity', 'applicationAuthenticationClientSignInActivity',
               'applicationAuthenticationResourceSignInActivity', 'delegatedClientSignInActivity',
               'delegatedResourceSignInActivity', 'signInActivity')
CREDENTIAL_FIELDS = ('keyId', 'displayName', 'startDateTime', 'endDateTime', 'type', 'usage')
IDENTITY_FIELDS = ('id', 'appId', 'displayName', 'accountEnabled', 'servicePrincipalType',
                   'signInAudience', 'securityEnabled', 'groupTypes', 'visibility',
                   'membershipRuleProcessingState', 'createdDateTime')


def guid(value):
    if not isinstance(value, str):
        raise ValueError('missing Graph identity')
    try:
        identity = UUID(value)
    except ValueError as exc:
        raise ValueError('malformed Graph identity') from exc
    if identity.int == 0 or str(identity) != value.casefold():
        raise ValueError('noncanonical Graph identity')
    return str(identity)


def required_types(wanted):
    return set(BASE_KINDS) if KIND in wanted else set()


def project_native(kind, row):
    if not isinstance(row, dict):
        raise ValueError('malformed directory row')
    guid(row.get('id'))
    output = {key: row[key] for key in IDENTITY_FIELDS if key in row}
    # Coverage is data, not an assertion that absent credential arrays are empty.
    if '_coverage' in row:
        output['_coverage'] = row['_coverage']
    for field in ('passwordCredentials', 'keyCredentials'):
        if field in row:
            value = row[field]
            if not isinstance(value, list) or any(not isinstance(credential, dict) for credential in value):
                raise ValueError('malformed credential metadata')
            output[field] = [{key: credential[key] for key in CREDENTIAL_FIELDS if key in credential}
                             for credential in value]
    return output


def project_report(name, row):
    if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not row['id']:
        raise ValueError('activity report row identity unavailable')
    guid(row.get('appId'))
    fields = ('id', 'appId') if name == 'service_principal_activity' else (
        'id', 'appId', 'appObjectId', 'servicePrincipalObjectId', 'keyId',
        'credentialOrigin', 'keyType', 'keyUsage', 'createdDateTime', 'expirationDateTime', 'expirationDate', 'resourceId')
    output = {key: row[key] for key in fields if key in row}
    if name == 'credential_activity':
        guid(row.get('keyId'))
        origin = row.get('credentialOrigin')
        if origin not in ('application', 'servicePrincipal'):
            raise ValueError('activity report credential origin unavailable')
        guid(row.get('appObjectId' if origin == 'application' else 'servicePrincipalObjectId'))
    for field in FLOW_FIELDS:
        if field in row:
            activity = row[field]
            if activity is not None and not isinstance(activity, dict):
                raise ValueError('activity report timestamp metadata is malformed')
            output[field] = None if activity is None else {key: activity[key] for key in ACTIVITY_FIELDS if key in activity}
    return output
