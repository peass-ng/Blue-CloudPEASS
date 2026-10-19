"""Cognito native refresh-token rotation setting; no registration or cloud calls.

The response's optional rotation object is never defaulted. Only the explicit
Feature enum determines the configuration verdict. The documented grace range
is validated as a response shape, without choosing a customer grace policy.
"""
import re

from . import result, unknown
from .facts import Unavailable, get, guard, list_of_objects

CHECK_ID = 'aws.review.cognito.app_client_refresh_token_rotation'
KIND = 'cognito_user_pool_client'
TITLE = 'Cognito app client enables refresh token rotation'
REMEDIATION = ('Enable refresh token rotation on the app client. Migrate refresh requests to '
               'GetTokensFromRefreshToken and remove ALLOW_REFRESH_TOKEN_AUTH before enabling rotation; '
               'validate application compatibility separately.')


def evaluate(item, index):
    try:
        guard(item)
        scope = get(index, 'context.scope', str)
        match = re.fullmatch(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9])', scope)
        if get(index, 'context.provider', str) != 'aws' or match is None:
            raise Unavailable('AWS account and Region context required')
        account, region = match.groups()
        if get(item, 'AccountId', str) != account or get(item, 'Region', str) != region:
            raise Unavailable('app client account or Region is foreign')
        pool, client = get(item, 'UserPoolId', str), get(item, 'ClientId', str)
        if (re.fullmatch(re.escape(region) + r'_[A-Za-z0-9]+', pool) is None or len(pool) > 55 or
                re.fullmatch(r'[A-Za-z0-9_+]{1,128}', client) is None or
                get(item, 'id', str) != pool + '/' + client):
            raise Unavailable('app client native identity malformed or unbound')
        if (get(item, '_provenance.source_operation', str) != 'list_user_pool_clients' or
                get(item, '_provenance.read_only', bool) is not True):
            raise Unavailable('native app client enumeration provenance missing')
        envelopes = get(index, 'collections.' + KIND, list)
        if len(envelopes) != 1:
            raise Unavailable('app client inventory missing or ambiguous')
        envelope = envelopes[0]
        if (get(envelope, 'type', str) != KIND or get(envelope, 'scope', str) != scope or
                get(envelope, 'account_id', str) != account or get(envelope, 'global', bool) is not False or
                get(envelope, 'status', str) != 'collected' or 'error' in envelope):
            raise Unavailable('app client inventory coverage or account binding unavailable')
        rows = list_of_objects(get(envelope, 'items', list))
        matches = [row for row in rows if get(row, 'id', str) == item['id']]
        if len(matches) != 1 or matches[0] != item:
            raise Unavailable('app client absent, duplicated or inconsistent in scoped inventory')
        detail = get(item, 'ClientDetail', dict)
        if get(detail, 'collection_status', str) != 'collected' or 'error' in detail or 'error' in item:
            raise Unavailable('DescribeUserPoolClient unavailable')
        configuration = get(detail, 'UserPoolClient', dict)
        if (get(configuration, 'UserPoolId', str) != pool or
                get(configuration, 'ClientId', str) != client):
            raise Unavailable('described client does not match enumerated native identity')
        rotation = get(configuration, 'RefreshTokenRotation', dict)
        feature = get(rotation, 'Feature', str)
        if feature not in {'ENABLED', 'DISABLED'}:
            raise Unavailable('unrecognized refresh token rotation setting')
        if 'RetryGracePeriodSeconds' in rotation:
            grace = get(rotation, 'RetryGracePeriodSeconds', int)
            if not 0 <= grace <= 60:
                raise Unavailable('malformed native rotation retry grace')
        return result(feature == 'DISABLED', client_id=client, user_pool_id=pool,
                      refresh_token_rotation=feature,
                      observed='Cognito app client refresh token rotation is ' + feature + '.',
                      semantics='Observed native rotation configuration only; application behavior, token validity and authentication are unassessed')
    except (Unavailable, TypeError, KeyError, IndexError, AttributeError) as error:
        return unknown('Native Cognito rotation configuration unavailable or malformed',
                       error_type=type(error).__name__,
                       observed='Required own-account Cognito rotation configuration is unavailable or malformed.')


DECLARATIONS = [{'id': CHECK_ID, 'kind': KIND, 'target': 'resource', 'severity': 'medium',
                 'category': 'hardening', 'title': TITLE, 'evaluator': 'evaluate',
                 'dependencies': [KIND], 'control': 'security_configuration', 'remediation': REMEDIATION}]


def fixture(feature='ENABLED'):
    account, region, pool, client = '123456789012', 'us-east-1', 'us-east-1_Example', 'exampleclient123'
    scope = account + '/' + region
    item = {'AccountId': account, 'Region': region, 'UserPoolId': pool, 'ClientId': client,
            'id': pool + '/' + client,
            '_provenance': {'source_operation': 'list_user_pool_clients', 'read_only': True},
            'ClientDetail': {'collection_status': 'collected', 'UserPoolClient': {
                'UserPoolId': pool, 'ClientId': client, 'RefreshTokenRotation': {'Feature': feature}}}}
    envelope = {'type': KIND, 'scope': scope, 'service': 'cognito-idp', 'account_id': account,
                'global': False, 'status': 'collected', 'items': [item]}
    return item, {'context': {'provider': 'aws', 'scope': scope}, 'collections': {KIND: [envelope]},
                  KIND: [{'type': KIND, 'scope': scope, 'data': item}]}


_pass, _pass_index = fixture()
_fail, _fail_index = fixture('DISABLED')
RUNTIME_CASES = {CHECK_ID: {'pass': _pass, 'pass_index': _pass_index,
                           'fail': _fail, 'fail_index': _fail_index, 'missing': {}, 'malformed': None}}

DESCRIPTION = ('Checks the explicit RefreshTokenRotation.Feature setting returned for an own-account Cognito '
               'user-pool app client. ENABLED passes and DISABLED fails. Missing, denied, foreign or malformed '
               'evidence remains unknown. This checks configuration, not token validity, authentication or exploitation.')
ADMISSION_DATA = {'schema_version': 1, 'checks': [{
    'spec': {'id': CHECK_ID, 'provider': 'aws', 'resource_kind': KIND,
             'data_source': 'cognito-idp:DescribeUserPoolClient via ClientDetail.UserPoolClient.RefreshTokenRotation.Feature, native UserPoolId/ClientId and complete own-account regional inventory',
             'predicate': 'PASS on explicit ENABLED; FAIL on explicit DISABLED; UNKNOWN on missing, denied, incomplete, foreign, malformed or unrecognized evidence. No omitted-response default or customer-policy input.',
             'severity': 'medium', 'category': 'hardening', 'title': TITLE,
             'description': DESCRIPTION, 'remediation_hint': REMEDIATION},
    'description': {'description': DESCRIPTION,
                    'evaluated': ['ClientDetail.collection_status', 'ClientDetail.UserPoolClient.UserPoolId/ClientId',
                                  'ClientDetail.UserPoolClient.RefreshTokenRotation.Feature',
                                  'optional RetryGracePeriodSeconds native type/range', 'AccountId', 'Region',
                                  'UserPoolId', 'ClientId', 'id', '_provenance', 'complete scoped cognito_user_pool_client inventory'],
                    'pass_when': 'The bound native app client explicitly reports Feature=ENABLED.',
                    'fail_when': 'The bound native app client explicitly reports Feature=DISABLED.',
                    'not_applicable_when': 'No app client resource is present; missing configuration on a present client is UNKNOWN.'},
    'sources': [
        {'url': 'https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RefreshTokenRotationType.html',
         'sha256': '709fa5be9af4adf7f51725fc9673275dd1151cf9db602373d61adf0bbf1ed02a'},
        {'url': 'https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UserPoolClientType.html',
         'sha256': '6fd4f8d9be37dd4ab73e50fcac5a7e069ffa1fb0c4c007f64d06387126800d43'},
        {'url': 'https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-refresh-token.html',
         'sha256': '634d29107758a83cb49a1aeda39b72ef48f6eb77c2209909938546db3f030b25'}],
    'requirements': [], 'dependencies': [KIND], 'target': 'resource',
    'review_notes': 'Rotation is recommended by AWS. RefreshTokenRotation is optional in UserPoolClientType; omitted response evidence is UNKNOWN. Legacy REFRESH_TOKEN_AUTH is incompatible with rotation and must be migrated before enablement. Optional retry grace is validated only against the documented native 0..60 range, without an arbitrary policy threshold. CMK, VPC-only, backup retention and EFS root-exception proposals remain outside scope because they depend on owner criteria.',
    'function': 'peaso.checks.aws_cognito_rotation_review_20261019:evaluate'}]}
