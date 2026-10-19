"""Cognito management-event flags and role-group correlation."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = '222233334444'
POOL = 'us-east-1_AbCd1234'
ACTOR = f'arn:aws:iam::{ACCOUNT}:user/lab'
ROLE_ARN = f'arn:aws:iam::{ACCOUNT}:role/lab'
FIELDS = (
    ('AdminCreateUser', 'request.cognito_suppressed_admin_user'),
    ('AdminSetUserPassword', 'request.cognito_permanent_password_set'),
    ('CreateGroup', 'request.cognito_group_role_set'),
    ('CreateUserPoolClient', 'request.cognito_long_refresh_no_revocation'),
    ('SetUserPoolMfaConfig', 'request.cognito_mfa_off'),
    ('SetRiskConfiguration', 'request.cognito_compromised_credentials_no_action'),
    ('AdminDisableUser', 'request.cognito_user_disabled'),
    ('AdminEnableUser', 'request.cognito_user_enabled'),
    ('AdminAddUserToGroup', 'request.cognito_user_added_to_role_group'),
)
RULES = tuple(Rule(id=str(i), title=field, description=field, level='medium',
                   technique_id=field, product='aws', selection={
                       'event.source': 'cognito-idp.amazonaws.com', 'event.name': name,
                       'event.outcome': 'success', field: True})
              for i, (name, field) in enumerate(FIELDS))


def event(name, request, when='2026-10-19T15:00:00Z'):
    return {'eventSource': 'cognito-idp.amazonaws.com', 'eventName': name,
            'eventCategory': 'Management', 'eventType': 'AwsApiCall',
            'managementEvent': True, 'readOnly': False, 'awsRegion': 'us-east-1',
            'recipientAccountId': ACCOUNT, 'userIdentity': {'accountId': ACCOUNT, 'arn': ACTOR},
            'eventTime': when, 'eventID': name + when,
            'requestParameters': {'userPoolId': POOL, **request}}


def hits(records):
    return {x.technique_id for x in detect_aws_events(records, RULES)}


def test_specific_cognito_control_changes_and_failed_calls():
    cases = [
        (event('AdminCreateUser', {'messageAction': 'SUPPRESS'}), 'request.cognito_suppressed_admin_user'),
        (event('AdminSetUserPassword', {'permanent': True}), 'request.cognito_permanent_password_set'),
        (event('CreateGroup', {'groupName': 'lab', 'roleArn': ROLE_ARN}), 'request.cognito_group_role_set'),
        (event('CreateUserPoolClient', {'refreshTokenValidity': 3650,
              'tokenValidityUnits': {'refreshToken': 'days'}, 'enableTokenRevocation': False}),
         'request.cognito_long_refresh_no_revocation'),
        (event('SetUserPoolMfaConfig', {'mfaConfiguration': 'OFF'}), 'request.cognito_mfa_off'),
        (event('SetRiskConfiguration', {'compromisedCredentialsRiskConfiguration': {
              'eventFilter': ['SIGN_IN'], 'actions': {'eventAction': 'NO_ACTION'}}}),
         'request.cognito_compromised_credentials_no_action'),
        (event('AdminDisableUser', {}), 'request.cognito_user_disabled'),
        (event('AdminEnableUser', {}), 'request.cognito_user_enabled'),
    ]
    for record, expected in cases:
        assert hits([record]) == {expected}
        assert hits([{**record, 'errorCode': 'AccessDenied'}]) == set()
        assert hits([{**record, 'managementEvent': False}]) == set()
    benign = [
        event('AdminCreateUser', {'messageAction': 'RESEND'}),
        event('AdminSetUserPassword', {'permanent': False}),
        event('CreateGroup', {'groupName': 'lab'}),
        event('CreateUserPoolClient', {'refreshTokenValidity': 30, 'enableTokenRevocation': True}),
        event('SetUserPoolMfaConfig', {'mfaConfiguration': 'OPTIONAL'}),
        event('SetRiskConfiguration', {'compromisedCredentialsRiskConfiguration': {
            'eventFilter': ['SIGN_IN'], 'actions': {'eventAction': 'BLOCK'}}}),
    ]
    assert hits(benign) == set()


def test_user_added_to_recent_role_group_requires_matching_successful_change():
    group = event('CreateGroup', {'groupName': 'lab', 'roleArn': ROLE_ARN})
    add = event('AdminAddUserToGroup', {'groupName': 'lab'}, '2026-10-19T15:01:00Z')
    assert 'request.cognito_user_added_to_role_group' in hits([add, group])
    assert hits([add]) == set()
    failed = {**add, 'errorCode': 'AccessDenied'}
    assert 'request.cognito_user_added_to_role_group' not in hits([group, failed])
    wrong = deepcopy(add)
    wrong['requestParameters']['groupName'] = 'other'
    assert 'request.cognito_user_added_to_role_group' not in hits([group, wrong])
