"""Normal connector requirements cannot inject gateway monitoring outcomes."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from peaso.checks.compliance_new_sw25_facts import _policy, GATEWAY_ID
from peaso.checks.facts import Unavailable
from peaso.server.validation import validate_connector

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'


def review():
    now = datetime.now(timezone.utc)
    return {'status': 'collected', 'scope': SCOPE, 'checks': {GATEWAY_ID: {
        'windowStart': (now - timedelta(hours=1)).isoformat(),
        'windowEnd': (now - timedelta(minutes=1)).isoformat(),
        'maxAlertLatencySeconds': 60, 'evaluationIntervalSeconds': 60,
        'targetDenominator': 'totalTargetsAtWindowStart'}}}


def intake(value, mode='cognito', provider='azure'):
    auth = {'method': 'token', 'arm_token': 'inert'} if provider == 'azure' else {}
    return validate_connector(provider, auth, {'compliance_policy': {'sw25': value}}, SimpleNamespace(auth_mode=mode))


@pytest.mark.parametrize('mode', ['local', 'cognito'])
def test_normal_connector_accepts_only_normative_gateway_requirements(mode):
    intake(review(), mode)


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('mutation', ['observation', 'boolean_interval', 'timezone', 'inverted', 'denominator', 'foreign_provider'])
def test_intake_rejects_observed_outcomes_and_invalid_windows(mode, mutation):
    from fastapi import HTTPException
    value = review()
    criteria = value['checks'][GATEWAY_ID]
    if mutation == 'observation': criteria['actionDelivered'] = True
    if mutation == 'boolean_interval': criteria['maxAlertLatencySeconds'] = True
    if mutation == 'timezone': criteria['windowStart'] = '2026-10-01T00:00:00'
    if mutation == 'inverted': criteria['windowStart'] = criteria['windowEnd']
    if mutation == 'denominator': criteria['targetDenominator'] = 'healthyTargets'
    with pytest.raises(HTTPException) as error:
        intake(value, mode, 'aws' if mutation == 'foreign_provider' else 'azure')
    assert error.value.status_code == 422


def test_shared_policy_bridge_is_scope_bound_and_does_not_modify_input():
    value = review()
    original = deepcopy(value)
    index = {'context': {'provider': 'azure', 'scope': SCOPE,
                        'metadata': {'compliance_policy': {'sw25': value}}}}
    policy = _policy(index, GATEWAY_ID)
    assert policy == {**value['checks'][GATEWAY_ID], 'scope': SCOPE}
    assert value == original


@pytest.mark.parametrize('mutation', ['foreign', 'denied', 'child_scope'])
def test_bridge_cannot_rebind_foreign_or_unavailable_approval(mutation):
    value = review()
    if mutation == 'foreign': value['scope'] = '/subscriptions/foreign'
    if mutation == 'denied': value['status'] = 'denied'
    if mutation == 'child_scope': value['checks'][GATEWAY_ID]['scope'] = '/subscriptions/foreign'
    index = {'context': {'provider': 'azure', 'scope': SCOPE,
                        'metadata': {'compliance_policy': {'sw25': value}}}}
    with pytest.raises(Unavailable):
        _policy(index, GATEWAY_ID)


def test_legacy_other_review_does_not_hide_new_gateway_requirement():
    value = review()
    index = {'context': {'provider': 'azure', 'scope': SCOPE, 'metadata': {
        'sw25_policy': {'other': {'scope': SCOPE}}, 'compliance_policy': {'sw25': value}}}}
    assert _policy(index, GATEWAY_ID)['maxAlertLatencySeconds'] == 60


def test_existing_legacy_gateway_policy_retains_its_original_authority():
    legacy = {'scope': SCOPE, 'maxAlertLatencySeconds': 90}
    index = {'context': {'provider': 'azure', 'scope': SCOPE, 'metadata': {
        'sw25_policy': {GATEWAY_ID: legacy}, 'compliance_policy': {'sw25': review()}}}}
    assert _policy(index, GATEWAY_ID) == legacy


def test_gateway_and_existing_guest_requirements_can_share_normal_connector():
    value = review()
    value['checks']['azure.cis.guest_users_reviewed_monthly_basis'] = {}
    value['checks']['azure.cis.guest_users_reviewed_regular_basis'] = {'maxReviewAgeDays': 30}
    intake(value)
