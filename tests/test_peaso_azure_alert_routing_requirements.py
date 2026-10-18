"""Normal connectors admit routing requirements, never routing observations."""
from copy import deepcopy

import pytest
from fastapi import HTTPException

from peaso.checks.compliance_new_sw25_facts import ROUTING_ID, _policy
from tests.test_peaso_azure_gateway_requirements import SCOPE, intake, review

GROUP = SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/security'


def policy(criteria):
    return {'status': 'collected', 'scope': SCOPE, 'checks': {ROUTING_ID: criteria}}


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('criteria', [{}, {'actionGroupId': None}, {'actionGroupId': GROUP}])
def test_optional_or_exact_group_requirement_reaches_shared_policy(mode, criteria):
    requirement = policy(deepcopy(criteria))
    intake(requirement, mode)
    context = {'context': {'provider': 'azure', 'scope': SCOPE,
                          'metadata': {'compliance_policy': {'sw25': requirement}}}}
    assert _policy(context, ROUTING_ID) == {**criteria, 'scope': SCOPE}


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('mutation', ['foreign', 'wrong_type', 'traversal', 'observation', 'boolean', 'foreign_provider'])
def test_invalid_or_observed_routing_input_rejected(mode, mutation):
    value = policy({'actionGroupId': GROUP})
    criterion = value['checks'][ROUTING_ID]
    if mutation == 'foreign': criterion['actionGroupId'] = GROUP.replace('11111111-', '33333333-', 1)
    if mutation == 'wrong_type': criterion['actionGroupId'] = GROUP.replace('actionGroups', 'metricAlerts')
    if mutation == 'traversal': criterion['actionGroupId'] = GROUP.rsplit('/', 1)[0] + '/..'
    if mutation == 'observation': criterion['_actionStateBindings'] = []
    if mutation == 'boolean': criterion['actionGroupId'] = True
    with pytest.raises(HTTPException) as error:
        intake(value, mode, provider='aws' if mutation == 'foreign_provider' else 'azure')
    assert error.value.status_code == 422


def test_routing_requirement_coexists_with_existing_native_criteria():
    value = review()
    value['checks'][ROUTING_ID] = {'actionGroupId': GROUP}
    value['checks']['azure.cis.guest_users_reviewed_monthly_basis'] = {}
    value['checks']['azure.cis.guest_users_reviewed_regular_basis'] = {'maxReviewAgeDays': 30}
    intake(value)
