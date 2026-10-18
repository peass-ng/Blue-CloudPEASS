"""Unrestricted sibling CA rules do not suppress native licensing evidence."""
import copy
import pytest
from test_peaso_azure_ca_risk_entitlement_20261016 import (
    policy, routes, collect, fact, Transport, SKUS, USERS)
from urllib.parse import urlsplit


@pytest.mark.parametrize('optional', ['absent', 'null'])
def test_unrestricted_sibling_allows_licensed_risk_evidence(optional):
    sibling = policy(levels=[])
    sibling['id'] = '99999999-aaaa-bbbb-cccc-111111111111'
    if optional == 'absent':
        sibling['conditions'].pop('signInRiskLevels')
    else:
        sibling['conditions']['signInRiskLevels'] = None
    result = fact(collect(Transport(routes(policies=[policy(), sibling]))))
    assert result['status'] == 'collected'
    assert result['items'][0]['risk_p2_service_plan_ids']


def test_only_unrestricted_null_condition_avoids_license_reads():
    sibling = policy(levels=[])
    sibling['conditions']['signInRiskLevels'] = None
    api = Transport(routes(policies=[sibling]))
    result = fact(collect(api))
    assert result['status'] == 'empty'
    assert not any(urlsplit(call).path in (SKUS, USERS) for call in api.calls)


def test_absent_conditions_object_is_still_unavailable():
    malformed = policy()
    malformed['conditions'] = None
    result = fact(collect(Transport(routes(policies=[malformed]))))
    assert result['status'] not in ('collected', 'empty')
