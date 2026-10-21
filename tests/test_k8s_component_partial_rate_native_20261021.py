"""Captured unsafe flags survive incomplete siblings; zero QPS is not a bounded rate."""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from peaso.checks.fixtures import CASES


def containers(value):
    if isinstance(value, dict):
        if isinstance(value.get('containers'), list):
            return value['containers']
        for child in value.values():
            found = containers(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = containers(child)
            if found is not None:
                return found
    return None


@pytest.mark.parametrize('kind', ['job', 'pod', 'podtemplate'])
@pytest.mark.parametrize('value,status', [('0', 'UNKNOWN'), ('5', 'PASS'), ('6', 'FAIL'),
                                         ('invalid', 'UNKNOWN'), (None, 'UNKNOWN')])
def test_declared_event_rate(kind, value, status):
    cid = f'k8s.ports.{kind}.container_argument_event_qps_less_than_5'
    item = deepcopy(CASES[cid]['pass'])
    flags = containers(item)[0]['_component_config']['flags']
    if value is None:
        del flags['event-qps']
    else:
        flags['event-qps'] = value
    before = deepcopy(item)
    assert evaluate_check(cid, item, {})[0] == status
    assert item == before


@pytest.mark.parametrize('first', [False, True])
@pytest.mark.parametrize('base,status', [('fail', 'FAIL'), ('pass', 'UNKNOWN')])
def test_incomplete_sibling_preserves_confirmed_unsafe_component(first, base, status):
    cid = 'k8s.ports.job.container_argument_event_qps_less_than_5'
    item = deepcopy(CASES[cid][base])
    rows = containers(item)
    incomplete = deepcopy(rows[0])
    incomplete['name'] = 'incomplete'
    incomplete['_component_config']['flags_complete'] = False
    rows.insert(0 if first else len(rows), incomplete)
    before = deepcopy(item)
    assert evaluate_check(cid, item, {})[0] == status
    assert item == before


@pytest.mark.parametrize('cid', [
    'k8s.ports.job.container_argument_authorization_mode_no_always_allow',
    'k8s.ports.pod.container_argument_pod_security_policy_enabled',
])
@pytest.mark.parametrize('case,status', [('pass', 'PASS'), ('fail', 'FAIL'), ('missing', 'UNKNOWN')])
def test_other_component_contracts_preserved(cid, case, status):
    assert evaluate_check(cid, deepcopy(CASES[cid][case]), {})[0] == status
