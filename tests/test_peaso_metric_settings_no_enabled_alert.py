# Historical fixture contracts; current native admission is tested separately.
"""A complete empty/disabled primary roster independently disproves settings."""
from copy import deepcopy
import pytest

from tests.compliance_draft_isolation import staged_registry
from peaso.checks import CHECKS
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot


@pytest.fixture
def settings():
    with staged_registry(['compliance_new_sw25']):
        from tests.test_peaso_compliance_new_sw25 import fixture, SCOPE, NOW
        from peaso.checks.compliance_new_sw25_facts import SETTINGS_ID
        yield fixture(SETTINGS_ID), SCOPE, NOW, SETTINGS_ID


def verdict(case):
    index, scope, now, cid = case
    snapshot = make_snapshot('azure', [scope], [c for envs in index['collections'].values() for c in envs],
        metadata=index['context']['metadata'], created_at=now)
    return next(f['status'] for f in evaluate_snapshot(snapshot, checks=[cid])['findings'] if f['check_id'] == cid)


def inventory(case, kind):
    return case[0]['collections'][kind][0]


def policy(case):
    return case[0]['context']['metadata']['sw25_policy'][case[-1]]['expectedMetricSettings']


def no_enabled(case, mode):
    alerts = inventory(case, 'metric_alert')
    if mode == 'empty': alerts.update(status='empty', items=[])
    else: alerts['items'][0]['properties']['enabled'] = False


@pytest.mark.parametrize('mode', ['empty', 'disabled'])
@pytest.mark.parametrize('groups', ['missing', 'denied', 'partial', 'empty'])
def test_no_enabled_native_rule_fails_without_action_group_evidence(settings, mode, groups):
    no_enabled(settings, mode)
    if groups == 'missing': del settings[0]['collections']['action_group']
    else: inventory(settings, 'action_group').update(status=groups, items=[])
    assert verdict(settings) == 'FAIL'
    check = next(c for c in CHECKS if c.id == settings[-1])
    assert check.allow_incomplete_failure
    assert set(check.dependencies) == {'metric_alert', 'action_group'}


@pytest.mark.parametrize('mode', ['invalid_later_setting', 'empty_group_policy', 'foreign_group_policy', 'empty_policy'])
def test_all_expected_settings_validated_before_conclusive_failure(settings, mode):
    no_enabled(settings, 'empty')
    if mode == 'invalid_later_setting':
        second = deepcopy(policy(settings)[0]); second['severity'] = True
        policy(settings).append(second)
    elif mode == 'empty_group_policy': policy(settings)[0]['actionGroupIds'] = []
    elif mode == 'foreign_group_policy': policy(settings)[0]['actionGroupIds'][0] = '/subscriptions/other/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/group'
    elif mode == 'empty_policy': policy(settings).clear()
    assert verdict(settings) == 'UNKNOWN'


@pytest.mark.parametrize('state,expected', [('partial', 'UNKNOWN'), ('denied', 'DENIED')])
def test_primary_unavailable_inventory_never_proves_no_rule(settings, state, expected):
    inventory(settings, 'metric_alert').update(status=state, items=[])
    assert verdict(settings) == expected


@pytest.mark.parametrize('mode', ['string_enabled', 'wrong_type', 'untrusted_proof'])
def test_malformed_primary_declaration_never_proves_all_disabled(settings, mode):
    no_enabled(settings, 'disabled')
    alert = inventory(settings, 'metric_alert')['items'][0]
    if mode == 'string_enabled': alert['properties']['enabled'] = 'false'
    elif mode == 'wrong_type': alert['type'] = 'Microsoft.Compute/virtualMachines'
    else: alert['_provenance'] = {'read_only': False}
    assert verdict(settings) == 'UNKNOWN'


def test_enabled_rule_still_requires_group_evidence(settings):
    del settings[0]['collections']['action_group']
    assert verdict(settings) == 'UNKNOWN'


def test_existing_complete_positive_still_passes(settings):
    assert verdict(settings) == 'PASS'
