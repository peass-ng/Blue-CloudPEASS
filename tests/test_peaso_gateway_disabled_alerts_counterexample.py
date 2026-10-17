"""Disabled native rules cannot monitor a gateway, regardless of missing history."""
import pytest

from tests.test_peaso_gateway_empty_alerts_counterexample import (
    capture, verdict, SCOPE, GATEWAY, NOW, FAMILIES,
)
from peaso.snapshot import make_snapshot


TYPES = {'metric_alert': 'metricAlerts', 'activity_log_alert': 'activityLogAlerts',
         'scheduled_query_rule': 'scheduledQueryRules'}


def disabled_snapshot(families=FAMILIES, history='missing'):
    snapshot = capture(history)
    for family in families:
        collection = next(c for c in snapshot['collections'] if c['type'] == family)
        collection.update(status='collected', items=[{
            'id': SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/' + TYPES[family] + '/disabled',
            'properties': {'enabled': False, 'scopes': [GATEWAY]}}])
    return snapshot


def status(snapshot):
    return verdict(make_snapshot('azure', [SCOPE], snapshot['collections'],
        metadata=snapshot['metadata'], created_at=NOW.isoformat()))


@pytest.mark.parametrize('family', FAMILIES)
@pytest.mark.parametrize('history', ['missing', 'partial', 'denied'])
def test_disabled_rule_with_complete_alert_universe_proves_failure(family, history):
    assert status(disabled_snapshot([family], history)) == 'FAIL'


def test_all_three_families_disabled_prove_failure():
    assert status(disabled_snapshot()) == 'FAIL'


@pytest.mark.parametrize('family', FAMILIES)
def test_enabled_candidate_with_unknown_semantics_keeps_unknown(family):
    snapshot = disabled_snapshot()
    collection = next(c for c in snapshot['collections'] if c['type'] == family)
    collection['items'][0]['properties']['enabled'] = True
    assert status(snapshot) == 'UNKNOWN'


@pytest.mark.parametrize('family', FAMILIES)
@pytest.mark.parametrize('state,expected', [('partial', 'UNKNOWN'), ('denied', 'DENIED')])
def test_incomplete_alert_family_cannot_prove_all_rules_disabled(family, state, expected):
    snapshot = disabled_snapshot()
    collection = next(c for c in snapshot['collections'] if c['type'] == family)
    collection['status'] = state
    if state == 'denied':
        collection['items'] = []
    assert status(snapshot) == expected


@pytest.mark.parametrize('value', ['false', 0, None])
def test_malformed_enabled_value_cannot_be_treated_as_disabled(value):
    snapshot = disabled_snapshot()
    next(c for c in snapshot['collections'] if c['type'] == FAMILIES[0])['items'][0]['properties']['enabled'] = value
    assert status(snapshot) == 'UNKNOWN'
