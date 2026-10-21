from copy import deepcopy

import pytest

from peaso.iam_usage_evidence import inactivity, legacy_token_usage

NOW = '2026-10-21T12:00:00Z'
CREATED = '2025-01-01T00:00:00Z'


def usage(**overrides):
    return inactivity(**({'created_at': CREATED, 'observed_at': NOW,
                          'observation_start': '2026-01-01T00:00:00Z', 'complete_usage': True} | overrides))


def test_recent_positive_survives_partial_history():
    status, evidence = usage(last_successful_use='2026-10-20T12:00:00Z', complete_usage=False, observation_start=None)
    assert status == 'PASS'
    assert evidence['days_since_last_successful_use'] == 1


def test_old_success_reports_exact_days_only_with_sufficient_coverage():
    status, evidence = usage(last_successful_use='2026-01-01T12:00:00Z')
    assert status == 'FAIL'
    assert evidence['days_since_last_successful_use'] == 293


@pytest.mark.parametrize('overrides', [
    {'complete_usage': False}, {'observation_start': None},
    {'observation_start': '2026-10-01T00:00:00Z'},
])
def test_partial_absence_cannot_establish_inactivity(overrides):
    assert usage(**overrides)[0] == 'UNKNOWN'


def test_old_creation_alone_does_not_establish_unused():
    assert usage(observation_start=None, complete_usage=False)[0] == 'UNKNOWN'


def test_new_object_is_not_falsely_old_when_no_use_is_recorded():
    status, evidence = usage(created_at='2026-10-20T12:00:00Z', complete_usage=False, observation_start=None)
    assert status == 'PASS'
    assert evidence['object_age_days'] == 1
    assert 'days_since_last_successful_use' not in evidence


def test_complete_absence_reports_window_not_fabricated_last_use():
    status, evidence = usage()
    assert status == 'FAIL'
    assert evidence['no_successful_use_observed_days'] == 293
    assert 'days_since_last_successful_use' not in evidence
    assert evidence['last_successful_use'] is None


@pytest.mark.parametrize('overrides', [
    {'last_successful_use': '2027-01-01T00:00:00Z'},
    {'last_successful_use': '2024-01-01T00:00:00Z'},
    {'created_at': '2027-01-01T00:00:00Z'},
    {'observed_at': '2026-10-21T12:00:00'},
    {'observation_start': '2027-01-01T00:00:00Z'},
    {'threshold_days': True}, {'threshold_days': -1}, {'enabled': 'false'},
    {'complete_usage': 'true'}, {'last_successful_use': 'bad'},
])
def test_malformed_or_contradictory_activity_is_unknown(overrides):
    assert usage(**overrides)[0] == 'UNKNOWN'


def test_exact_day_threshold_is_not_more_than_threshold():
    assert usage(last_successful_use='2026-07-23T12:00:00Z')[0] == 'PASS'
    assert usage(observation_start='2026-07-23T12:00:00Z')[0] == 'UNKNOWN'
    assert usage(observation_start='2026-07-23T11:59:59Z')[0] == 'FAIL'


def test_disabled_object_has_explicit_state():
    assert usage(enabled=False)[0] == 'NOT_APPLICABLE'


SA = {'metadata': {'name': 'worker', 'namespace': 'app', 'uid': 'synthetic-sa-uid'}, 'secrets': [{'name': 'legacy'}]}


def token(last='2026-01-01'):
    return {'type': 'kubernetes.io/service-account-token', 'metadata': {
        'name': 'legacy', 'namespace': 'app', 'uid': 'synthetic-token-uid',
        'creationTimestamp': CREATED,
        'annotations': {'kubernetes.io/service-account.name': 'worker', 'kubernetes.io/service-account.uid': 'synthetic-sa-uid'},
        'labels': {'kubernetes.io/legacy-token-last-used': last}}}


def test_kubernetes_uses_metadata_without_reading_or_emitting_token_data():
    item = token()
    item['data'] = {'token': 'MUST_NOT_BE_READ_OR_EMITTED'}
    before = deepcopy(item)
    status, evidence = legacy_token_usage(item, observed_at=NOW, service_account=SA)
    assert status == 'FAIL'
    assert evidence['resource_name'] == 'app/legacy'
    assert evidence['last_used_date'] == '2026-01-01'
    assert evidence['timestamp_precision'] == 'UTC calendar day'
    assert 'MUST_NOT_BE_READ_OR_EMITTED' not in str(evidence)
    assert item == before


@pytest.mark.parametrize('last', [None, '', 'invalid', '2026-02-30', '2027-01-01'])
def test_missing_or_invalid_legacy_token_tracking_is_unknown(last):
    assert legacy_token_usage(token(last), observed_at=NOW, service_account=SA)[0] == 'UNKNOWN'


def test_legacy_token_boundary_uses_end_of_day():
    assert legacy_token_usage(token('2026-07-23'), observed_at=NOW, service_account=SA)[0] == 'PASS'
    assert legacy_token_usage(token('2026-07-22'), observed_at=NOW, service_account=SA)[0] == 'FAIL'


def test_non_token_secret_is_not_applicable():
    item = token()
    item['type'] = 'Opaque'
    assert legacy_token_usage(item, observed_at=NOW, service_account=SA)[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('sa', [None, {}, {'metadata': SA['metadata'], 'secrets': []},
    {'metadata': dict(SA['metadata'], namespace='other'), 'secrets': SA['secrets']},
    {'metadata': dict(SA['metadata'], uid='recreated-sa'), 'secrets': SA['secrets']}])
def test_unbound_manual_or_foreign_token_cannot_be_called_unused(sa):
    assert legacy_token_usage(token(), observed_at=NOW, service_account=sa)[0] == 'UNKNOWN'
