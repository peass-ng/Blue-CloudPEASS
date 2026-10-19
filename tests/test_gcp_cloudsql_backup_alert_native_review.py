"""Native declarations; no synthetic truth marker or cloud mutation."""
from copy import deepcopy

import pytest

from peaso.checks.facts import Unavailable
from peaso.checks.gcp_cloudsql_backup_alert_native import EXPECTED, configured_alerts, matches_failed_window

SCOPE = 'projects/123'
PROJECT = {'name': SCOPE, 'projectId': 'review-project'}
FILTER = ' AND '.join(f'{key}="{value}"' for key, value in EXPECTED.items())


def policy():
    return {'name': SCOPE + '/alertPolicies/backup', 'enabled': True,
            'conditions': [{'conditionMatchedLog': {'filter': FILTER}}]}


def metric():
    return {'name': SCOPE + '/metrics/failed-backup', 'metricId': 'failed-backup',
            'filter': FILTER, 'metricDescriptor': {'type': 'logging.googleapis.com/user/failed-backup',
                                                  'metricKind': 'DELTA', 'valueType': 'INT64'}}


def threshold_policy():
    alert = policy()
    alert['conditions'] = [{'conditionThreshold': {
        'filter': 'metric.type="logging.googleapis.com/user/failed-backup"',
        'comparison': 'COMPARISON_GT', 'duration': '0s'}}]
    return alert


@pytest.mark.parametrize('separator', [' AND ', '\n', '  '])
def test_native_conjunction_accepts_reordering_and_implicit_and(separator):
    expression = separator.join(f'{key} = "{value}"' for key, value in reversed(EXPECTED.items()))
    assert matches_failed_window(expression) is True


@pytest.mark.parametrize('expression', [FILTER + ' AND ', FILTER + ' OR true',
    FILTER + ' AND resource.labels.database_id="only-one"',
    FILTER + ' AND severity=ERROR', FILTER + ' AND resource.type="cloudsql_database"',
    '(' + FILTER + ')', '', 'filterMatchesFailedCloudSqlBackupRun=true'])
def test_restrictions_or_unproved_syntax_never_prove_coverage(expression):
    assert matches_failed_window(expression) is None


@pytest.mark.parametrize('status', ['STATUS_ATTEMPT_FAILED', 'STATUS_SUCCEEDED', 'STATUS_SKIPPED'])
def test_recoverable_attempt_failure_is_not_final_window_failure(status):
    assert matches_failed_window(FILTER.replace('STATUS_FAILED', status)) is False


def test_native_log_alert_and_metric_alert_are_independent_supported_paths():
    assert configured_alerts(PROJECT, SCOPE, [policy()], []) == [policy()['name']]
    assert configured_alerts(PROJECT, SCOPE, [threshold_policy()], [metric()]) == [policy()['name']]


def test_alias_from_independent_project_metadata_is_accepted():
    alert = policy()
    alert['name'] = 'projects/review-project/alertPolicies/backup'
    assert configured_alerts(PROJECT, SCOPE, [alert], []) == [alert['name']]


@pytest.mark.parametrize('change', ['foreign', 'restricted', 'and_combiner', 'missing_conditions'])
def test_alert_uncertainty_does_not_become_pass(change):
    alert = policy()
    if change == 'foreign': alert['name'] = 'projects/other/alertPolicies/backup'
    if change == 'restricted': alert['conditions'][0]['conditionMatchedLog']['filter'] += ' AND severity=ERROR'
    if change == 'and_combiner':
        alert['conditions'].append({'conditionMatchedLog': {'filter': FILTER}})
        alert['combiner'] = 'AND'
    if change == 'missing_conditions': alert['conditions'] = []
    with pytest.raises(Unavailable): configured_alerts(PROJECT, SCOPE, [alert], [])


@pytest.mark.parametrize('key,value', [('comparison', 'COMPARISON_LT'), ('thresholdValue', 10),
    ('thresholdValue', True), ('thresholdValue', float('nan')), ('duration', '600s'),
    ('aggregations', [{'perSeriesAligner': 'ALIGN_MEAN'}]), ('trigger', {'count': 3}),
    ('trigger', {'count': True}),
    ('denominatorFilter', 'metric.type="other"'), ('forecastOptions', {})])
def test_threshold_semantics_need_positive_native_proof(key, value):
    alert = threshold_policy()
    alert['conditions'][0]['conditionThreshold'][key] = value
    with pytest.raises(Unavailable): configured_alerts(PROJECT, SCOPE, [alert], [metric()])


@pytest.mark.parametrize('key,value', [('metricKind', 'GAUGE'), ('valueType', 'DISTRIBUTION'),
                                     ('type', 'logging.googleapis.com/user/other')])
def test_only_native_integer_delta_counters_prove_any_failure_alert(key, value):
    row = metric()
    row['metricDescriptor'][key] = value
    with pytest.raises(Unavailable): configured_alerts(PROJECT, SCOPE, [threshold_policy()], [row])


def test_disabled_and_absent_local_declarations_are_not_a_configured_alert():
    alert = policy()
    alert['enabled'] = False
    assert configured_alerts(PROJECT, SCOPE, [alert], []) == []
    assert configured_alerts(PROJECT, SCOPE, [], []) == []


def test_missing_enabled_boolvalue_cannot_be_interpreted_as_disabled():
    alert = policy()
    del alert['enabled']
    with pytest.raises(Unavailable): configured_alerts(PROJECT, SCOPE, [alert], [])


def test_invalid_enabled_policy_is_not_a_working_alert_declaration():
    alert = policy()
    alert['validity'] = {'code': 3, 'message': 'Invalid condition'}
    assert configured_alerts(PROJECT, SCOPE, [alert], []) == []


def test_logmatch_cannot_be_combined_with_other_conditions_even_with_or():
    alert = policy()
    alert['conditions'].append({'conditionMatchedLog': {'filter': FILTER}})
    alert['combiner'] = 'OR'
    with pytest.raises(Unavailable): configured_alerts(PROJECT, SCOPE, [alert], [])


def test_unrelated_unsupported_policy_does_not_erase_supported_positive_proof():
    alert = policy()
    other = deepcopy(alert)
    other['conditions'][0]['conditionMatchedLog']['filter'] = 'severity>=ERROR'
    assert configured_alerts(PROJECT, SCOPE, [other, alert], []) == [alert['name']]


def observed(alerts, metrics=(), *, denied=None):
    """Actual installed collector and engine; only native API transport is mocked."""
    from tests.test_peaso_collectors_gcp import snapshot
    from peaso.collectors.gcp import ReadError
    from peaso.engine import evaluate_snapshot

    def resolve(request):
        url = request['url']
        if denied and url.endswith('/' + denied):
            raise ReadError('denied', {'code': 'fixture_denied'})
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            return dict(PROJECT)
        if url == 'https://compute.googleapis.com/compute/v1/' + SCOPE:
            return {}
        if url.endswith(':getAncestry'):
            return {'ancestor': [{'resourceId': {'type': 'project', 'id': '123'}}]}
        if url.endswith('/metrics'):
            assert 'metricKind,valueType' in request['params']['fields']
            return {'metrics': [{**row, 'name': row['metricId']} for row in metrics]}
        if url.endswith('/alertPolicies'):
            assert 'validity' in request['params']['fields']
            return {'alertPolicies': alerts}
        raise AssertionError('Unexpected cloud API: ' + url)

    native, transport = snapshot(['project', 'logging_metric', 'monitoring_alert_policy'],
                                  resolve, scopes=[SCOPE], metrics_scopes=False)
    findings = evaluate_snapshot(native, checks=['gcp_cloudsql_backup_failure_alert'])['findings']
    assert len(findings) == 1
    assert all(row['method'] == 'GET' or row['url'].endswith(':getAncestry')
               for row in transport.requests)
    return native, findings[0]


@pytest.mark.parametrize('mode,expected', [('direct', 'PASS'), ('counter', 'PASS'),
    ('absent', 'FAIL'), ('disabled', 'FAIL'), ('invalid', 'FAIL'), ('missing_enabled', 'UNKNOWN'),
    ('restricted', 'UNKNOWN'), ('denied', 'UNKNOWN')])
def test_installed_native_pipeline(mode, expected):
    alert, metrics = policy(), []
    if mode == 'counter': alert, metrics = threshold_policy(), [metric()]
    if mode == 'disabled': alert['enabled'] = False
    if mode == 'invalid': alert['validity'] = {'code': 3, 'message': 'Invalid condition'}
    if mode == 'missing_enabled': del alert['enabled']
    if mode == 'restricted': alert['conditions'][0]['conditionMatchedLog']['filter'] += ' AND severity=ERROR'
    _, finding = observed([] if mode == 'absent' else [alert], metrics,
                          denied='alertPolicies' if mode == 'denied' else None)
    assert finding['status'] == expected, finding
    if expected != 'UNKNOWN':
        assert finding['evidence']['notification_delivery_assessed'] is False
