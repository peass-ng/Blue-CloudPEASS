"""Conclusive LTR misconfiguration is independent of missing copy history."""
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_bulk_native import SCOPE, SQL

CHECK = 'azure.gap.sql_database_long_term_geo_redundant_backup_enabled'


def verdict(snapshot):
    findings = evaluate_snapshot(snapshot, checks=[CHECK], include_not_applicable=True)['findings']
    assert len(findings) == 1
    return findings[0]['status']


def capture(*, enabled=False, copies='not_collected', policy='collected', redundancy=None, primary='collected'):
    rows = [] if redundancy is None else [{
        'id': SQL + '/longTermRetentionBackups/copy', 'parent_id': SQL,
        'properties': {'backupStorageRedundancy': redundancy}}]
    return make_snapshot('azure', [SCOPE], [
        {'type': 'sql_database', 'scope': SCOPE, 'status': primary,
         'items': [{'id': SQL, 'properties': {'status': 'Online'}}] if primary != 'empty' else []},
        {'type': 'sql_database_ltr_policy', 'scope': SCOPE, 'status': policy,
         'items': [{'id': SQL + '/backupLongTermRetentionPolicies/default', 'properties': {
             'weeklyRetention': 'P1W' if enabled else 'P0W',
             'monthlyRetention': 'P0M', 'yearlyRetention': 'P0Y'}}] if policy == 'collected' else []},
        {'type': 'sql_ltr_backup', 'scope': SCOPE, 'status': copies, 'items': rows},
    ])


@pytest.mark.parametrize('history', ['not_collected', 'denied', 'partial'])
def test_native_disabled_retention_fails_without_copy_history(history):
    assert verdict(capture(copies=history)) == 'FAIL'


@pytest.mark.parametrize('redundancy', ['Local', 'Zone'])
def test_native_non_geo_copy_fails_without_retention_policy(redundancy):
    assert verdict(capture(policy='not_collected', copies='collected', redundancy=redundancy)) == 'FAIL'


@pytest.mark.parametrize('history,expected', [('not_collected', 'UNKNOWN'), ('denied', 'DENIED')])
def test_enabled_policy_does_not_pass_without_copy_history(history, expected):
    assert verdict(capture(enabled=True, copies=history)) == expected


@pytest.mark.parametrize('redundancy', ['Geo', 'GeoZone'])
def test_geo_copy_cannot_pass_without_retention_policy(redundancy):
    assert verdict(capture(policy='not_collected', copies='collected', redundancy=redundancy)) == 'UNKNOWN'


def test_incomplete_primary_does_not_prove_failure():
    assert verdict(capture(primary='partial')) == 'UNKNOWN'


def test_authoritative_empty_database_roster_needs_no_child_history():
    assert verdict(capture(primary='empty', policy='not_collected')) == 'NOT_APPLICABLE'
