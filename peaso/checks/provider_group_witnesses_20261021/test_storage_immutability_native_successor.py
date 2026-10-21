"""Offline acceptance matrix for a review-only current native successor."""
from copy import deepcopy
import socket

import pytest

from peaso import checks, engine
from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot
from tests.test_peaso_azure_bulk_native import Transport, SUB, STORAGE
from tests.test_peaso_azure_storage_recovery_metadata_native import storage_case

from storage_immutability_native_successor import proposed_registry, reviewed_source, evaluate

CHECK = 'azure_storage_account_10_3_4_7_02943e9'


def test_single_check_isolation_and_reviewed_source():
    original = reviewed_source()
    proposal = proposed_registry(checks.CHECKS)
    assert len(proposal) == len(checks.CHECKS)
    assert next(c for c in proposal if c.id == CHECK).evaluate is evaluate
    assert next(c for c in checks.CHECKS if c.id == CHECK) is original
    assert all(new is old for new, old in zip(proposal, checks.CHECKS) if old.id != CHECK)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('unexpected real network or credential call')
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(azure, 'credential_for', forbidden)


def run_case(monkeypatch, mode, mutation=None, source_mutation=None, successor=True):
    routes = storage_case(mode)
    if source_mutation:
        source_mutation(routes)
    http = Transport(routes)
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda connector, kinds: original(connector, kinds, transport=http))
    connector = {'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0}}
    snapshot = collect_live(connector, ['storage_account', 'storage_immutability_evidence'])
    if mutation:
        mutation(snapshot)
        snapshot.pop('snapshot_id', None)
    check = next(c for c in checks.CHECKS if c.id == CHECK)
    if successor:
        monkeypatch.setattr(engine, '_registry', lambda: proposed_registry(checks.CHECKS))
    rows = evaluate_snapshot(snapshot, checks=[CHECK], include_not_applicable=True)['findings']
    assert len(rows) == 1, rows
    return rows[0]['status'], snapshot


def test_current_frozen_check_still_requires_owner_approval(monkeypatch):
    assert run_case(monkeypatch, 'good', successor=False)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mode,expected', [
    ('good', 'PASS'), ('time_policy', 'PASS'), ('container_policy', 'PASS'),
    ('absent', 'FAIL'), ('disabled', 'FAIL'), ('container_disabled_override', 'FAIL'),
    ('no_containers', 'NOT_APPLICABLE'), ('missing_account_mode', 'UNKNOWN'),
    ('missing_container_mode', 'UNKNOWN'), ('missing_presence', 'UNKNOWN'),
    ('policy_get_denied', 'UNKNOWN'), ('container_get_denied', 'UNKNOWN'),
    ('list_denied', 'UNKNOWN'), ('partial_page', 'UNKNOWN'),
    ('foreign_container', 'UNKNOWN'), ('duplicate_container', 'UNKNOWN'),
    ('embedded_conflict', 'UNKNOWN'), ('migration', 'UNKNOWN'),
])
def test_current_native_without_customer_attestation(monkeypatch, mode, expected):
    actual, snapshot = run_case(monkeypatch, mode)
    assert actual == expected
    evidence = next(c for c in snapshot['collections'] if c['type'] == 'storage_immutability_evidence')
    if expected == 'PASS':
        assert evidence['items'][0]['_provenance']['policy_approved'] is False


def test_foreign_parent_and_partial_projection_fail_closed(monkeypatch):
    def foreign(snapshot):
        row = next(c for c in snapshot['collections'] if c['type'] == 'storage_immutability_evidence')['items'][0]
        row['parent_id'] = row['parent_id'].replace('/storageAccounts/', '/storageAccounts/foreign-')
    assert run_case(monkeypatch, 'good', foreign)[0] == 'UNKNOWN'


def test_missing_evidence_fails_closed(monkeypatch):
    def missing(snapshot):
        snapshot['collections'] = [c for c in snapshot['collections'] if c['type'] != 'storage_immutability_evidence']
    assert run_case(monkeypatch, 'good', missing)[0] == 'UNKNOWN'


@pytest.mark.parametrize('state,expected', [('Locked', 'PASS'), ('Unlocked', 'PASS'),
                                            ('Disabled', 'FAIL'), ('unexpected', 'UNKNOWN')])
def test_official_policy_state_from_account_get(monkeypatch, state, expected):
    def change(routes):
        routes[STORAGE]['properties']['immutableStorageWithVersioning']['immutabilityPolicy']['state'] = state
    assert run_case(monkeypatch, 'good', source_mutation=change)[0] == expected


@pytest.mark.parametrize('field,value', [
    ('read_only', False), ('complete', False), ('schema_version', 2),
    ('source_operation', 'owner.review'), ('captured_at', '2020-01-01T00:00:00Z'),
])
def test_mutated_provenance_is_unknown(monkeypatch, field, value):
    def mutate(snapshot):
        row = next(c for c in snapshot['collections'] if c['type'] == 'storage_immutability_evidence')['items'][0]
        row['_provenance'][field] = value
    assert run_case(monkeypatch, 'good', mutate)[0] == 'UNKNOWN'


def test_read_only_source_cannot_be_replaced_by_approval(monkeypatch):
    def mutate(snapshot):
        row = next(c for c in snapshot['collections'] if c['type'] == 'storage_immutability_evidence')['items'][0]
        row['_provenance'].update(read_only=False, policy_approved=True)
    assert run_case(monkeypatch, 'good', mutate)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field,value', [
    ('source_kind', 'foreign'), ('source_id', '/subscriptions/foreign'),
    ('new_writes_inherit', False),
])
def test_effective_policy_source_conflict(monkeypatch, field, value):
    def mutate(snapshot):
        row = next(c for c in snapshot['collections'] if c['type'] == 'storage_immutability_evidence')['items'][0]
        policy = row['payload']['containers']['items'][0]['effective_default_policy']
        policy[field] = value
    expected = 'FAIL' if field == 'new_writes_inherit' else 'UNKNOWN'
    assert run_case(monkeypatch, 'good', mutate)[0] == expected
