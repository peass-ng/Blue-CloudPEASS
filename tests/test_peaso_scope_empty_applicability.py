"""Explicit empty applicability cannot bypass missing security evidence."""
from dataclasses import replace

import pytest

from peaso import engine
from peaso.checks import CHECKS
from peaso.snapshot import make_snapshot

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
CHECKS_WITH_EMPTY_PRIMARY = [
    ('azure_recovery_vault_10_3_3_1_1f42f66', 'sql_database'),
    ('azure_recovery_vault_10_3_3_8_26e08d7', 'sql_database'),
    ('azure_nsg_world_ingress_approved_ports', 'nsg'),
    ('azure.other.nsg_port_protocol_assignment', 'nsg'),
]


def status(snapshot, check_id):
    findings = [f for f in engine.evaluate_snapshot(snapshot, checks=[check_id], include_not_applicable=True)['findings']
                if f['check_id'] == check_id]
    assert len(findings) == 1
    return findings[0]['status']


@pytest.mark.parametrize('check_id,kind', CHECKS_WITH_EMPTY_PRIMARY)
def test_complete_empty_primary_reaches_existing_not_applicable_predicate(check_id, kind):
    snapshot = make_snapshot('azure', [SCOPE], [{'type': kind, 'scope': SCOPE, 'status': 'empty', 'items': []}])
    assert status(snapshot, check_id) == 'NOT_APPLICABLE'


@pytest.mark.parametrize('observed,expected', [('PASS', 'UNKNOWN'), ('FAIL', 'UNKNOWN'), ('NOT_APPLICABLE', 'NOT_APPLICABLE')])
def test_empty_opt_in_can_accept_only_not_applicable(monkeypatch, observed, expected):
    original = next(c for c in CHECKS if c.id == 'azure_nsg_world_ingress_approved_ports')
    prototype = replace(original, declared_dependencies=('nsg', 'missing_child'), allow_incomplete_failure=False,
                        empty_applicability_dependencies=('nsg',), evaluate=lambda item, index: (observed, {'reason': 'fixture'}))
    monkeypatch.setattr(engine, '_registry', lambda: [prototype])
    snapshot = make_snapshot('azure', [SCOPE], [{'type': 'nsg', 'scope': SCOPE, 'status': 'empty', 'items': []}])
    assert status(snapshot, prototype.id) == expected


@pytest.mark.parametrize('primary,expected', [('partial', 'UNKNOWN'), ('denied', 'DENIED'), ('collected', 'UNKNOWN')])
def test_unproved_or_nonempty_roster_never_authorizes_applicability(monkeypatch, primary, expected):
    original = next(c for c in CHECKS if c.id == 'azure_nsg_world_ingress_approved_ports')
    calls = []
    def evaluate(item, index):
        calls.append(True)
        return 'NOT_APPLICABLE', {'reason': 'fixture'}
    prototype = replace(original, declared_dependencies=('nsg', 'missing_child'), allow_incomplete_failure=False,
                        empty_applicability_dependencies=('nsg',), evaluate=evaluate)
    monkeypatch.setattr(engine, '_registry', lambda: [prototype])
    rows = [{'id': SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg'}] if primary == 'collected' else []
    snapshot = make_snapshot('azure', [SCOPE], [{'type': 'nsg', 'scope': SCOPE, 'status': primary, 'items': rows}])
    assert status(snapshot, prototype.id) == expected
    assert calls == []


def test_unopted_check_retains_original_dependency_guard(monkeypatch):
    original = next(c for c in CHECKS if c.id == 'azure_nsg_world_ingress_approved_ports')
    calls = []
    def evaluate(item, index):
        calls.append(True)
        return 'NOT_APPLICABLE', {}
    prototype = replace(original, empty_applicability_dependencies=(), evaluate=evaluate)
    monkeypatch.setattr(engine, '_registry', lambda: [prototype])
    snapshot = make_snapshot('azure', [SCOPE], [{'type': 'nsg', 'scope': SCOPE, 'status': 'empty', 'items': []}])
    assert status(snapshot, prototype.id) == 'UNKNOWN' and calls == []


def test_existing_mysql_resource_check_preserves_empty_semantics():
    snapshot = make_snapshot('azure', [SCOPE], [{'type': 'mysql_single_server', 'scope': SCOPE, 'status': 'empty', 'items': []}])
    assert status(snapshot, 'azure.cis.mysql_single_audit_log_enabled') == 'EMPTY'


@pytest.mark.parametrize('target,declared,empty', [
    ('resource', ['nsg'], ['nsg']), ('scope', ['nsg'], ['unrelated']),
    ('scope', ['nsg'], ['nsg', 'nsg']),
])
def test_registry_rejects_invalid_applicability_opt_ins(target, declared, empty):
    from peaso.checks import register
    with pytest.raises(ValueError):
        register('fixture.invalid.empty_opt_in', 'azure', 'hardening', 'nsg', 'fixture', 'low', 'CM-6',
                 'fixture', target=target, dependencies=declared, empty_applicability_dependencies=empty)


@pytest.mark.parametrize('check_id', ['azure_nsg_world_ingress_approved_ports', 'azure.other.nsg_port_protocol_assignment'])
def test_actual_collector_empty_nsg_remains_not_applicable(monkeypatch, check_id):
    from peaso.collectors import azure, collect_live
    from tests.test_peaso_azure_bulk_native import Transport, SUB
    api = Transport({})
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda c, kinds: original(c, kinds, transport=api))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0}},
                            ['nsg', 'nsg_effective_internet_path', 'nsg_service_measurement'])
    assert status(snapshot, check_id) == 'NOT_APPLICABLE'
    assert any(c['type'] == 'nsg' and c['status'] == 'empty' for c in snapshot['collections'])
