"""Unused-object findings remain available through the public offline CLI."""
from copy import deepcopy
import json
import socket

import pytest

from peaso.cli import main
from peaso.snapshot import make_snapshot


@pytest.mark.parametrize('provider,ident', [
    ('aws', 'aws.iam.group_inline_policies_have_members'),
    ('gcp', 'gcp.iam.custom_role_has_declared_grants'),
    ('azure', 'azure.iam.static_group_has_members'),
    ('k8s', 'k8s.iam.role_has_declared_consumers'),
    ('aws', 'aws.network.internet_gateway_attached'),
    ('gcp', 'gcp.network.address_reserved_without_users'),
    ('azure', 'azure.network.route_table_has_subnet_reference'),
    ('k8s', 'k8s.network.networkpolicy_selects_current_pod'),
])
def test_offline_cli_exports_unused_iam_and_network_as_hacktricks_hardening(
    provider, ident, tmp_path, monkeypatch,
):
    from peaso.checks.fixtures import CASES
    case = CASES[ident]
    index = case['fail_index']
    context = index['context']
    collections = [deepcopy(row) for group in index['collections'].values() for row in group]
    snapshot = make_snapshot(provider, [context['scope']], collections,
        created_at=context.get('created_at', '2026-10-21T12:00:00Z'),
        metadata=deepcopy(context.get('metadata', {})))
    source, output = tmp_path / 'snapshot.json', tmp_path / 'report.json'
    source.write_text(json.dumps(snapshot))

    def no_network(*args, **kwargs):
        raise AssertionError('Offline evaluation must not contact a cloud API')

    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'create_connection', no_network)
    assert main(['evaluate', str(source), '--quiet', '--categories', 'hardening',
        '--frameworks', 'hacktricks', '--checks', ident, '--output', str(output)]) == 0
    report = json.loads(output.read_text())
    findings = [row for row in report['findings'] if row['check_id'] == ident]
    assert len(findings) == 1
    finding = findings[0]
    assert finding['status'] == 'FAIL', finding
    assert finding['category'] == 'hardening'
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    assert finding['evidence'], finding
    assert finding['resource_id'], finding
