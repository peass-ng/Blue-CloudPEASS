"""Native firewall response-to-finding matrix for every port-specific control.

Checks declared rules only. This does not simulate routing or effective reachability.
Reference: https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list
"""
from copy import deepcopy
import socket

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.checks.claude_gcp_k8s_compute import FIREWALL_PORTS, FIREWALL_PORT_IDS
from tests.test_peaso_collectors_gcp import snapshot

SCOPE = 'projects/p-one'
ENDPOINT = 'https://compute.googleapis.com/compute/v1/projects/p-one/global/firewalls'
SCENARIOS = [
    ('public_v4', 'FAIL'), ('public_v6', 'FAIL'), ('private_v4', 'PASS'),
    ('different_port', 'PASS'), ('all_ports', 'FAIL'), ('numeric_protocol', 'FAIL'),
    ('all_protocols', 'FAIL'), ('disabled', 'NOT_APPLICABLE'),
    ('egress', 'NOT_APPLICABLE'), ('invalid_port', 'UNKNOWN'),
    ('denied_field', 'UNKNOWN'), ('denied_inventory', 'DENIED'),
]


@pytest.fixture(autouse=True)
def forbid_provider_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('This review must not use network or real credentials')
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)


@pytest.mark.parametrize('suffix', sorted(FIREWALL_PORT_IDS))
@pytest.mark.parametrize('scenario,expected', SCENARIOS)
def test_native_port_rule_roundtrip(suffix, scenario, expected):
    ports, protocols = FIREWALL_PORTS[suffix]
    rule = {'kind': 'compute#firewall', 'id': '10001', 'name': 'port-review',
            'selfLink': ENDPOINT + '/port-review',
            'network': 'https://compute.googleapis.com/compute/v1/projects/p-one/global/networks/review',
            'direction': 'INGRESS', 'priority': 1000, 'disabled': False,
            'sourceRanges': ['0.0.0.0/0'],
            'allowed': [{'IPProtocol': protocols[0], 'ports': [str(ports[0])]}]}
    if scenario == 'public_v6': rule['sourceRanges'] = ['::/0']
    elif scenario == 'private_v4': rule['sourceRanges'] = ['10.0.0.0/8']
    elif scenario == 'different_port': rule['allowed'][0]['ports'] = ['65535']
    elif scenario == 'all_ports': rule['allowed'][0].pop('ports')
    elif scenario == 'numeric_protocol':
        rule['allowed'][0]['IPProtocol'] = {'tcp': '6', 'udp': '17'}[protocols[0]]
    elif scenario == 'all_protocols': rule['allowed'] = [{'IPProtocol': 'all'}]
    elif scenario == 'disabled': rule['disabled'] = True
    elif scenario == 'egress':
        rule['direction'] = 'EGRESS'; rule.pop('sourceRanges'); rule['destinationRanges'] = ['0.0.0.0/0']
    elif scenario == 'invalid_port': rule['allowed'][0]['ports'] = ['70000']
    original = deepcopy(rule)

    def resolve(request):
        assert request['method'] == 'GET' and request['url'] == ENDPOINT
        if scenario == 'denied_inventory':
            raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        return {'kind': 'compute#firewallList', 'items': [rule]}

    collected, transport = snapshot(['firewall'], resolve, scopes=[SCOPE])
    assert rule == original and len(transport.requests) == 1
    if scenario == 'denied_field':
        collected['collections'][0]['items'][0].setdefault('_coverage', {})['allowed'] = {'status': 'denied'}
        collected.pop('snapshot_id', None)
    before = deepcopy(collected)
    cid = FIREWALL_PORT_IDS[suffix]
    findings = evaluate_snapshot(collected, checks=[cid])['findings']
    assert collected == before
    assert len(findings) == 1 and findings[0]['check_id'] == cid
    assert findings[0]['status'] == expected, findings[0]
    if expected in ('PASS', 'FAIL'):
        assert findings[0]['evidence']['ports'] == ports
        assert 'matching_allow_entries' in findings[0]['evidence']
