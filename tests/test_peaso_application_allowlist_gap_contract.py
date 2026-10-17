"""Uncollected external application evidence must remain an explicit gap."""
from peaso.collectors import bulk_evidence
from peaso.snapshot import make_snapshot


def test_allowlist_attestation_routes_as_uncollected_external_evidence():
    scope = '/subscriptions/00000000-0000-0000-0000-000000000001'
    calls = []

    class NativeOnly:
        SUPPORTED_TYPES = {'vm'}

        def collect(self, connector, requirements):
            calls.append((connector, requirements))
            assert requirements == ['vm']
            assert connector['options']['inventories'] == ['vm']
            return make_snapshot('azure', [scope], [{
                'type': 'vm', 'scope': scope, 'status': 'collected', 'items': []}])

    result = bulk_evidence.collect(NativeOnly(), {
        'provider': 'azure', 'scopes': [scope],
        'options': {'inventories': ['vm', 'application_allowlist_attestation']}},
        ['vm', 'application_allowlist_attestation'])
    assert len(calls) == 1
    gap, = [row for row in result['collections'] if row['type'] == 'application_allowlist_attestation']
    assert gap['scope'] == scope
    assert gap['status'] == 'not_collected'
    assert gap['items'] == []
    assert gap['error']['code'] == 'native_evidence_projection_unavailable'
    assert result['metadata']['intentional_partial'] is True
    assert result['metadata']['bulk_evidence']['unavailable_projections'] == ['application_allowlist_attestation']


def test_allowlist_attestation_not_advertised_as_native_inventory():
    coverage = bulk_evidence.coverage()['azure']
    assert 'application_allowlist_attestation' in coverage['unavailable_projections']
    assert 'application_allowlist_attestation' not in coverage['native_types']
    assert 'application_allowlist_attestation' not in coverage['native_aliases']
