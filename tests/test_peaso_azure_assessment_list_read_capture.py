"""Normal Azure assessment LIST response capture, without guest-scan claims."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
VM = SCOPE + '/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'
LIST = SCOPE + '/providers/Microsoft.Security/assessments'


def assessment(name='stable-key', status='Healthy'):
    return {'id': VM + '/providers/Microsoft.Security/assessments/' + name,
            'name': name, 'type': 'Microsoft.Security/assessments',
            'properties': {'resourceDetails': {'source': 'Azure', 'id': VM},
                           'status': {'code': status}}}


class Transport:
    tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'

    def __init__(self, listing):
        self.listing = listing
        self.calls = []

    def close(self):
        pass

    def request(self, url, *, body=None, audience=azure.ARM):
        assert body is None
        self.calls.append(url)
        path = urlsplit(url).path
        if path == SCOPE + '/providers/Microsoft.Compute/virtualMachines':
            return {'value': [{'id': VM, 'name': 'vm',
                'type': 'Microsoft.Compute/virtualMachines',
                'properties': {'storageProfile': {'osDisk': {'osType': 'Linux'}}}}]}
        if path == VM:
            return {'id': VM, 'name': 'vm', 'type': 'Microsoft.Compute/virtualMachines',
                    'properties': {'storageProfile': {'osDisk': {'osType': 'Linux'}}}}
        if path == LIST:
            response = self.listing(url) if callable(self.listing) else self.listing
            if isinstance(response, Exception):
                raise response
            return copy.deepcopy(response)
        return {'value': []}


def collect(listing):
    api = Transport(listing)
    snapshot = azure.collect({'scopes': [SCOPE], 'options': {'retries': 0}},
                             ['vm', 'security_assessment'], transport=api)
    envelope = next(c for c in snapshot['collections'] if c['type'] == 'security_assessment')
    return snapshot, envelope, api


def test_list_capture_is_actual_read_only_page_proof_with_scope_and_bindings():
    start = datetime.now(timezone.utc)
    snapshot, envelope, api = collect({'value': [assessment()]})
    row = envelope['items'][0]
    proof = row['_provenance']
    assert envelope['status'] == 'collected' and proof['source_operation'] == 'Assessments_List'
    assert proof['read_only'] is True and proof['api_version'] == '2020-01-01'
    assert proof['representation'] == 'metadata' and proof['scope'] == SCOPE
    assert proof['credential_context_id'] == snapshot['metadata']['credential_context_id']
    assert proof['customer_context_id'] == snapshot['metadata']['customer_context_id']
    assert start <= datetime.fromisoformat(proof['observed_at']) <= datetime.now(timezone.utc)
    assert row['properties']['status']['code'] == 'Healthy'
    assert len([url for url in api.calls if urlsplit(url).path == LIST]) == 1
    assert not {'applicable', 'rule_set_complete', 'guest_scanned_at'} & proof.keys()


def test_http_body_cannot_supply_or_override_assessment_list_capture():
    row = assessment(status='Unhealthy')
    row['_provenance'] = {'source_operation': 'Forged', 'observed_at': '2099-01-01T00:00:00Z',
                          'read_only': False, 'credential_context_id': 'other'}
    _, envelope, _ = collect({'value': [row]})
    actual = envelope['items'][0]
    assert actual['_provenance']['source_operation'] == 'Assessments_List'
    assert actual['_provenance']['read_only'] is True
    assert actual['_provenance']['observed_at'] != '2099-01-01T00:00:00Z'
    assert actual['properties']['status']['code'] == 'Unhealthy'


@pytest.mark.parametrize('mode', ['denied_first', 'denied_next', 'foreign_next'])
def test_list_read_failure_or_foreign_page_never_makes_complete_assessment_inventory(mode):
    def listing(url):
        if mode == 'denied_first':
            return azure.AzureReadError('forbidden', 403)
        if 'page=2' in url:
            if mode == 'denied_next':
                return azure.AzureReadError('forbidden', 403)
            foreign = assessment(); foreign['id'] = foreign['id'].replace(SCOPE, '/subscriptions/foreign')
            return {'value': [foreign]}
        return {'value': [assessment()], 'nextLink': azure.ARM + LIST + '?page=2'}
    _, envelope, api = collect(listing)
    assert envelope['status'] == ('denied' if mode == 'denied_first' else 'partial')
    assert len(envelope['items']) == (0 if mode == 'denied_first' else 1)
    if envelope['items']:
        assert envelope['items'][0]['_provenance']['source_operation'] == 'Assessments_List'
    assert len([url for url in api.calls if urlsplit(url).path == LIST]) <= 2


def test_completed_empty_list_has_no_synthetic_assessment_or_host_claim():
    _, envelope, api = collect({'value': []})
    assert envelope['status'] == 'empty' and envelope['items'] == []
    assert len([url for url in api.calls if urlsplit(url).path == LIST]) == 1


def test_paginated_list_stamps_each_distinct_page_without_extra_calls():
    def listing(url):
        if 'page=2' in url:
            return {'value': [assessment('second-key', 'Unhealthy')]}
        return {'value': [assessment()], 'nextLink': azure.ARM + LIST + '?page=2'}
    snapshot, envelope, api = collect(listing)
    assert envelope['status'] == 'collected' and len(envelope['items']) == 2
    assert [row['name'] for row in envelope['items']] == ['stable-key', 'second-key']
    for row in envelope['items']:
        proof = row['_provenance']
        assert proof['source_operation'] == 'Assessments_List'
        assert proof['scope'] == SCOPE
        assert proof['customer_context_id'] == snapshot['metadata']['customer_context_id']
    assert len([url for url in api.calls if urlsplit(url).path == LIST]) == 2


def test_unchanged_cached_list_response_cannot_be_reissued_as_fresh_scan_proof():
    row = assessment()
    response = {'value': [row], 'nextLink': azure.ARM + LIST + '?api-version=2020-01-01'}
    _, envelope, api = collect(response)
    assert envelope['status'] == 'partial'
    assert envelope['items'][0]['_provenance']['source_operation'] == 'Assessments_List'
    assert len([url for url in api.calls if urlsplit(url).path == LIST]) == 1


