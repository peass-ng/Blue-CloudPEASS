"""The password baseline receives native domain metadata, never invented IdP facts."""
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from tests.test_peaso_collectors_azurek8s import FakeAzure

TENANT = '22222222-2222-2222-2222-222222222222'
SCOPE = '/tenants/' + TENANT
CID = 'azure.other.entra_password_baseline'


@pytest.mark.parametrize('mode', ['managed', 'federated', 'omitted', 'injected', 'denied', 'partial', 'unverified'])
def test_normal_domain_metadata_keeps_baseline_unknown_without_provisioning_and_effective_policy(monkeypatch, mode, approved_review=False):
    row = {'id': 'example.test', 'authenticationType': 'Federated' if mode == 'federated' else 'Managed',
           'isVerified': True}
    if mode != 'omitted':
        row.update(passwordValidityPeriodInDays=120, passwordNotificationWindowInDays=14)
    if mode == 'injected':
        row.update(newlyProvisionedIdentities=[], effectivePasswordPolicies=[])
    def response(url, body, audience):
        assert body is None and audience == azure.GRAPH
        parsed = urlsplit(url)
        assert parsed.path == '/v1.0/domains'
        fields = set(parse_qs(parsed.query)['$select'][0].split(','))
        assert {'id', 'authenticationType', 'passwordValidityPeriodInDays', 'passwordNotificationWindowInDays'} <= fields
        assert 'passwordPolicies' not in fields
        if mode == 'denied': raise azure.AzureReadError('fixture_graph_access_denied', 403)
        result = {'value': [deepcopy(row)]}
        if mode == 'partial': result['@odata.nextLink'] = url + '&$skiptoken=next'
        return result
    transport = FakeAzure(response)
    transport.tenant = TENANT
    transport.verified_tenant = None if mode == 'unverified' else TENANT
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda connector, kinds: original(connector, kinds, transport=transport))
    auth = {'method': 'token', 'arm_token': 'inert', 'graph_token': 'inert', 'tenant_id': TENANT}
    options = {'retries': 1, **({'max_pages': 1} if mode == 'partial' else {})}
    if approved_review:
        options['compliance_policy'] = {'sw21': {'status': 'collected', 'scope': SCOPE,
            'passwords': {'approvedPasswordBaseline': {
                'complexity': {'equals': True}, 'lockoutThreshold': {'maximum': 10}}}}}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'azure', 'scopes': ['/subscriptions/11111111-1111-1111-1111-111111111111'], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CID]})
    assert requirements == ['entra_domain']
    snapshot = collect_live(connector, requirements)
    source = next(c for c in snapshot['collections'] if c['type'] == 'directory_domain')
    projected = next(c for c in snapshot['collections'] if c['type'] == 'entra_domain')
    assert projected['source_inventory'] == 'directory_domain'
    assert projected['scope'] == source['scope'] == SCOPE
    state = 'denied' if mode == 'denied' else 'partial' if mode == 'partial' else 'collected'
    assert source['status'] == projected['status'] == state
    assert len(projected['items']) == (0 if mode == 'denied' else 1)
    for domain in projected['items']:
        assert domain['id'] == 'example.test'
        assert domain['_provenance']['tenant_id'] == TENANT
        assert domain['_provenance']['tenant_verified'] is (mode != 'unverified')
        for field in ('newlyProvisionedIdentities', 'effectivePasswordPolicies'):
            assert field not in domain and domain['_coverage'][field]['status'] == 'not_collected'
        if mode == 'omitted':
            assert 'passwordValidityPeriodInDays' not in domain
        else:
            assert domain['passwordValidityPeriodInDays'] == 120
    results = evaluate_snapshot(snapshot, checks=[CID])['findings']
    assert results and {f['status'] for f in results} == {'DENIED' if mode == 'denied' else 'UNKNOWN'}
    assert len(transport.calls) == 1
    if approved_review:
        assert 'newlyProvisionedIdentities' in results[0]['evidence']['reason']


def test_approved_baseline_reaches_unavailable_provisioning_guard_after_native_domain_read(monkeypatch):
    test_normal_domain_metadata_keeps_baseline_unknown_without_provisioning_and_effective_policy(
        monkeypatch, 'managed', approved_review=True)
