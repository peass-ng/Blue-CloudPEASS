"""Public collector dispatch derives dates without additional native requests."""
import base64
import copy
import json
from datetime import datetime, timezone
import pytest
from peaso.collectors import azure
from peaso.engine import evaluate_snapshot
from tests import test_peaso_azure_certificate_issuance_native as fixture

@pytest.mark.parametrize('requirements', [['certificate_issuance'], ['certificate_issuance', 'key_vault_certificate']])
def test_public_dispatch_reuses_native_reads_and_keeps_signed_rotation_unknown(requirements):
    public_der = fixture.public_der.__wrapped__()
    owner = {'status': 'collected', 'scope': fixture.SCOPE, 'observed_at': datetime.now(timezone.utc).isoformat(),
             'max_age_seconds': 86400, 'parameters': {'approvedTlsServiceInventory': ['applicationGateway', 'appService'],
                                                   'tlsObservationMaxAgeSeconds': 3600}}
    options = {'concurrency': 1, 'retries': 0, 'compliance_parameters': {'azure_tls_certificates': owner}}
    original = copy.deepcopy(options)
    class Transport:
        def __init__(self): self.calls = []
        def request(self, url, *, body=None, audience=None):
            self.calls.append((url, audience))
            if url == azure.ARM + '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01':
                assert isinstance(body, dict)
                return {'data': [], 'totalRecords': 0, 'count': 0}
            assert body is None
            if url == azure.ARM + fixture.RID + '/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview':
                return {'value': []}
            if url == azure.ARM + fixture.SCOPE + '/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01':
                return {'value': [{'id': fixture.RID, 'name': 'fixturevault', 'type': 'Microsoft.KeyVault/vaults',
                                   'properties': {'vaultUri': fixture.ORIGIN}}]}
            if url == fixture.ORIGIN + '/certificates?api-version=2025-07-01':
                return {'value': [{'id': fixture.ORIGIN + '/certificates/cert'}]}
            if url == fixture.ORIGIN + '/certificates/cert?api-version=2025-07-01':
                return {'id': fixture.CURRENT, 'attributes': {'created': 1893456000},
                        'cer': base64.b64encode(public_der).decode(), 'sid': 'NEVER_FOLLOW_SECRET',
                        'privateKey': 'NEVER_COPY_PRIVATE_KEY'}
            raise AssertionError('unexpected native request ' + url)
    transport = Transport()
    snapshot = azure.collect({'scopes': [fixture.SCOPE], 'auth': {'method': 'token', 'token': 'inert'},
                              'options': options}, requirements=requirements, transport=transport)
    collections = {c['type']: c for c in snapshot['collections']}
    assert collections['vault']['status'] == 'collected'
    assert collections['key_vault_certificate']['status'] == 'collected'
    issued = collections['certificate_issuance']
    assert issued['status'] == 'collected' and len(issued['items']) == 1
    assert issued['items'][0]['issued_at'] == fixture.ISSUED.isoformat()
    assert issued['items'][0]['authority'] == 'x509_not_before' and issued['items'][0]['serial'] == '01'
    assert len(transport.calls) == 5 and len({url for url, _ in transport.calls}) == 5
    assert snapshot['metadata']['compliance_policy'] == owner and options == original
    assert 'vault_certificate' not in collections and 'scopeCoverage' not in issued
    assert 'NEVER_' not in json.dumps(snapshot)
    report = evaluate_snapshot(snapshot, checks=fixture.CHECKS)
    findings = [f for f in report['findings'] if f['check_id'] in fixture.CHECKS]
    assert {f['check_id'] for f in findings} == set(fixture.CHECKS)
    assert {f['status'] for f in findings} == {'UNKNOWN'}
