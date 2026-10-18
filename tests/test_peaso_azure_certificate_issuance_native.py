"""Public X.509 issuance facts do not attest deployment or TLS-universe coverage."""
import base64
import copy
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from peaso.collectors import azure, azure_swc
from peaso.collectors import azure_certificate_issuance_native as native
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
RID = SCOPE + '/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/fixturevault'
ORIGIN = 'https://fixturevault.vault.azure.net'
CURRENT = ORIGIN + '/certificates/cert/v1'
ISSUED = datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
CHECKS = ['azure.other.certificate_rotation_90_days', 'azure.other.certificate_rotation_180_days']


@pytest.fixture(scope='module')
def public_der():
    # The ephemeral key signs an offline public-only fixture and is never stored.
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fixture.example.invalid')])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(1).not_valid_before(ISSUED)
            .not_valid_after(ISSUED + timedelta(days=3650)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def source(public_der, status='collected'):
    row = {'id': RID + '/certificates/cert', 'parent_id': RID, 'name': 'cert', 'vault_uri': ORIGIN,
           'currentCertificate': {'id': CURRENT, 'attributes': {'created': 1893456000},
             'cer': base64.b64encode(public_der).decode(), 'sid': 'SENSITIVE_NEVER_FOLLOW',
             'privateKey': 'SENSITIVE_NEVER_COPY',
             '_provenance': {'source_operation': 'certificates_get_current', 'read_only': True,
               'request_uri': ORIGIN + '/certificates/cert', 'representation': 'full', 'api_version': '2025-07-01'}}}
    return {'type': 'key_vault_certificate', 'scope': SCOPE, 'service': 'Microsoft.KeyVault',
            'status': status, 'items': [row] if status not in ('empty', 'denied') else [],
            'scopeCoverage': {'scope': SCOPE,
                '_provenance': {'source_operation': 'vault_current_certificate_inventory_read', 'read_only': True},
                'resolution': dict.fromkeys(('vaults', 'certificatePages', 'currentVersions'), 'complete')}}


def project(parent, **limits):
    reader = azure._Reader({'concurrency': 1, 'retries': 0, **limits})
    reader.collections = [parent]
    reader.total = len(parent.get('items', []))
    native.collect(reader, [SCOPE], {'certificate_issuance'})
    assert reader.budget.calls == 0
    return reader.collections[-1]


def test_exact_public_notbefore_and_identifiers_without_creation_time_or_material(public_der):
    result = project(source(public_der))
    assert result['status'] == 'collected'
    row = result['items'][0]
    assert row['issued_at'] == ISSUED.isoformat()
    assert row['authority'] == 'x509_not_before' and row['serial'] == '01'
    assert row['thumbprint'] == x509.load_der_x509_certificate(public_der).fingerprint(hashes.SHA1()).hex()
    assert row['native_certificate_id'] == CURRENT
    assert row['id'] == RID + '/certificates/cert/issuance/v1'
    assert row['_provenance']['source_operation'] == 'authoritative_certificate_issuance_read'
    serialized = json.dumps(result)
    assert all(s not in serialized for s in ('SENSITIVE_', '1893456000', '"cer":', 'privateKey', '"sid"'))


@pytest.mark.parametrize('mode', [
    'foreign_scope', 'foreign_parent', 'parent_traversal', 'parent_percent', 'parent_backslash',
    'name_mismatch', 'foreign_origin', 'origin_parent_mismatch', 'unversioned', 'foreign_version',
    'malformed_der', 'missing_der', 'oversized_der', 'trailing_der', 'pem',
    'missing_provenance', 'not_readonly', 'wrong_operation', 'wrong_request', 'wrong_version',
    'incomplete_representation', 'missing_coverage', 'incomplete_coverage', 'duplicate_id',
    'ambiguous_same_public_cert', 'collected_without_items', 'empty_with_items',
])
def test_rejects_unbound_malformed_or_ambiguous_projection(public_der, mode):
    parent = source(public_der)
    row = parent['items'][0]
    current = row['currentCertificate']
    if mode == 'foreign_scope': parent['scope'] = '/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    elif mode == 'foreign_parent': row['parent_id'] = RID.replace(SCOPE, '/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
    elif mode == 'parent_traversal': row['parent_id'] = RID.replace('/rg/', '/../')
    elif mode == 'parent_percent': row['parent_id'] = RID.replace('/rg/', '/%2e%2e/')
    elif mode == 'parent_backslash': row['parent_id'] = RID.replace('/rg/', '/r\\g/')
    elif mode == 'name_mismatch': row['name'] = 'other'
    elif mode == 'foreign_origin': row['vault_uri'] = 'https://evil.example.invalid'
    elif mode == 'origin_parent_mismatch': row['vault_uri'] = 'https://foreign.vault.azure.net'
    elif mode == 'unversioned': current['id'] = ORIGIN + '/certificates/cert'
    elif mode == 'foreign_version': current['id'] = ORIGIN + '/certificates/other/v1'
    elif mode == 'malformed_der': current['cer'] = '!!!!'
    elif mode == 'missing_der': current.pop('cer')
    elif mode == 'oversized_der': current['cer'] = 'a' * (native.MAX_PUBLIC_DER_BASE64 + 1)
    elif mode == 'trailing_der': current['cer'] = base64.b64encode(public_der + b'junk').decode()
    elif mode == 'pem': current['cer'] = base64.b64encode(b'-----BEGIN CERTIFICATE-----').decode()
    elif mode == 'missing_provenance': current.pop('_provenance')
    elif mode == 'not_readonly': current['_provenance']['read_only'] = 1
    elif mode == 'wrong_operation': current['_provenance']['source_operation'] = 'secrets_get'
    elif mode == 'wrong_request': current['_provenance']['request_uri'] += '/v1'
    elif mode == 'wrong_version': current['_provenance']['api_version'] = 'unknown'
    elif mode == 'incomplete_representation': current['_provenance']['representation'] = 'list'
    elif mode == 'missing_coverage': parent.pop('scopeCoverage')
    elif mode == 'incomplete_coverage': parent['scopeCoverage']['resolution']['certificatePages'] = 'unknown'
    elif mode == 'duplicate_id': parent['items'].append(copy.deepcopy(row))
    elif mode == 'ambiguous_same_public_cert':
        other = copy.deepcopy(row)
        other['id'] = RID + '/certificates/other'
        other['name'] = 'other'
        other['currentCertificate']['id'] = ORIGIN + '/certificates/other/v2'
        other['currentCertificate']['_provenance']['request_uri'] = ORIGIN + '/certificates/other'
        parent['items'].append(other)
    elif mode == 'collected_without_items': parent['items'] = []
    elif mode == 'empty_with_items': parent['status'] = 'empty'
    result = project(parent)
    assert result['status'] not in ('collected', 'empty')
    assert result['items'] == []
    assert 'SENSITIVE_' not in json.dumps(result)


@pytest.mark.parametrize('status,expected', [('partial', 'partial'), ('denied', 'denied'), ('empty', 'empty')])
def test_source_completeness_is_never_upgraded(public_der, status, expected):
    result = project(source(public_der, status))
    assert result['status'] == expected
    if status == 'partial': assert len(result['items']) == 1


def test_resource_limit_and_duplicate_source_envelopes_stay_unavailable(public_der):
    assert project(source(public_der), max_resources=1)['status'] == 'partial'
    reader = azure._Reader({'concurrency': 1})
    reader.collections = [source(public_der), source(public_der)]
    native.collect(reader, [SCOPE], {'certificate_issuance'})
    assert reader.collections[-1]['status'] == 'malformed' and not reader.collections[-1]['items']


def test_dependency_and_nonselection_noop():
    assert native.required_types({'certificate_issuance'}) == {'key_vault_certificate', 'vault'}
    assert native.required_types({'vault'}) == set()
    reader = azure._Reader({})
    native.collect(reader, [SCOPE], {'vault'})
    assert reader.collections == [] and reader.budget.calls == 0


def test_existing_current_certificate_reader_reused_with_zero_additional_requests(public_der):
    reader = azure._Reader({'concurrency': 1, 'retries': 0})
    reader.collections = [{'type': 'vault', 'scope': SCOPE, 'status': 'collected',
        'items': [{'id': RID, 'properties': {'vaultUri': ORIGIN}}]}]
    calls = []
    def request(url, *, body=None, audience=None):
        assert body is None and audience == azure.VAULT
        calls.append(url)
        if url == ORIGIN + '/certificates?api-version=2025-07-01':
            return {'value': [{'id': ORIGIN + '/certificates/cert'}]}
        assert url == ORIGIN + '/certificates/cert?api-version=2025-07-01'
        return {'id': CURRENT, 'attributes': {'created': 1893456000},
                'cer': base64.b64encode(public_der).decode(), 'sid': 'SENSITIVE_NEVER_FOLLOW'}
    azure_swc.collect_current_certificates(reader, request, [SCOPE])
    assert len(calls) == reader.budget.calls == 2
    native.collect(reader, [SCOPE], {'certificate_issuance'})
    assert len(calls) == reader.budget.calls == 2
    assert reader.collections[-1]['status'] == 'collected'
    assert 'SENSITIVE_' not in json.dumps(reader.collections)


@pytest.mark.parametrize('days', [90, 180])
def test_signed_rotation_remains_unknown_without_native_served_endpoint_coverage(public_der, days):
    result = project(source(public_der))
    assert result['status'] == 'collected'  # Real useful fact, insufficient endpoint proof.
    now = datetime.now(timezone.utc).isoformat()
    snapshot = make_snapshot('azure', [SCOPE], [result], created_at=now,
        metadata={'compliance_policy': {'status': 'collected', 'scope': SCOPE,
            'observed_at': now, 'max_age_seconds': 3600,
            'parameters': {'approvedTlsServiceInventory': ['Microsoft.Web/sites'], 'tlsObservationMaxAgeSeconds': 3600}}})
    report = evaluate_snapshot(snapshot, checks=[f'azure.other.certificate_rotation_{days}_days'])
    findings = [f for f in report['findings'] if f['check_id'] in CHECKS]
    assert findings and {f['status'] for f in findings} == {'UNKNOWN'}


def test_two_versions_cannot_both_claim_the_same_current_certificate_name(public_der):
    parent = source(public_der)
    other = copy.deepcopy(parent['items'][0])
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'other.example.invalid')])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(2).not_valid_before(ISSUED)
            .not_valid_after(ISSUED + timedelta(days=3650)).sign(key, hashes.SHA256()))
    other['currentCertificate']['id'] = ORIGIN + '/certificates/cert/v2'
    other['currentCertificate']['cer'] = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    parent['items'].append(other)
    result = project(parent)
    assert result['status'] == 'malformed' and result['items'] == []
