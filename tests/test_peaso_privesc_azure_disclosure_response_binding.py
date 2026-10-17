"""Response-shape regressions for the bounded Azure disclosure evaluator.

All values here are synthetic local stubs. No Azure call or credential collection occurs.
"""
import copy

import pytest

from peaso.privesc.effective_permissions.azure import AzureModel
from peaso.privesc.effective_permissions.azure_disclosure_effects import (
    UNSUPPORTED_DISCLOSURES, source_control_returned_token_fields, valid,
)
from tests.test_peaso_privesc_azure_disclosures_v7 import ENTRIES, SOURCE, case, run
from tests.test_peaso_privesc_schema_ext import reached


def _app_case():
    entry = next(e for e in ENTRIES if e['service'] == 'app_services')
    return entry, *case(entry)


def _native_app_response(snapshot, fact, metadata, response):
    resource = fact['TargetId']
    metadata['ReturnedCredentialFields'] = source_control_returned_token_fields(response, resource)
    snapshot['metadata'].update({
        'tenant_verified': True, 'context_binding': 'scan_local',
        'native_disclosure_subject': {'oid': SOURCE, 'tid': 't'},
        'credential_context_id': 'synthetic-credential-context',
        'customer_context_id': 'synthetic-customer-context',
    })
    provenance = {
        'source': 'azure_native_metadata', 'authenticated_response_bound': True,
        'read_only': True, 'values_omitted': True, 'tenant_id': 't',
        'tenant_verified': True, 'source_principal_id': SOURCE,
        'credential_context_id': 'synthetic-credential-context',
        'customer_context_id': 'synthetic-customer-context',
        'source_operation': 'SourceControls_Get',
        'request_uri': 'https://management.azure.com' + resource,
        'response_status': 200, 'observed_at': fact['EvidenceObservedAt'],
    }
    metadata['_provenance'] = copy.deepcopy(provenance)
    fact['_provenance'] = copy.deepcopy(provenance)


def test_app_service_reviewed_config_without_returned_token_is_not_disclosure():
    entry, snapshot, fact, metadata = _app_case()
    assert metadata['NativeResource'] == {
        'id': fact['TargetId'], 'type': 'Microsoft.Web/sourcecontrols', 'name': 'GitHub'
    }
    model = AzureModel(snapshot)
    assert not valid(model, entry['id'], fact, fact['SourceId'], fact['TargetId'], fact['TargetScope'])
    assert not reached(run(snapshot, entry), SOURCE, entry['id'])


@pytest.mark.parametrize('properties', [
    {}, {'token': None}, {'token': ''}, {'token': '***'},
    {'token': '@Microsoft.KeyVault(SecretUri=https://vault.test/secrets/name)'},
    {'token': 'https://vault.test/secrets/name/version'},
    {'refreshToken': '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v/secrets/s'},
])
def test_source_control_absent_null_redacted_or_reference_fields_are_not_credentials(properties):
    entry, snapshot, fact, metadata = _app_case()
    response = dict(metadata['NativeResource'], properties=properties)
    _native_app_response(snapshot, fact, metadata, response)
    assert metadata['ReturnedCredentialFields'] == []
    model = AzureModel(snapshot)
    assert not valid(model, entry['id'], fact, SOURCE, fact['TargetId'], fact['TargetScope'])
    assert not reached(run(snapshot, entry), SOURCE, entry['id'])


def test_only_exact_authenticated_source_control_response_with_documented_value_can_bind():
    entry, snapshot, fact, metadata = _app_case()
    # Microsoft.Web SourceControl documents properties.token as an OAuth access token.
    # The response value is a benign local stub; only its field name enters the snapshot.
    response = dict(metadata['NativeResource'], properties={'token': 'synthetic-local-test-value'})
    _native_app_response(snapshot, fact, metadata, response)
    assert metadata['ReturnedCredentialFields'] == ['properties.token']
    assert 'synthetic-local-test-value' not in repr(snapshot)
    model = AzureModel(snapshot)
    assert valid(model, entry['id'], fact, SOURCE, fact['TargetId'], fact['TargetScope'])
    assert reached(run(snapshot, entry), SOURCE, entry['id'])
    for key, value in [('request_uri', 'https://management.azure.com/providers/Microsoft.Web/sourcecontrols/other'),
                       ('response_status', 204), ('source_operation', 'Other_Get')]:
        bad = copy.deepcopy(snapshot)
        next(c for c in bad['collections'] if c['type']=='azure_disclosure_source_metadata')['items'][0]['_provenance'][key] = value
        assert not reached(run(bad, entry), SOURCE, entry['id'])
    bad = copy.deepcopy(snapshot)
    next(c for c in bad['collections'] if c['type']=='azure_privesc_challenge_evidence')['items'][0]['_provenance']['request_uri'] = 'https://management.azure.com/providers/Microsoft.Web/sourcecontrols/other'
    assert not reached(run(bad, entry), SOURCE, entry['id'])


@pytest.mark.parametrize('technique,response', [
    ('azure-spring-apps-microsoftappplatformspringapmslistsecretkeysaction',
     {'value': ['connection-string']}),
    ('azure-spring-apps-config-server-bindings-secret-exposure',
     {'properties': {'generatedProperties': 'spring.datasource.url=jdbc:test', 'secrets': [{'name': 'db-password'}]}}),
    ('azure-service-linker-read-connection-configuration-to-exfiltrate-the-backing-secret',
     {'configurations': [{'name': 'DB_PASSWORD', 'value': '@Microsoft.KeyVault(SecretUri=https://vault.test/secrets/db)'}]}),
    ('azure-sre-agent-microsoftappagentsdataconnectorslistsecretsaction',
     {'value': [{'name': 'kusto', 'properties': {'identity': 'systemAssigned'}}]}),
    ('azure-sre-agent-microsoftappagentslistsecretsaction',
     {'properties': {'identity': 'systemAssigned'}}),
])
def test_five_suppressed_response_shaped_names_and_references_remain_unknown(technique, response):
    entry = next(e for e in ENTRIES if e['id'] == technique)
    snapshot, fact, metadata = case(entry)
    metadata['ResponseShape'] = response
    assert technique in UNSUPPORTED_DISCLOSURES
    assert not valid(AzureModel(snapshot), technique, fact, SOURCE, fact['TargetId'], fact['TargetScope'])
    assert not reached(run(snapshot, entry), SOURCE, technique)
