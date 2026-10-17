"""Capture bindings on shared signed SW13 observations, using full-contract fixtures."""
from __future__ import annotations

import importlib

import pytest

from tests.compliance_draft_isolation import staged_registry


with staged_registry(['compliance_new_sw13']):
    fixture_module = importlib.import_module('tests.test_peaso_compliance_new_sw13')


CONSUMERS = (
    (fixture_module.m.TLS, 'tls_endpoint_observation'),
    (fixture_module.m.RESTORE, 'backup_restore_test'),
    (fixture_module.m.CORRELATION, 'security_query_review'),
    (fixture_module.m.NOTIFY, 'authentication_notification'),
    (fixture_module.m.DEVICE, 'azure_compliance_review'),
)


def prepared(cid):
    item, index = fixture_module.fixture(cid)
    metadata = index['context']['metadata']
    metadata.setdefault('credential_context_id', 'fixture-credential')
    metadata.setdefault('customer_context_id', 'fixture-customer')
    metadata.setdefault('tenant_id', 'tenant-13')
    return item, index


@pytest.mark.parametrize('cid,kind', CONSUMERS)
@pytest.mark.parametrize('field', ('credential_context_id', 'customer_context_id', 'tenant_id'))
def test_explicit_capture_binding_must_match_authority(cid, kind, field):
    item, index = prepared(cid)
    evaluate = fixture_module.REGISTERED[cid].evaluate
    assert evaluate(item, index)[0] == 'PASS'
    proof = fixture_module.raw(index, kind)['_provenance']
    correct = (index['context']['scope'].removeprefix('/tenants/') if field == 'tenant_id'
               and index['context']['scope'].startswith('/tenants/')
               else index['context']['metadata'][field])
    proof[field] = correct.upper() if field == 'tenant_id' else correct
    assert evaluate(item, index)[0] == 'PASS'
    proof[field] = 'foreign-' + correct
    assert evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field', ('credential_context_id', 'customer_context_id', 'tenant_id'))
def test_explicit_binding_without_authoritative_metadata_is_unknown(field):
    item, index = prepared(fixture_module.m.TLS)
    evaluate = fixture_module.REGISTERED[fixture_module.m.TLS].evaluate
    assert evaluate(item, index)[0] == 'PASS'
    index['context']['metadata'].pop(field)
    fixture_module.raw(index, 'tls_endpoint_observation')['_provenance'][field] = 'unresolved-binding'
    assert evaluate(item, index)[0] == 'UNKNOWN'
