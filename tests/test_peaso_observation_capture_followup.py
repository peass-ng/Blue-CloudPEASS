"""Capture bindings on shared signed SW13 observations, using full-contract fixtures."""
from __future__ import annotations

import importlib
import sys
from functools import lru_cache

import pytest
import peaso.checks
import tests

from tests.compliance_draft_isolation import staged_registry


_CHECK_MODULE = 'peaso.checks.compliance_new_sw13'
_TEST_MODULE = 'tests.test_peaso_compliance_new_sw13'
_ABSENT = object()


@lru_cache(maxsize=1)
def fixture_module():
    """Load the signed fixtures without publishing their registrar in this process."""
    before_modules = {name: sys.modules.get(name, _ABSENT) for name in (_CHECK_MODULE, _TEST_MODULE)}
    before_attrs = {
        (peaso.checks, 'compliance_new_sw13'): peaso.checks.__dict__.get('compliance_new_sw13', _ABSENT),
        (tests, 'test_peaso_compliance_new_sw13'): tests.__dict__.get('test_peaso_compliance_new_sw13', _ABSENT),
    }
    try:
        with staged_registry(['compliance_new_sw13']):
            return importlib.import_module(_TEST_MODULE)
    finally:
        for name, previous in before_modules.items():
            if previous is _ABSENT:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
        for (package, name), previous in before_attrs.items():
            if previous is _ABSENT:
                package.__dict__.pop(name, None)
            else:
                package.__dict__[name] = previous


CONSUMERS = (
    ('TLS', 'tls_endpoint_observation'),
    ('RESTORE', 'backup_restore_test'),
    ('CORRELATION', 'security_query_review'),
    ('NOTIFY', 'authentication_notification'),
    ('DEVICE', 'azure_compliance_review'),
)


def prepared(module, cid):
    item, index = module.fixture(cid)
    metadata = index['context']['metadata']
    metadata.setdefault('credential_context_id', 'fixture-credential')
    metadata.setdefault('customer_context_id', 'fixture-customer')
    metadata.setdefault('tenant_id', 'tenant-13')
    return item, index


@pytest.mark.parametrize('cid,kind', CONSUMERS)
@pytest.mark.parametrize('field', ('credential_context_id', 'customer_context_id', 'tenant_id'))
def test_explicit_capture_binding_must_match_authority(cid, kind, field):
    module = fixture_module()
    cid = getattr(module.m, cid)
    item, index = prepared(module, cid)
    evaluate = module.REGISTERED[cid].evaluate
    assert evaluate(item, index)[0] == 'PASS'
    proof = module.raw(index, kind)['_provenance']
    correct = (index['context']['scope'].removeprefix('/tenants/') if field == 'tenant_id'
               and index['context']['scope'].startswith('/tenants/')
               else index['context']['metadata'][field])
    proof[field] = correct.upper() if field == 'tenant_id' else correct
    assert evaluate(item, index)[0] == 'PASS'
    proof[field] = 'foreign-' + correct
    assert evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field', ('credential_context_id', 'customer_context_id', 'tenant_id'))
def test_explicit_binding_without_authoritative_metadata_is_unknown(field):
    module = fixture_module()
    item, index = prepared(module, module.m.TLS)
    evaluate = module.REGISTERED[module.m.TLS].evaluate
    assert evaluate(item, index)[0] == 'PASS'
    index['context']['metadata'].pop(field)
    module.raw(index, 'tls_endpoint_observation')['_provenance'][field] = 'unresolved-binding'
    assert evaluate(item, index)[0] == 'UNKNOWN'


def test_fixture_import_restores_staged_module_and_registry_boundary():
    before_modules = {name: sys.modules.get(name, _ABSENT) for name in (_CHECK_MODULE, _TEST_MODULE)}
    before_checks = tuple(peaso.checks.CHECKS)
    before_aliases = dict(peaso.checks.CHECK_ALIASES)
    module = fixture_module()
    assert module.m.TLS in module.REGISTERED
    assert all(sys.modules.get(name, _ABSENT) is previous for name, previous in before_modules.items())
    assert tuple(peaso.checks.CHECKS) == before_checks
    assert peaso.checks.CHECK_ALIASES == before_aliases
