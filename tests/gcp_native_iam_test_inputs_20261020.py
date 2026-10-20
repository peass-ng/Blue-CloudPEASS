"""Current native scope overlay for mutable legacy IAM unit inputs only.

The original CASES remain historical: role bindings, permissions and malformed
cases are copied, never repaired globally. CRM identity, ancestry and collection
receipts come from the independently asserted native32/fix transport and actual
GCPCollector, rather than hand-written favorable completeness flags.
"""
from copy import deepcopy
from functools import lru_cache

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.collectors.gcp import GCPCollector
from peaso.engine import _index
from peaso.snapshot import resources, validate
from tests.test_gcp_native57_iam_kms_fix_20261020 import FixAPI
from tests.test_gcp_native57_iam_kms_review_20261020 import CAPTURED, PROJECT, SCOPE

ROOT_CHECKS = {
    'gcp.gap.iam_user_managed_sa_no_admin_roles',
    'gcp.ports.service_account_mutating_role_declarations',
    'gcp.ports.function_basic_role_declarations',
    'gcp.ports.function_logging_mutation_declarations',
    'gcp.ports.function_legacy_deployment_role_declarations',
}


@lru_cache(maxsize=10)
def _native_index(cid, ancestors):
    kinds = list(next(check for check in CHECKS if check.id == cid).dependencies)
    api = FixAPI(cid, 'parent-good' if ancestors else 'good')
    collector = GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'inventories': kinds, 'include_inherited': True, 'resource_iam': False,
        'metrics_scopes': False, 'service_account_activity': False, 'concurrency': 1,
    }}, requirements=kinds, transport=api)
    collector.read_time = CAPTURED
    snapshot = collector.collect()
    assert not api.contract_errors, (api.contract_errors, api.requests)
    assert validate(snapshot) == snapshot
    index = _index(snapshot, resources(snapshot))
    index['context'] = {'provider': 'gcp', 'scope': SCOPE, 'metadata': snapshot['metadata']}
    return index


def _native_names(value):
    """Rename only the legacy test's project identity; preserve predicates."""
    if isinstance(value, dict):
        return {key: (PROJECT if key == 'projectId' and item == 'p' else _native_names(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [_native_names(item) for item in value]
    if isinstance(value, str):
        if value == 'projects/p':
            return SCOPE
        if value.startswith('projects/p/'):
            value = SCOPE + value[len('projects/p'):]
        return value.replace('@p.iam.gserviceaccount.com', '@' + PROJECT + '.iam.gserviceaccount.com')
    return value


def current_iam_fixture(cid, *, ancestors=False):
    """Return a fresh explicit overlay, with no change to global CASES."""
    fixture = deepcopy(CASES[cid])
    if cid not in ROOT_CHECKS:
        return fixture
    fixture = _native_names(fixture)
    native = deepcopy(_native_index(cid, ancestors))
    index = fixture['index']
    index['project'] = native['project']
    index['context'] = native['context']
    # Preserve the legacy policy/permission contents. Only their collection
    # receipts and the CRM join are migrated to a collector-produced scope.
    # These are direct evaluator unit inputs, not a reconstructed snapshot:
    # omit native item lists because the legacy bindings/roles are deliberate
    # unit mutations. Retain the actual scoped status/read receipts only.
    index['collections'] = {
        kind: [{key: value for key, value in envelope.items()
                if key in ('scope', 'status', 'coverage_status', 'source_requests')}
               for envelope in native['collections'][kind]]
        for kind in index['collections']
    }
    return fixture
