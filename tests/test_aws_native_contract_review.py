"""Audit accounting and incomplete-data contracts; no cloud credentials used."""
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.audit_aws_native_contracts import active_ids, producer_contracts, registry, source_ref
from tests.test_peaso_checks import CASES
from tests.aws_late_native_contracts_20261020 import assert_workload_producer, workload_witness_case

CHECKS = registry()

# Exact current external evaluator placement, including already reviewed
# activity/completion successors. Unexpected moves still fail this gate.
EXTERNAL_EVALUATORS = {
    'aws.claude_a.vpc.sg_in_use_anywhere': 'peaso/unused_network_aws.py',
    'aws.claude_a.iam.role_used_within_60_days': 'peaso/unused_iam_aws_activity.py',
    'aws.claude_a.iam.console_password_used_45': 'peaso/unused_iam_aws_completion.py',
    'aws.claude_a.iam.prowler_console_password_used_45': 'peaso/unused_iam_aws_completion.py',
    'aws.claude_a.iam.access_keys_used_45': 'peaso/unused_iam_aws_completion.py',
    'aws.a.iam.unused_credentials_45_days': 'peaso/unused_iam_aws_completion.py',
    'aws.a.iam.unused_credentials_90_days': 'peaso/unused_iam_aws_completion.py',
    'aws.gap.iam.active_keys_used_within_45_days': 'peaso/unused_iam_aws_completion.py',
    'aws.iam.group_inline_policies_have_members': 'peaso/unused_iam_aws_inline.py',
    'aws.iam.identity_center.permission_set_has_consumer_all_accounts': 'peaso/unused_iam_aws_completion.py',
    'aws.iam.saml_provider_has_role_consumer': 'peaso/unused_iam_aws_federation_consumers.py',
    'aws.iam.oidc_provider_has_role_consumer': 'peaso/unused_iam_aws_federation_consumers.py',
    'aws.network.route_table_associated': 'peaso/unused_network_aws.py',
    'aws.network.internet_gateway_attached': 'peaso/unused_network_aws.py',
    'aws.network.vpn_gateway_attached': 'peaso/unused_network_aws.py',
    'aws.network.target_group_has_load_balancer': 'peaso/unused_network_aws.py',
}


def test_active_aws_registry_has_resolvable_collectors_and_real_evaluators():
    active = active_ids()
    assert active <= {check.id for check in CHECKS}
    producers = producer_contracts()
    external = {}
    for check in CHECKS:
        ref = source_ref(check.evaluate)
        assert Path(ref['file']).is_file() and ref['line'] > 0
        if not ref['file'].startswith('peaso/checks/'):
            external[check.id] = ref['file']
        if check.id in active:
            if check.id == 'aws.review.workload.selected_command_literal_secret_indicators':
                assert_workload_producer(check, producers[check.kind])
            else:
                assert all(producers[kind]['producer_found'] for kind in check.dependencies), check.id
    assert external == EXTERNAL_EVALUATORS


@pytest.mark.parametrize('check', CHECKS, ids=lambda c: c.id)
def test_explicit_partial_resource_never_passes(check):
    if check.id == 'aws.review.workload.selected_command_literal_secret_indicators':
        item, index = workload_witness_case()
        assert check.evaluate(deepcopy(item), deepcopy(index))[0] == 'FAIL'
    else:
        cases = CASES[check.id]
        item = deepcopy(cases.get('pass', {}))
        index = deepcopy(cases.get('pass_index', cases.get('case_indices', {}).get('pass', cases.get('index', {}))))
    item['collection_status'] = 'partial'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check', [check for check in CHECKS if check.target == 'scope'], ids=lambda c: c.id)
def test_scope_partial_dependencies_cannot_prove_pass(check):
    cases = CASES[check.id]
    if 'pass' not in cases:
        pytest.skip('no positive shared scope fixture; absence is explicit')
    item = deepcopy(cases['pass'])
    index = deepcopy(cases.get('pass_index', cases.get('case_indices', {}).get('pass', cases.get('index', {}))))
    changed = 0
    for kind in check.dependencies:
        for envelope in index.get('collections', {}).get(kind, []):
            envelope['status'] = 'partial'
            changed += 1
    if not changed:
        # Legacy examples can predate a native dependency (for example the
        # account-global Config proof). They must remain unresolved, rather
        # than silently skipping this incomplete-evidence contract.
        assert check.evaluate(item, index)[0] != 'PASS', check.id
        return
    assert check.evaluate(item, index)[0] != 'PASS', check.id
