from copy import deepcopy

import pytest

from scripts.audit_aws_requirement_associations import additional_signal_review, assurance_corrections, definitions, reconcile_edge


KEY = ('cis_1.4_aws', '1.11')


def test_explicit_canonical_rejection_does_not_become_automation():
    row = reconcile_edge('source', ['native'], KEY,
                         {KEY: {'decision': 'PARTIAL', 'native_checks': ['other'], 'removed_checks': ['native']}}, {})
    assert row['disposition'] == 'explicit_canonical_rejection'
    assert not row['counts_as_requirement_automation']
    assert not row['compliance_membership_change_authorized']


def test_alternative_canonical_predicate_does_not_prove_candidate_equivalence():
    row = reconcile_edge('source', ['native'], KEY,
                         {KEY: {'decision': 'PARTIAL', 'native_checks': ['other'], 'removed_checks': []}}, {})
    assert row['disposition'] == 'unresolved_additional_signal_semantics'


def test_one_removed_candidate_cannot_hide_a_second_unreviewed_candidate():
    row = reconcile_edge('source', ['removed', 'new'], KEY,
                         {KEY: {'decision': 'PARTIAL', 'native_checks': [], 'removed_checks': ['removed']}}, {})
    assert row['disposition'] == 'unresolved_additional_signal_semantics'


def test_privileged_mode_source_leaf_is_not_proved_by_secret_indicators():
    result = additional_signal_review('codebuild_project_no_secrets_in_variables', ('pci_4.0_aws', '7.2.1.3'))
    assert result['recommendation'] == 'retain_topic_only'
    assert 'privilegedMode' in result['reason']


def test_new_ecs_secret_signal_retains_partial_assurance():
    result = additional_signal_review('ecs_task_definitions_no_environment_secrets', ('pci_4.0_aws', '3.5.1.14'))
    assert result['recommendation'] == 'propose_add_partial_signal'
    assert 'PARTIAL' in result['reason']


def test_missing_ledger_and_compiler_drift_remain_unresolved():
    assert reconcile_edge('s', ['n'], KEY, {}, {})['disposition'] == 'unresolved_missing_canonical_requirement'
    assert reconcile_edge('s', ['n'], KEY, {KEY: {'decision': 'MAPPED', 'native_checks': ['n']}}, {})['disposition'] == 'unresolved_compiled_membership_differs_from_ledger'


def test_nested_requirement_uses_exact_framework_and_requirement_identity():
    docs = {'cis': {'Requirements': [{'Id': '1', 'Requirements': [
        {'Id': '1.11', 'Description': 'Initial setup', 'Checks': ['s']}]}]}}
    assert definitions(docs)[('cis', '1.11')]['description'] == 'Initial setup'
    assert ('cis', '1') not in definitions(docs)


def test_initial_key_assurance_downgrade_preserves_number_and_current_scope():
    row = {'requirement_id': '1.11', 'native_checks': ['aws.claude_a.iam.no_unused_initial_access_key'],
           'runtime_status': 'automated', 'decision': 'MAPPED', 'reason': 'Existing claim'}
    requirements = {'frameworks': [{'id': 'cis_1.4_aws', 'provider': 'aws', 'requirements': [row]}]}
    before = deepcopy(requirements)
    patch, = assurance_corrections(requirements)
    assert patch['requirement_id'] == '1.11'
    assert patch['decision'] == 'PARTIAL'
    assert patch['runtime_status'] == 'partial'
    assert requirements == before
    row['runtime_status'] = 'partial'
    assert assurance_corrections(requirements) == []


def test_initial_setup_history_counterexample_with_real_predicate():
    from peaso.checks.claude_aws_a_iam import no_initial_key
    # Created with the user, then used: current last-use evidence cannot prove
    # the historical prohibition. The hygiene predicate still returns PASS.
    row = {'password_enabled': 'true', 'user_creation_time': '2025-01-01T00:00:00Z',
           'access_key_1_active': 'true', 'access_key_2_active': 'false',
           'access_key_1_last_rotated': '2025-01-01T00:00:00Z',
           'access_key_1_last_used_date': '2026-10-18T00:00:00Z'}
    assert no_initial_key(row, {})[0] == 'PASS'
