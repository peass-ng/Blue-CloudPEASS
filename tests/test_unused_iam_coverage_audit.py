"""Coverage audit must expose routing/archival gaps rather than certify names."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('unused_iam_audit', Path(__file__).resolve().parents[1] / 'scripts/audit_unused_iam_coverage.py')
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


def row(provider, ident, category='hardening', frameworks=None):
    return {'provider': provider, 'id': ident, 'title': ident, 'type': 'identity',
            'category': category, 'frameworks': frameworks or ['HackTricks Cloud Best Practices']}


def result(catalog, provider, family):
    return next(r for r in audit_module.audit(catalog)['requirements'] if r['provider'] == provider and r['object_family'] == family)


def test_each_provider_has_distinct_identity_credential_and_authorization_requirements():
    requirements = audit_module.audit({'checks': []})['requirements']
    assert {r['provider'] for r in requirements} == {'aws', 'gcp', 'azure', 'k8s'}
    assert len(requirements) == 38
    assert all(r['state'] == 'no_candidate' for r in requirements)


def test_archived_check_does_not_satisfy_runtime_coverage():
    candidate = row('aws', 'iam.role_unused_90')
    candidate['type'] = 'iam_role'
    catalog = {'checks': [], 'archived_checks': [candidate]}
    assert result(catalog, 'aws', 'roles')['state'] == 'archived_only'


def test_least_privilege_check_does_not_satisfy_hardening_requirement():
    candidate = row('gcp', 'service_account.recently_used', 'least_privilege')
    candidate['type'] = 'service_account'
    catalog = {'checks': [candidate]}
    assert result(catalog, 'gcp', 'service_accounts')['state'] == 'hardening_or_compliance_mapping_missing'
    assert result(catalog, 'gcp', 'service_account_keys')['state'] == 'no_candidate'


def test_compliance_tag_and_hardening_still_require_behavioral_verification():
    candidate = row('azure', 'entra_user_recent_sign_in')
    candidate['type'] = 'directory_user'
    catalog = {'checks': [candidate]}
    assert result(catalog, 'azure', 'users')['state'] == 'runtime_and_evidence_review_required'


def test_rotation_or_mfa_check_is_not_an_unused_object_candidate():
    catalog = {'checks': [row('aws', 'iam.user_mfa_enabled'), row('aws', 'iam.access_key_rotated_90_days')]}
    assert result(catalog, 'aws', 'users')['state'] == 'no_candidate'
    assert result(catalog, 'aws', 'access_keys')['state'] == 'no_candidate'



def test_service_account_key_does_not_count_as_a_human_user_control():
    candidate = row('gcp', 'service_account_key.recently_used')
    candidate['type'] = 'service_account_key'
    candidate['title'] = 'User-managed service account key authenticated recently'
    catalog = {'checks': [candidate]}
    assert result(catalog, 'gcp', 'users')['state'] == 'no_candidate'
    assert result(catalog, 'gcp', 'service_accounts')['state'] == 'no_candidate'
    assert result(catalog, 'gcp', 'service_account_keys')['state'] == 'runtime_and_evidence_review_required'


def test_gcp_native_names_preserve_insight_workspace_and_storage_hmac_review_leads():
    candidates = []
    for kind, ident in [('service_account', 'gcp.iam.service_account_no_active_unused_insight'),
                        ('workspace_user', 'gcp.workspace.user_recent_activity'),
                        ('storage_hmac_key', 'gcp.htbp.storage.hmac_key_not_stale_or_default_sa')]:
        candidate = row('gcp', ident)
        candidate['type'] = kind
        candidates.append(candidate)
    catalog = {'checks': candidates}
    for family in ('service_accounts', 'users', 'hmac_keys'):
        assert result(catalog, 'gcp', family)['state'] == 'runtime_and_evidence_review_required'


def test_current_policy_insight_usage_control_is_only_a_behavioral_review_lead():
    candidate = row('gcp', 'gcp.iam.role_grant_has_observed_permission_use')
    candidate['type'] = 'insight'
    assert result({'checks': [candidate]}, 'gcp', 'iam_bindings_and_permissions')['state'] == 'runtime_and_evidence_review_required'


def test_directory_login_and_federation_lifecycle_controls_are_review_leads():
    candidates = []
    for kind, ident in [('workspace_user', 'gcp.iam.directory_user_recent_recorded_login'),
                        ('workload_identity_pool', 'gcp.iam.workload_identity_pool_has_enabled_provider'),
                        ('workforce_pool', 'gcp.iam.workforce_pool_has_enabled_provider')]:
        candidate = row('gcp', ident)
        candidate['type'] = kind
        candidates.append(candidate)
    catalog = {'checks': candidates}
    assert result(catalog, 'gcp', 'users')['state'] == 'runtime_and_evidence_review_required'
    assert len(result(catalog, 'gcp', 'workload_and_workforce_federation')['candidates']) == 2


def test_recorded_key_usage_controls_are_review_leads_not_global_inactivity_proof():
    candidates = []
    for kind, ident in [('api_key', 'gcp.iam.api_key_recent_recorded_successful_requests'),
                        ('storage_hmac_key', 'gcp.iam.hmac_key_recent_recorded_successful_requests')]:
        candidate = row('gcp', ident)
        candidate['type'] = kind
        candidates.append(candidate)
    for family in ('api_keys', 'hmac_keys'):
        assert result({'checks': candidates}, 'gcp', family)['state'] == 'runtime_and_evidence_review_required'


def test_custom_role_declarations_are_a_structural_review_lead():
    candidate = row('gcp', 'gcp.iam.custom_role_has_declared_grants')
    candidate['type'] = 'iam_role'
    assert result({'checks': [candidate]}, 'gcp', 'custom_roles')['state'] == 'runtime_and_evidence_review_required'


def test_group_inline_policy_consumers_are_a_structural_review_lead():
    candidate = row('aws', 'aws.iam.group_inline_policies_have_members')
    candidate['type'] = 'iam_group'
    assert result({'checks': [candidate]}, 'aws', 'inline_policies')['state'] == 'runtime_and_evidence_review_required'


def test_entra_custom_role_consumer_control_does_not_claim_action_usage():
    candidate = row('azure', 'azure.iam.custom_directory_role_has_declared_consumers')
    candidate['type'] = 'directory_role_definition'
    assert result({'checks': [candidate]}, 'azure', 'custom_roles')['state'] == 'runtime_and_evidence_review_required'


def test_arm_custom_role_consumer_control_is_a_structural_review_lead():
    candidate = row('azure', 'azure.iam.custom_arm_role_has_declared_consumers')
    candidate['type'] = 'role_definition'
    assert result({'checks': [candidate]}, 'azure', 'custom_roles')['state'] == 'runtime_and_evidence_review_required'


def test_non_identity_groups_and_policy_user_text_cannot_satisfy_aws_identity_families():
    candidates = []
    for kind, ident in [('waf_rule_group', 'aws.cb.waf.rule_group_not_empty'),
                        ('network_firewall_rule_group', 'aws.claude_a.networkfirewall.stateless_rule_group_not_empty'),
                        ('iam_policy', 'aws.claude_a.iam.custom_policy_in_use')]:
        candidate = row('aws', ident)
        candidate['type'] = kind
        candidates.append(candidate)
    catalog = {'checks': candidates}
    assert result(catalog, 'aws', 'groups')['state'] == 'no_candidate'
    assert result(catalog, 'aws', 'users')['state'] == 'no_candidate'
    assert result(catalog, 'aws', 'roles')['state'] == 'no_candidate'
    assert result(catalog, 'aws', 'managed_policies')['state'] == 'runtime_and_evidence_review_required'
