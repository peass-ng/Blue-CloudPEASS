"""Short observations from reviewed Azure predicates; evidence remains intact."""
from .azure_bulk_clarity_reviewed import ROWS


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'azure' or finding.get('status') != 'FAIL':
        return None
    row = ROWS.get(finding.get('check_id'))
    evidence = finding.get('evidence')
    if row is None or not isinstance(evidence, dict):
        return None
    cid = finding['check_id']
    if cid == 'azure.cis.latest_os_patches_vms_applied':
        count = evidence.get('available_critical_security_patches')
        if type(count) is int and count > 0:
            return f'The VM assessment reports {count} available critical or security patches.'
    if cid == 'azure.other.backup_immutability_30':
        state = evidence.get('immutability_state')
        if state in {'Disabled', 'Unlocked'}:
            return f'Backup immutability is {state.lower()}, rather than locked.'
    if cid == 'azure_aks_cluster_7_2_1_6_93c4fab':
        names = evidence.get('privileged_containers')
        if isinstance(names, list) and names:
            return f'{len(names)} observed Pod containers declare privileged mode.'
    if cid == 'azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb':
        containers = evidence.get('writable_root_containers')
        if isinstance(containers, list) and containers:
            return f'{len(containers)} containers do not declare a read-only root filesystem.'
    if cid == 'azure.cis.multifactor_auth_status_privileged_users' and evidence.get('legacy_per_user_mfa_state') == 'disabled':
        uncovered = evidence.get('uncovered_contexts')
        if isinstance(uncovered, list) and not uncovered:
            return 'The legacy per-user MFA state is disabled; this profile does not accept that state even with covered Conditional Access paths.'
    if cid == 'azure_vm_8_2_1_1_712e1ad':
        count = evidence.get('configured_bootstrap_ssh_public_key_count')
        if type(count) is int and count > 0:
            return f'The running Linux VM declares {count} bootstrap SSH public keys; this legacy profile prefers none.'
    if cid == 'azure_vault_3_7_1_2_532ecd2':
        outcomes = evidence.get('outcomes')
        if isinstance(outcomes, list):
            for item in outcomes:
                if not isinstance(item, dict) or item.get('status') != 'FAIL':
                    continue
                bits = item.get('measured_rsa_modulus_bits')
                if type(bits) is int and 0 < bits < 2048:
                    return f'The current issued certificate uses a {bits}-bit RSA public key.'
    if cid in {'azure.gap.automation_account_encrypted_with_cmk', 'azure.gap.stream_analytics_job_encrypted_with_cmk'}:
        if evidence.get('reason') in {'platform-managed encryption key configured', 'platform-managed key configured'}:
            return 'Platform-managed encryption is configured; this profile requires a customer-managed key.'
    return row['static_observed_sentence']
