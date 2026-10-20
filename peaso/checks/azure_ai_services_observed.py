"""Brief observations from the four reviewed ARM configuration results."""


def observation(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'azure':
        return None
    status, evidence = finding.get('status'), finding.get('evidence')
    if status not in ('PASS', 'FAIL') or not isinstance(evidence, dict):
        return None
    cid = finding.get('check_id')
    if cid == 'azure.review.ai_services.audit_logging':
        count = evidence.get('qualifying_log_entries')
        if type(count) is int and count >= 0 and (count > 0) == (status == 'PASS'):
            return 'Audit logs ' + ('have' if count else 'do not have') + ' a configured diagnostic destination.'
    elif cid == 'azure.review.ai_services.managed_identity':
        mode = evidence.get('identity_type')
        if mode in ('None', 'SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned') and (mode != 'None') == (status == 'PASS'):
            return 'The account has ' + ('no managed identity.' if mode == 'None' else mode + ' identity.')
    elif cid == 'azure.review.ai_services.outbound_restriction':
        enabled = evidence.get('restrict_outbound_network_access')
        if type(enabled) is bool and enabled == (status == 'PASS'):
            return 'Outbound network restrictions are ' + ('enabled.' if enabled else 'disabled.')
    elif cid == 'azure.review.ai_services.prompt_shield':
        results = evidence.get('deployment_results')
        if isinstance(results, list) and results and all(v in ('PASS', 'FAIL', 'UNKNOWN') for v in results):
            if status == 'FAIL' and 'FAIL' in results:
                return 'At least one text deployment policy lacks enabled blocking Prompt Shields.'
            if status == 'PASS' and set(results) == {'PASS'}:
                return 'All assessed text deployment policies enable blocking Prompt Shields.'
    return None
