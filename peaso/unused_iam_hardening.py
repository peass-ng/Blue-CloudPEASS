"""Keep unused identity/credential signals in the normal Hardening scan scope."""
from dataclasses import replace

# Existing IDs and formal mappings are retained. Native successors validate
# creation age and source-bound usage windows without changing signed histories.
ROUTED_IDS = frozenset({
    'aws.a.iam.unused_credentials_45_days',
    'aws.a.iam.unused_credentials_90_days',
    'aws.claude_a.iam.user_bedrock_access_not_stale',
    'aws.claude_a.iam.role_bedrock_access_not_stale',
    'aws.claude_a.iam.user_sagemaker_access_not_stale',
    'gcp.claude.service_account.recently_used',
    'gcp.claude.service_account_key.recently_used',
})


def install(registry):
    by_id = {check.id: check for check in registry.CHECKS}
    missing = ROUTED_IDS - by_id.keys()
    if missing:
        raise ValueError('unused IAM routing refers to missing native controls: ' + ', '.join(sorted(missing)))
    if any(by_id[ident].category not in ('least_privilege', 'hardening') for ident in ROUTED_IDS):
        raise ValueError('unused IAM routing predecessor category changed')
    registry.CHECKS[:] = [replace(check, category='hardening') if check.id in ROUTED_IDS else check
                          for check in registry.CHECKS]
    from peaso.unused_iam_gcp import install as install_gcp_unused
    install_gcp_unused(registry)
    from peaso.unused_iam_aws_activity import install as install_aws_activity
    install_aws_activity(registry)
    from peaso.unused_iam_aws_inline import install as install_aws_inline
    install_aws_inline(registry)
    from peaso.unused_iam_aws_completion import install as install_aws_completion
    install_aws_completion(registry)
    from peaso.unused_iam_aws_federation_consumers import install as install_federation_consumers
    install_federation_consumers(registry)
    from peaso.unused_network_hardening import install as install_unused_network
    install_unused_network(registry)
