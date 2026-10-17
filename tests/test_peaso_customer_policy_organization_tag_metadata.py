"""Three exact newly introduced SDK reads; no IAM deployment or global build."""
import pytest
from scripts.peaso_deploy_customer_policy import (
    iam_action, build_policy, VERIFIED_ACTIONS, ORGANIZATION_TAG_METADATA_REFERENCES,
)

READS = {
    ('resourcegroupstaggingapi', 'get_resources'): 'tag:GetResources',
    ('organizations', 'describe_effective_policy'): 'organizations:DescribeEffectivePolicy',
    ('organizations', 'describe_organizational_unit'): 'organizations:DescribeOrganizationalUnit',
}


@pytest.mark.parametrize('operation,action', READS.items())
def test_reviewed_sdk_namespace_and_action(operation, action):
    assert iam_action(*operation) == action and action in VERIFIED_ACTIONS
    assert ORGANIZATION_TAG_METADATA_REFERENCES[action].startswith(
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_')


def test_selected_read_policy_contains_exactly_three_actions():
    policy = build_policy(set(READS), include_credential_report_generation=False)
    assert policy == {'Version': '2012-10-17', 'Statement': [{
        'Sid': 'ConfigurationAndInventoryRead', 'Effect': 'Allow',
        'Action': sorted(READS.values()), 'Resource': '*'}]}
    assert set(ORGANIZATION_TAG_METADATA_REFERENCES) == set(READS.values())


@pytest.mark.parametrize('operation', [
    ('resourcegroupstaggingapi', 'tag_resources'),
    ('resourcegroupstaggingapi', 'untag_resources'),
    ('resourcegroupstaggingapi', 'start_report_creation'),
    ('organizations', 'create_policy'), ('organizations', 'update_policy'),
    ('organizations', 'attach_policy'), ('organizations', 'detach_policy'),
    ('organizations', 'move_account'), ('organizations', 'delete_organizational_unit'),
])
def test_neighbor_mutations_never_become_grants(operation):
    with pytest.raises(ValueError, match='Mutation outside metadata policy'):
        iam_action(*operation)
    with pytest.raises(ValueError, match='Mutation outside metadata policy'):
        build_policy({operation}, include_credential_report_generation=False)


@pytest.mark.parametrize('operation', ['get_tag_keys', 'get_tag_values', 'get_compliance_summary', 'describe_report_creation'])
def test_namespace_fix_does_not_approve_other_tag_reads(operation):
    with pytest.raises(ValueError, match='requires reference review'):
        iam_action('resourcegroupstaggingapi', operation)
