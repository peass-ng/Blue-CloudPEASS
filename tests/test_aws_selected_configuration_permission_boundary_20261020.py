"""Optional selected content cannot silently expand the default audit role."""
import pytest
from scripts import peaso_deploy_customer_policy as policy
from peaso.collectors.aws import READ_ACTIONS

@pytest.mark.parametrize('operation',sorted(policy.OPTIONAL_CONFIGURATION_READ_REFERENCES))
def test_selected_configuration_action_has_primary_reference_and_is_not_default_granted(operation):
    action,url=policy.OPTIONAL_CONFIGURATION_READ_REFERENCES[operation]
    assert policy.iam_action(*operation)==action
    assert url.startswith('https://docs.aws.amazon.com/service-authorization/')
    assert operation in policy.UNGRANTED_CONTENT_OPERATIONS


def test_default_metadata_policy_unchanged_by_optional_selected_calls():
    optional=set(policy.OPTIONAL_CONFIGURATION_READ_REFERENCES)
    actual=policy.build_policy(READ_ACTIONS)
    prior=policy.build_policy(READ_ACTIONS-optional)
    assert actual==prior
    assert policy.build_policy()==policy.build_policy((READ_ACTIONS|policy.PRESERVED_TEMPLATE_READ_ACTIONS)-optional)


def test_stage_read_is_the_exact_management_route_not_invocation():
    assert policy.GATEWAY_PATHS[('apigateway','get_stage')]==('/restapis/*/stages/*',)
    assert policy.iam_action('apigateway','get_stage')=='apigateway:GET'
