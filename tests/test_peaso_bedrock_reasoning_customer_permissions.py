"""Only static read grants required for the native Bedrock association control."""
import pytest
from scripts.peaso_deploy_customer_policy import iam_action, build_policy, BEDROCK_REASONING_METADATA_REFERENCES

READS = {
    ('bedrock-agent', 'list_agent_aliases'): 'bedrock:ListAgentAliases',
    ('bedrock-agent', 'get_agent_alias'): 'bedrock:GetAgentAlias',
    ('bedrock-agent', 'get_agent_version'): 'bedrock:GetAgentVersion',
    ('bedrock', 'get_automated_reasoning_policy'): 'bedrock:GetAutomatedReasoningPolicy',
}


@pytest.mark.parametrize('pair,expected', READS.items())
def test_new_control_reads_use_official_bedrock_iam_namespace(pair, expected):
    assert iam_action(*pair) == expected
    assert expected in BEDROCK_REASONING_METADATA_REFERENCES


def test_native_control_minimal_policy_grants_only_requested_metadata_reads():
    policy = build_policy(READS, include_credential_report_generation=False)
    actions = {action for row in policy['Statement']
               for action in ([row['Action']] if isinstance(row['Action'], str) else row['Action'])}
    assert actions == set(READS.values())
    assert all(row['Effect'] == 'Allow' for row in policy['Statement'])


@pytest.mark.parametrize('service,operation', [
    ('bedrock-agent', 'create_agent'), ('bedrock-agent', 'update_agent_alias'),
    ('bedrock-agent', 'prepare_agent'), ('bedrock-agent-runtime', 'invoke_agent'),
    ('bedrock', 'create_automated_reasoning_policy_version'),
    ('bedrock', 'start_automated_reasoning_policy_test_workflow'),
    ('bedrock-runtime', 'invoke_model'), ('bedrock-runtime', 'apply_guardrail'),
])
def test_control_metadata_mapping_does_not_authorize_mutation_or_inference(service, operation):
    with pytest.raises(ValueError):
        iam_action(service, operation)
