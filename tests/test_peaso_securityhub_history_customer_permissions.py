"""Static permissions for native Security Hub history, without workflow writes."""
import pytest
from scripts.peaso_deploy_customer_policy import (
    SECURITYHUB_HISTORY_METADATA_REFERENCE, build_policy, iam_action,
)


def test_history_api_maps_to_reviewed_read_permission():
    assert iam_action("securityhub", "get_finding_history") == "securityhub:GetFindingHistory"
    assert SECURITYHUB_HISTORY_METADATA_REFERENCE[0] == "securityhub:GetFindingHistory"


def test_requested_finding_and_history_reads_generate_only_two_permissions():
    policy = build_policy(
        {("securityhub", "get_findings"), ("securityhub", "get_finding_history")},
        include_credential_report_generation=False,
    )
    actions = {action for row in policy["Statement"]
               for action in ([row["Action"]] if isinstance(row["Action"], str) else row["Action"])}
    assert actions == {"securityhub:GetFindings", "securityhub:GetFindingHistory"}
    assert all(row["Effect"] == "Allow" for row in policy["Statement"])


@pytest.mark.parametrize("operation", ["batch_update_findings", "create_automation_rule"])
def test_history_mapping_does_not_authorize_workflow_mutations(operation):
    with pytest.raises(ValueError):
        iam_action("securityhub", operation)
