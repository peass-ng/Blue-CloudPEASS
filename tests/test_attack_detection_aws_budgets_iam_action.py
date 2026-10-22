"""Synthetic derivatives of disposable AWS Budgets IAM action creation."""

from copy import deepcopy

from peaso.attack_detection.aws_budgets_iam_action import normalize_aws_budgets_iam_action


ACCOUNT = "999999999999"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-execution"
POLICY = f"arn:aws:iam::{ACCOUNT}:policy/synthetic-read"
ACTION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def event():
    return {
        "eventSource": "budgets.amazonaws.com", "eventName": "CreateBudgetAction",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventTime": "2026-10-22T00:00:00Z", "eventID": "synthetic-action-event",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": {
            "AccountId": ACCOUNT, "BudgetName": "synthetic-budget",
            "ActionType": "APPLY_IAM_POLICY", "ApprovalModel": "MANUAL",
            "ExecutionRoleArn": ROLE,
            "Definition": {"IamActionDefinition": {"PolicyArn": POLICY,
                                                    "Roles": ["synthetic-target"]}},
        },
        "responseElements": {"AccountId": ACCOUNT, "BudgetName": "synthetic-budget",
                             "ActionId": ACTION_ID},
    }


def test_accepted_iam_action_is_flagged_without_identifiers():
    result = normalize_aws_budgets_iam_action(event())
    assert result["request.budget_iam_policy_action_created"] is True
    assert result["request.budget_action_automatic"] is False
    assert result["target.id"].startswith("sha256:")
    for value in (ROLE, POLICY, ACTION_ID, "synthetic-budget", "synthetic-target"):
        assert value not in str(result)
    assert "__raw_cloudtrail" not in result


def test_automatic_action_is_distinguished_without_claiming_execution():
    record = event()
    record["requestParameters"]["ApprovalModel"] = "AUTOMATIC"
    result = normalize_aws_budgets_iam_action(record)
    assert result["request.budget_action_automatic"] is True
    assert "executed" not in result


def test_failed_unrelated_and_mismatched_events_are_excluded():
    base = event()
    mutations = (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
        lambda x: x.update(eventName="DeleteBudgetAction"),
        lambda x: x["requestParameters"].update(ActionType="RUN_SSM_DOCUMENTS"),
        lambda x: x["requestParameters"].update(AccountId="000000000000"),
        lambda x: x["requestParameters"].update(ExecutionRoleArn="invalid"),
        lambda x: x["requestParameters"]["Definition"]["IamActionDefinition"].update(Roles=[]),
        lambda x: x["responseElements"].update(BudgetName="other"),
        lambda x: x["responseElements"].update(ActionId="invalid"),
    )
    for mutate in mutations:
        record = deepcopy(base)
        mutate(record)
        assert normalize_aws_budgets_iam_action(record) is None
