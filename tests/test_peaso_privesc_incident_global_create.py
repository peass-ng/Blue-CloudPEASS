"""Creating an Incident Manager response plan requires a global grant."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.effective_permissions.aws import AwsModel
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-ssm-incidents-response-plan-automation-passrole"
ENTRY = next(row for row in privesc.load_catalog()["entries"] if row["id"] == ID)
ACCOUNT = "111111111111"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"


def _route(create_resource):
    snap = _snapshot(ENTRY)
    user = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Action": "ssm-incidents:CreateResponsePlan", "Resource": create_resource},
        {"Effect": "Allow", "Action": "ssm-incidents:StartIncident",
         "Resource": f"arn:aws:ssm-incidents::{ACCOUNT}:response-plan/*"},
    ]
    model = AwsModel(snap)
    model.incident_accounts[(ACCOUNT, REGION)] = {
        "ReplicationSets": {"collection_status": "collected", "items": [{"status": "ACTIVE",
            "regionMap": {REGION: {"status": "ACTIVE"}}}]},
        "ResponsePlans": {"collection_status": "empty", "items": []},
    }
    model._ssm_new_automation_document = lambda *_a, **_k: ("conditional", "document")
    return model._ssm_incident_response_route(model.principals[user["Arn"]],
                                               model.principals[role["Arn"]])


def test_response_plan_creation_requires_global_resource():
    assert _route("*") == ("conditional", "new_response_plan_automation_execution")
    assert _route(f"arn:aws:ssm-incidents::{ACCOUNT}:response-plan/Existing") is None
