"""Security Hub history cannot certify a finding from another AWS account."""

from peaso.collectors.aws_wave_semantics_native import PROFILE
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
PRODUCT = f"arn:aws:securityhub:{REGION}::product/aws/securityhub"
ACTOR = f"arn:aws:iam::{ACCOUNT}:role/responder"
CREATED = "2026-10-10T00:00:00Z"
CAPTURE = "2026-10-10T05:00:00Z"


def _snapshot(*, native_account=ACCOUNT):
    finding = {"id": "finding-1", "Id": "finding-1", "AccountId": ACCOUNT,
               "AwsAccountId": native_account, "Region": REGION, "ProductArn": PRODUCT,
               "CreatedAt": CREATED, "UpdatedAt": "2026-10-10T02:00:00Z",
               "Severity": {"Label": "HIGH"}, "Workflow": {"Status": "NOTIFIED"}}
    identity = {"Id": finding["Id"], "ProductArn": PRODUCT}
    records = [
        {"FindingIdentifier": identity, "UpdateTime": "2026-10-10T00:00:01Z",
         "FindingCreated": True, "UpdateSource": {"Type": "BATCH_IMPORT_FINDINGS",
         "Identity": PRODUCT}, "Updates": []},
        {"FindingIdentifier": identity, "UpdateTime": "2026-10-10T02:00:00Z",
         "UpdateSource": {"Type": "BATCH_UPDATE_FINDINGS", "Identity": ACTOR},
         "Updates": [{"UpdatedField": "Workflow.Status", "OldValue": "NEW",
                      "NewValue": "NOTIFIED"}]},
    ]
    history = {"id": finding["Id"], "ProductArn": PRODUCT, "AccountId": ACCOUNT,
               "Region": REGION, "CreatedAt": CREATED, "capture_at": CAPTURE,
               "complete": True, "_metadata_projection": PROFILE, "Records": records}
    return make_snapshot("aws", [SCOPE], [
        {"type": "securityhub_finding", "scope": SCOPE, "status": "collected",
         "items": [finding]},
        {"type": "securityhub_finding_history", "scope": SCOPE, "status": "collected",
         "items": [history]},
    ], created_at=CAPTURE, metadata={"parameters": {"approved_response_hours": 4,
        "approved_response_identity_arns": [ACTOR]}})


def test_native_finding_account_must_match_scoped_history():
    assert evaluate_snapshot(_snapshot(), checks=["aws_incident_workflow_sla"])["findings"][0]["status"] == "PASS"
    verdict = evaluate_snapshot(_snapshot(native_account="999999999999"),
                                checks=["aws_incident_workflow_sla"])["findings"][0]
    assert verdict["status"] == "UNKNOWN", verdict
