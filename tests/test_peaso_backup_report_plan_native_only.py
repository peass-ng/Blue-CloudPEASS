"""Native report-plan applicability and pagination through SDK Stubber."""
import boto3
import pytest
from botocore.stub import Stubber
from peaso.collectors import aws
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "aws.b.backup.report_plan_presence"
ACCOUNT = "111111111111"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
PLAN = {"BackupPlanArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-plan:00000000-0000-0000-0000-000000000001", "BackupPlanId": "00000000-0000-0000-0000-000000000001", "BackupPlanName": "plan"}
REPORT = {"ReportPlanArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:report-plan:report", "ReportPlanName": "report"}


def run(plan_pages, report_pages):
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION)
    client = session.client("backup", region_name=REGION)
    stub = Stubber(client)
    for response in plan_pages:
        if isinstance(response, str):
            stub.add_client_error("list_backup_plans", service_error_code=response)
        else:
            stub.add_response("list_backup_plans", response)
    for method, response, params in report_pages:
        if method == "error":
            stub.add_client_error("list_report_plans", service_error_code=response, expected_params=params)
        else:
            stub.add_response("list_report_plans", response, params)
    stub.activate()
    requests = aws.Requests({})
    requests.client = lambda _session, service, region: client
    specs = {kind: aws.SPECS[kind] for kind in ("backup_plan", "backup_report_plan")}
    reads = {}
    for kind in ("backup_plan", "backup_report_plan"):
        if kind in aws.FETCHERS:
            read = aws.FETCHERS[kind](requests, session, REGION, ACCOUNT)
        else:
            service, operation, expression = specs[kind]
            read = requests.pages(session, service, REGION, operation, expression)
        reads[kind] = read
    stub.assert_no_pending_responses()
    stub.deactivate()
    collections = [{"type": kind, "scope": SCOPE, "status": read.status, "items": read.items,
                    **({"error": read.error} if read.error else {})}
                   for kind, read in reads.items()]
    snapshot = make_snapshot("aws", [SCOPE], collections)
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CID])
    finding = next(f for f in report["findings"] if f["check_id"] == CID)
    assert finding["scope"] == SCOPE
    return finding, reads, requests


def test_complete_positive_two_pages():
    finding, reads, requests = run(
        [{"BackupPlansList": [PLAN]}],
        [("ok", {"ReportPlans": [], "NextToken": "next"}, {}),
         ("ok", {"ReportPlans": [REPORT]}, {"NextToken": "next"})])
    assert finding["status"] == "PASS"
    assert finding["evidence"]["backup_report_plans"] == 1
    assert reads["backup_report_plan"].status == "collected"
    assert requests.calls == 3


def test_complete_missing_report_plan_fails():
    finding, reads, requests = run([{"BackupPlansList": [PLAN]}], [("ok", {"ReportPlans": []}, {})])
    assert finding["status"] == "FAIL"
    assert reads["backup_report_plan"].status == "empty"
    assert requests.calls == 2


def test_complete_no_backup_plan_is_not_applicable():
    finding, reads, requests = run([{"BackupPlansList": []}], [("ok", {"ReportPlans": []}, {})])
    assert finding["status"] == "NOT_APPLICABLE"
    assert finding["evidence"]["backup_plans"] == 0
    assert requests.calls == 2


def test_report_page_denied_is_not_a_pass():
    finding, reads, requests = run(
        [{"BackupPlansList": [PLAN]}],
        [("ok", {"ReportPlans": [REPORT], "NextToken": "next"}, {}),
         ("error", "AccessDeniedException", {"NextToken": "next"})])
    assert reads["backup_report_plan"].status == "partial"
    assert finding["status"] == "UNKNOWN"
    assert requests.calls == 3


def test_first_report_page_denied_is_denied():
    finding, reads, requests = run([{"BackupPlansList": [PLAN]}], [("error", "AccessDeniedException", {})])
    assert reads["backup_report_plan"].status == "denied"
    assert finding["status"] == "DENIED"
    assert requests.calls == 2


def test_empty_plan_proves_non_applicability_despite_report_denial():
    finding, reads, requests = run([{"BackupPlansList": []}], [("error", "AccessDeniedException", {})])
    assert finding["status"] == "NOT_APPLICABLE"
    assert finding["evidence"]["empty_applicability_dependencies"] == ["backup_plan"]
    assert reads["backup_report_plan"].status == "denied"


def test_backup_plan_denial_cannot_prove_non_applicability():
    finding, reads, requests = run(["AccessDeniedException"], [("ok", {"ReportPlans": []}, {})])
    assert reads["backup_plan"].status == "denied"
    assert finding["status"] == "DENIED"
    assert requests.calls == 2


def test_report_present_without_backup_plan_follows_source_info():
    finding, reads, requests = run([{"BackupPlansList": []}], [("ok", {"ReportPlans": [REPORT]}, {})])
    assert finding["status"] == "NOT_APPLICABLE"
    assert reads["backup_report_plan"].status == "collected"
    assert requests.calls == 2
