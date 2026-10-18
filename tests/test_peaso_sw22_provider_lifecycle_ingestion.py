"""Normal sealed-snapshot ingestion of synthetic provider-auditor lifecycle facts.

These rows exercise the evidence contract; they are not observed provider facts.
"""

import copy
import json
from pathlib import Path

import pytest

from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot


CID = "azure_c5_dev_09_01b"
SCOPE = "/subscriptions/sub"
FIXTURE = Path(__file__).parent / "fixtures" / "bulk_pending_behavior.json"


def _input():
    accepted = copy.deepcopy(json.loads(FIXTURE.read_text())[CID]["pass_index"])
    context = accepted["context"]
    metadata = context["metadata"]
    metadata["compliance_policy"] = {"sw22": metadata.pop("sw22")}
    collections = [copy.deepcopy(batch) for batches in accepted["collections"].values() for batch in batches]
    return collections, context


def _run(mutate=None):
    collections, context = _input()
    if mutate:
        mutate(collections, context)
    supplied = make_snapshot("azure", [SCOPE], collections, metadata=context["metadata"],
                             created_at=context["created_at"])
    connector = {"provider": "azure", "scopes": [SCOPE], "auth": {},
                 "options": {"snapshot": supplied}}
    before = copy.deepcopy(supplied)
    collected = collect_snapshot({"connector": connector, "checks": [CID]})
    assert supplied == before and collected == supplied
    findings = [f for f in evaluate_snapshot(collected, checks=[CID], include_not_applicable=True)["findings"]
                if f["check_id"] == CID]
    assert len(findings) == 1
    return findings[0]


def _batch(collections, kind):
    return next(row for row in collections if row["type"] == kind)


def test_complete_external_provider_lifecycle_reaches_registered_pass():
    finding = _run()
    assert finding["status"] == "PASS"
    assert finding["evidence"]["repository_count"] == 1
    assert finding["evidence"]["stage_control_count"] == 16


def test_observed_missing_required_control_reaches_registered_fail():
    def missing(collections, context):
        row = _batch(collections, "source_control_evidence")["items"]
        next(value for value in row if value["stage_id"] == "release" and
             value["control"] == "authenticity")["outcome"] = "missing"
    finding = _run(missing)
    assert finding["status"] == "FAIL"
    assert ("repo1", "release", "authenticity") in finding["evidence"]["missing_controls"]


@pytest.mark.parametrize("kind", ["source_control", "source_control_evidence"])
def test_denied_required_collection_cannot_pass(kind):
    def denied(collections, context):
        batch = _batch(collections, kind)
        batch.update(status="denied", items=[], error={"code": "fixture-denied"})
    assert _run(denied)["status"] == "DENIED"


@pytest.mark.parametrize("field,value", [
    ("scope", "/subscriptions/foreign"),
    ("organization_id", "foreign-provider"),
    ("source_authority", "customer"),
])
def test_foreign_or_customer_audit_evidence_cannot_pass(field, value):
    def foreign(collections, context):
        _batch(collections, "source_control_evidence")["items"][0][field] = value
    assert _run(foreign)["status"] == "UNKNOWN"


def test_partial_evidence_collection_cannot_pass():
    def partial(collections, context):
        _batch(collections, "source_control_evidence")["status"] = "partial"
    assert _run(partial)["status"] == "UNKNOWN"


def test_uncovered_stage_audit_history_cannot_pass():
    def no_audit(collections, context):
        batch = _batch(collections, "source_control_evidence")
        batch["items"] = [row for row in batch["items"] if not (
            row["stage_id"] == "build" and row["control"] == "audit")]
    assert _run(no_audit)["status"] == "UNKNOWN"


def test_customer_repository_metadata_does_not_supply_provider_owned_policy():
    def customer(collections, context):
        context["metadata"]["compliance_policy"]["sw22"]["provider_source_lifecycle"]["provider_owned"] = False
    assert _run(customer)["status"] == "UNKNOWN"
