"""Real-source guards and evaluator boundaries for 711 AWS copy corrections."""
from copy import deepcopy
import json
import hashlib
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks.catalog import _base_description_for
from peaso.checks.fixtures import CASES
from peaso.checks.finding_clarity_reviewed import ROWS as PREVIOUS
from peaso.checks.aws_finding_clarity_reviewed import ROWS, _digest, description, remediation
from peaso.checks.aws_finding_clarity_reviewed import SEVERITY_REVIEW, SEVERITY_SOURCE_REVIEW

PACK = Path(__file__).resolve().parents[1] / "peaso/rulepacks"
REGISTRY = {check.id: check for check in CHECKS}


@pytest.fixture(scope="module")
def remediations():
    found = {}
    for path in PACK.glob("remediation*.json"):
        rows = json.loads(path.read_text())
        if isinstance(rows, dict):
            for cid, value in rows.items():
                from peaso.checks.aws_native_status_description_overlay import ROWS as status_rows, remediation as status_remediation
                if cid in ROWS and cid in status_rows and _digest(value) == status_rows[cid]["remediation_base_sha256"]:
                    corrected = status_remediation(cid, value)
                    if _digest(corrected) == ROWS[cid]["remediation_base_sha256"]:
                        found[cid] = corrected
                if cid == "aws.cloudtrail.management_events" and cid in ROWS:
                    from peaso.checks.cloudtrail_management_description_overlay import remediation as trail_remediation
                    corrected = trail_remediation(value)
                    if _digest(corrected) == ROWS[cid]["remediation_base_sha256"]:
                        found[cid] = corrected
                if cid in ROWS and _digest(value) == ROWS[cid]["remediation_base_sha256"]:
                    found[cid] = value
    found.update({cid: None for cid, row in ROWS.items() if row["remediation_base_sha256"] == _digest(None)})
    assert set(found) == set(ROWS), "Reviewed original remediation rows must still exist"
    return found


def test_scope_is_711_distinct_aws_controls_after_the_initial_review():
    assert len(ROWS) == 711
    assert set(ROWS) <= REGISTRY.keys()
    assert not set(ROWS) & PREVIOUS.keys()
    assert all(REGISTRY[cid].provider == "aws" for cid in ROWS)
    frontend = (PACK.parents[1] / "frontend/src/awsReviewedCheckIds.ts").read_text()
    ids = json.loads(frontend.split("Set<string>(", 1)[1].split(");", 1)[0])
    assert set(ids) == set(ROWS) | {cid for cid in PREVIOUS if cid.startswith("aws.")}, "Specific evidence prose must not claim an unreviewed check"


@pytest.mark.parametrize("cid", sorted(ROWS))
def test_description_keeps_signed_criteria_and_available_fields(cid):
    original = _base_description_for(cid)
    before = deepcopy(original)
    actual = description(cid, original)
    assert original == before
    assert len(actual["description"].split()) <= 45
    assert {k: v for k, v in actual.items() if k != "description"} == {
        k: v for k, v in original.items() if k != "description"}


@pytest.mark.parametrize("cid", sorted(ROWS))
def test_short_actions_keep_every_caveat_command_reference_and_binding(cid, remediations):
    original = remediations[cid]
    before = deepcopy(original)
    actual = remediation(cid, original)
    assert original == before
    assert 1 <= len(actual["steps"]) <= 2
    assert all(len(step.split()) <= 40 for step in actual["steps"])
    assert len(actual["summary"].split()) <= 40
    if original is None:
        assert actual["review_status"] == "approved" and actual["cli"] == []
        assert actual["references"] and actual["caveats"]
        return
    if cid in {"aws.c2b.efs.no_public_mount_targets", "aws.c2b.autoscaling.group_lc_no_public_ip", "aws.c2b.autoscaling.lc_no_public_ip"}:
        assert actual["caveats"][:len(original["caveats"])] == original["caveats"]
        assert actual["caveats"][-1]
        assert {k: v for k, v in actual.items() if k not in {"summary", "steps", "caveats"}} == {
            k: v for k, v in original.items() if k not in {"summary", "steps", "caveats"}}
        return
    if cid in __import__("peaso.checks.batch_remaining_aws", fromlist=["SPECS"]).SPECS:
        assert original["review_status"] == "source_bound_pending_review"
        assert actual["review_status"] == "approved" and actual["cli"] == []
        assert {k: v for k, v in actual.items() if k not in {"summary", "steps", "cli", "review_status"}} == {
            k: v for k, v in original.items() if k not in {"summary", "steps", "cli", "review_status"}}
        return
    assert {k: v for k, v in actual.items() if k not in {"summary", "steps"}} == {
        k: v for k, v in original.items() if k not in {"summary", "steps"}}


@pytest.mark.parametrize("cid", sorted(ROWS))
def test_any_unreviewed_source_change_fails_closed(cid, remediations):
    desc = deepcopy(_base_description_for(cid))
    desc["pass_when"] = "Different criterion"
    with pytest.raises(ValueError, match="Reviewed AWS finding clarity base changed"):
        description(cid, desc)
    guide = deepcopy(remediations[cid]) or {}
    guide["references"] = []
    with pytest.raises(ValueError, match="Reviewed AWS finding clarity base changed"):
        remediation(cid, guide)


def predicate_cases():
    output = []
    statuses = {"pass": "PASS", "fail": "FAIL", "missing": "UNKNOWN", "malformed": "UNKNOWN",
                "unknown": "UNKNOWN", "manual": "MANUAL", "not_applicable": "NOT_APPLICABLE"}
    for cid in sorted(ROWS):
        fixture = CASES.get(cid, {})
        for case, status in statuses.items():
            if case in fixture:
                output.append(pytest.param(cid, fixture[case], fixture.get(case + "_index", fixture.get("index", {})),
                                           fixture.get(case + "_expect", status), id=cid + ":" + case))
    return output


@pytest.mark.parametrize("cid,item,index,status", predicate_cases())
def test_existing_predicate_fixture_outcomes_are_preserved(cid, item, index, status):
    assert REGISTRY[cid].evaluate(deepcopy(item), deepcopy(index))[0] == status


def test_critical_encryption_and_exposure_limits_are_explicit(remediations):
    def desc(cid):
        return description(cid, _base_description_for(cid))["description"]
    assert "does not imply plaintext" in desc("aws.s3.default_encryption")
    assert "default envelope encryption" in desc("aws.eks.secrets_encryption")
    assert "at least one" in desc("aws.c2b.apigateway.stage_cache_encrypted")
    assert "does not prove authorizers protect" in desc("aws.c2b.apigateway.public_rest_api_authorizer")
    assert "NAT-only" in desc("aws.cb.rds.instance_no_public_subnet")
    assert "first" in desc("aws.cb.glue.job_s3_encryption_first_mode")
    assert "declared" in desc("aws.s3.no_public_acl")
    assert "Custom provider only when required" in remediation("aws.c2b.emr.cluster_local_disk_cmk",
        remediations["aws.c2b.emr.cluster_local_disk_cmk"])["summary"]


def test_default_s3_encryption_absence_does_not_become_failure():
    check = REGISTRY["aws.s3.default_encryption"]
    assert check.evaluate({"Encryption": {"absent": True}}, {})[0] == "UNKNOWN"
    good = {"Encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}}
    status, evidence = check.evaluate(good, {})
    assert status == "PASS" and evidence["algorithms"] == ["AES256"]
    assert "existing object encryption was not collected" in evidence["semantics"]


def test_priority_proposals_are_bound_to_the_actual_unchanged_sources():
    assert set(SEVERITY_REVIEW) == set(SEVERITY_SOURCE_REVIEW) == set(ROWS) | {cid for cid in PREVIOUS if cid.startswith("aws.")}
    for cid, proposal in SEVERITY_REVIEW.items():
        assert proposal["current"] == REGISTRY[cid].severity
        assert proposal["recommended"] in {"info", "low", "medium", "high", "critical"}
        assert proposal["reason"]
        source = SEVERITY_SOURCE_REVIEW[cid]
        assert hashlib.sha256((PACK.parents[1] / source["file"]).read_bytes()).hexdigest() == source["sha256"]


def test_priority_review_keeps_administrative_ports_and_public_data_serious():
    assert SEVERITY_REVIEW["aws.claude_a.vpc.sg_no_world_ssh"]["recommended"] == "high"
    assert SEVERITY_REVIEW["aws.claude_a.vpc.sg_no_world_rdp"]["recommended"] == "high"
    assert SEVERITY_REVIEW["aws.c2b.elbv2.internet_facing_open_sg"]["recommended"] == "medium"
    assert SEVERITY_REVIEW["aws.gap.s3.no_public_write_acl_or_policy"]["recommended"] == "critical"
    assert SEVERITY_REVIEW["aws.claude_a.s3.restrict_public_read"]["recommended"] == "critical"
    assert SEVERITY_REVIEW["aws.c2b.cloudfront.custom_ssl_certificate"]["recommended"] == "info"
    assert SEVERITY_REVIEW["aws.c2b.dms.public_instance_open_sg"]["recommended"] == "high"
