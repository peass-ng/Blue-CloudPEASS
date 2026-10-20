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


# The four core AWS priorities were reviewed after the AWS native admissions,
# before the subsequent GCP admissions in 15842280dfb336f356497451d94ec46b2ba5d4ee.
# The accepted GCP hooks have independent tests/test_gcp_*_review_20261019.py
# coverage and docs/gcp-review/native-extension-integration.{json,md} provenance.
# Remove this EXACT appended block only; the original whole-file SHA256 below
# still binds all AWS callbacks, registration, severities and public metadata.
# Never split on an import marker alone: that would silently admit any new tail.
_REVIEWED_GCP_ADMISSIONS = """from . import gcp_workbench_review_20261019  # Native, policy-independent Workbench settings.
gcp_workbench_review_20261019.install()
from . import gcp_function_secret_review_20261019
gcp_function_secret_review_20261019.install()

from . import gcp_configuration_secret_review_20261019
gcp_configuration_secret_review_20261019.install()

from . import gcp_log_secret_review_20261019
gcp_log_secret_review_20261019.install()

from . import gcp_selected_object_secret_review_20261019
gcp_selected_object_secret_review_20261019.install()

from . import gcp_image_secret_review_20261019
gcp_image_secret_review_20261019.install()

from . import gcp_selected_archive_secret_review_20261019
gcp_selected_archive_secret_review_20261019.install()
from . import gcp_additional_literal_secret_review_20261019
gcp_additional_literal_secret_review_20261019.install()

from . import gcp_dataform_secret_review_20261019
gcp_dataform_secret_review_20261019.install()
from . import gcp_job_literal_secret_review_20261019
gcp_job_literal_secret_review_20261019.install()
from . import gcp_gke_literal_secret_review_20261019
gcp_gke_literal_secret_review_20261019.install()
from . import gcp_notebook_airflow_secret_review_20261019
gcp_notebook_airflow_secret_review_20261019.install()
from . import gcp_function_source_secret_review_20261019
gcp_function_source_secret_review_20261019.install()
from . import gcp_artifact_file_secret_review_20261019
gcp_artifact_file_secret_review_20261019.install()
from . import gcp_composer_source_secret_review_20261019
gcp_composer_source_secret_review_20261019.install()
from . import gcp_os_security_update_review_20261019
gcp_os_security_update_review_20261019.install()
from . import gcp_cloudsql_backup_alert_native
gcp_cloudsql_backup_alert_native.install_fixtures()
from . import gcp_cloudbuild_log_secret_review_20261019
gcp_cloudbuild_log_secret_review_20261019.install()

from . import gcp_appengine_source_secret_review_20261019
gcp_appengine_source_secret_review_20261019.install()

from . import gcp_cloudbuild_artifact_secret_review_20261019
gcp_cloudbuild_artifact_secret_review_20261019.install()

from . import gcp_clouddeploy_source_secret_review_20261019
gcp_clouddeploy_source_secret_review_20261019.install()

from . import gcp_sourcerepo_secret_review_20261019
gcp_sourcerepo_secret_review_20261019.install()
"""


# The separately accepted managed-default integrity correction is reversed
# exactly for the historical AWS priority source receipt, never repinned.
_MANAGED_VERSION_SUCCESSOR = 'def aws_documents(item):\n    documents, unresolved = [], 0\n    try:\n        direct = optional(item, "PolicyDocument", None)\n        if "PolicyDocument" in item:\n            documents.append(direct)\n    except (Unavailable, ValueError):\n        unresolved += 1\n    if "PolicyVersionList" in item or "DefaultVersionId" in item:\n        try:\n            default_id = get(item, "DefaultVersionId", str)\n            versions = list_of_objects(get(item, "PolicyVersionList", list))\n            version_ids = [get(version, "VersionId", str) for version in versions]\n            flags = [get(version, "IsDefaultVersion", bool) for version in versions]\n            if (not default_id.strip() or any(not ident.strip() for ident in version_ids)\n                    or len(version_ids) != len(set(version_ids))):\n                raise Unavailable("managed policy version identity is incomplete or duplicated")\n            selected = [version for version, flag in zip(versions, flags) if flag]\n            if len(selected) != 1 or get(selected[0], "VersionId", str) != default_id:\n                raise Unavailable("managed policy default version is inconsistent")\n            # Do not consume any managed document until all version identities\n            # and flags agree with the policy\'s selected native default.\n            documents.append(get(selected[0], "Document"))\n        except (Unavailable, ValueError):\n            unresolved += 1\n    for key in ("UserPolicyList", "RolePolicyList", "GroupPolicyList"):\n        try:\n            policies = list_of_objects(optional(item, key, [], list))\n        except (Unavailable, ValueError):\n            unresolved += 1\n            continue\n        for policy in policies:\n            try:\n                documents.append(get(policy, "PolicyDocument"))\n            except (Unavailable, ValueError):\n                unresolved += 1\n    return documents, unresolved\n'
_MANAGED_VERSION_PREDECESSOR = 'def aws_documents(item):\n    documents, unresolved = [], 0\n    try:\n        direct = optional(item, "PolicyDocument", None)\n        if "PolicyDocument" in item:\n            documents.append(direct)\n    except (Unavailable, ValueError):\n        unresolved += 1\n    try:\n        versions = list_of_objects(optional(item, "PolicyVersionList", [], list))\n    except (Unavailable, ValueError):\n        versions, unresolved = [], unresolved + 1\n    for version in versions:\n        try:\n            if get(version, "IsDefaultVersion", bool):\n                documents.append(get(version, "Document"))\n        except (Unavailable, ValueError):\n            unresolved += 1\n    for key in ("UserPolicyList", "RolePolicyList", "GroupPolicyList"):\n        try:\n            policies = list_of_objects(optional(item, key, [], list))\n        except (Unavailable, ValueError):\n            unresolved += 1\n            continue\n        for policy in policies:\n            try:\n                documents.append(get(policy, "PolicyDocument"))\n            except (Unavailable, ValueError):\n                unresolved += 1\n    return documents, unresolved\n'
_MANAGED_VERSION_SUCCESSOR_SHA256 = '8815ab5071a819f27ff1d00fd57dde6dd9c416dd5c93e1ac10da54b3c26efe40'


def _reviewed_priority_source(source):
    text = (PACK.parents[1] / source["file"]).read_bytes()
    if source["file"] == "peaso/checks/__init__.py":
        successor = _MANAGED_VERSION_SUCCESSOR.encode()
        assert hashlib.sha256(successor).hexdigest() == _MANAGED_VERSION_SUCCESSOR_SHA256
        assert text.count(successor) == 1
        text = text.replace(successor, _MANAGED_VERSION_PREDECESSOR.encode(), 1)
        suffix = _REVIEWED_GCP_ADMISSIONS.encode()
        assert text.count(suffix) == 1 and text.endswith(suffix)
        text = text[:-len(suffix)]
    return text


def test_priority_proposals_are_bound_to_the_actual_unchanged_sources():
    assert set(SEVERITY_REVIEW) == set(SEVERITY_SOURCE_REVIEW) == set(ROWS) | {cid for cid in PREVIOUS if cid.startswith("aws.")}
    for cid, proposal in SEVERITY_REVIEW.items():
        assert proposal["current"] == REGISTRY[cid].severity
        assert proposal["recommended"] in {"info", "low", "medium", "high", "critical"}
        assert proposal["reason"]
        source = SEVERITY_SOURCE_REVIEW[cid]
        assert hashlib.sha256(_reviewed_priority_source(source)).hexdigest() == source["sha256"]


def test_priority_review_keeps_administrative_ports_and_public_data_serious():
    assert SEVERITY_REVIEW["aws.claude_a.vpc.sg_no_world_ssh"]["recommended"] == "high"
    assert SEVERITY_REVIEW["aws.claude_a.vpc.sg_no_world_rdp"]["recommended"] == "high"
    assert SEVERITY_REVIEW["aws.c2b.elbv2.internet_facing_open_sg"]["recommended"] == "medium"
    assert SEVERITY_REVIEW["aws.gap.s3.no_public_write_acl_or_policy"]["recommended"] == "critical"
    assert SEVERITY_REVIEW["aws.claude_a.s3.restrict_public_read"]["recommended"] == "critical"
    assert SEVERITY_REVIEW["aws.c2b.cloudfront.custom_ssl_certificate"]["recommended"] == "info"
    assert SEVERITY_REVIEW["aws.c2b.dms.public_instance_open_sg"]["recommended"] == "high"
