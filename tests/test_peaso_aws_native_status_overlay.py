"""Frozen AWS prose and reviewed remediation remain the hash-bound overlay base."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from peaso.checks.aws_native_status_description_overlay import ROWS, description, remediation, validate_rows
from peaso.checks.catalog import description_for
from peaso.checks import aws_finding_clarity_reviewed as clarity
from peaso.remediation import template


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "peaso/rulepacks"


def _digest(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


@pytest.mark.parametrize("check_id,status", [
    ("aws.a.cloudtrail.bucket_access_logging", "UNKNOWN"),
    ("aws.a.cloudtrail.bucket_mfa_delete", "UNKNOWN"),
    ("aws.a.iam.attached_policy_no_star_star", "NOT_APPLICABLE"),
])
def test_current_overlay_keeps_frozen_rows_and_native_catalog_in_sync(check_id, status):
    signed = json.loads((PACK / "check_descriptions.json").read_text())["checks"][check_id]
    reviewed = json.loads((PACK / "remediation_aws_reviewed.json").read_text())[check_id]
    native = {row["id"]: row for row in json.loads((PACK / "native_catalog.json").read_text())["checks"]}[check_id]
    assert _digest(signed) == ROWS[check_id]["description_base_sha256"]
    assert _digest(reviewed) == ROWS[check_id]["remediation_base_sha256"]
    current = description_for(check_id)
    predecessor = description(check_id, signed)
    assert current == clarity.description(check_id, predecessor)
    assert {k:v for k,v in current.items() if k != "description"} == {k:v for k,v in predecessor.items() if k != "description"}
    assert status in " ".join(str(v) for v in current.values())
    assert all(native[check_id_field] == current[check_id_field]
               for check_id_field in ROWS[check_id]["description_fields"])
    current_remediation = template(check_id)
    assert current_remediation == clarity.remediation(check_id, remediation(check_id, reviewed))
    assert current_remediation["caveats"] == native["remediation_details"]["caveats"]
    assert current_remediation["summary"] == native["remediation_details"]["summary"]
    assert status in " ".join(current_remediation["caveats"])


@pytest.mark.parametrize("check_id", ROWS)
def test_tampered_frozen_description_and_remediation_fail_closed(check_id):
    signed = json.loads((PACK / "check_descriptions.json").read_text())["checks"][check_id]
    reviewed = json.loads((PACK / "remediation_aws_reviewed.json").read_text())[check_id]
    bad_description = copy.deepcopy(signed)
    bad_description["description"] += " tampered"
    with pytest.raises(ValueError, match="AWS original description changed"):
        description(check_id, bad_description)
    with pytest.raises(ValueError, match="AWS original description changed"):
        validate_rows({check_id: bad_description})
    bad_remediation = copy.deepcopy(reviewed)
    bad_remediation["summary"] += " tampered"
    with pytest.raises(ValueError, match="AWS original remediation changed"):
        remediation(check_id, bad_remediation)
