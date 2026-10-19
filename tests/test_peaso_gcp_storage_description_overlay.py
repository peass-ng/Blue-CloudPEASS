"""The storage audit source correction is public and hash-bound."""
from copy import deepcopy
import hashlib
import json

import pytest

from peaso.checks import CHECKS
from peaso.remediation import template
from peaso.checks.catalog import _compliance, description_for
from peaso.checks.gcp_inherited_description_overlay import ROWS, description, validate_rows

ID = "gcp.claude.project.storage_data_access_audit_logs"


def test_public_storage_audit_criterion():
    base = deepcopy(_compliance()[1]["checks"][ID])
    row = description_for(ID)
    public = next(check.public() for check in CHECKS if check.id == ID)
    assert row["description"] == public["description"]
    assert row["pass_when"] == public["pass_when"]
    assert row["fail_when"] == public["fail_when"]
    assert "DATA_READ" in public["pass_when"] and "DATA_WRITE" in public["pass_when"]
    assert "complete" in public["fail_when"] and "exemptions" in public["fail_when"]
    assert "log delivery" in " ".join(template(ID)["caveats"])
    correction = public["description_correction"]
    assert correction["base_row_sha256"] == ROWS[ID]["base_row_sha256"]
    assert correction["base_catalog_row_sha256"] == ROWS[ID]["base_catalog_row_sha256"]
    assert "superseded" in correction["source_relationship"]
    assert "no FAIL path" in base["fail_when"]
    assert hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() == ROWS[ID]["base_row_sha256"]


def test_storage_audit_description_drift_rejected():
    checks = deepcopy(_compliance()[1]["checks"])
    checks[ID]["pass_when"] += " changed"
    with pytest.raises(ValueError, match="original description changed"):
        validate_rows(checks)
    with pytest.raises(ValueError, match="original description changed"):
        description(ID, checks[ID])


def test_all_three_frozen_rows_validate():
    validate_rows(_compliance()[1]["checks"])
