"""Public source correction is visible and rejects drift of frozen reviewed rows."""
from copy import deepcopy
import hashlib
import json

import pytest

from peaso.checks import CHECKS
from peaso.checks.catalog import description_for
from peaso.checks.gcp_inherited_description_overlay import ROWS, description, validate_rows
from peaso.checks.catalog import _compliance


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_public_native_criterion_and_history(check_id):
    base = deepcopy(_compliance()[1]["checks"][check_id])
    corrected = description_for(check_id)
    public = next(check.public() for check in CHECKS if check.id == check_id)
    assert corrected["fail_when"].startswith("FAIL when")
    assert public["description"] == corrected["description"]
    assert public["pass_when"] == corrected["pass_when"]
    assert public["fail_when"] == corrected["fail_when"]
    provenance = public["description_correction"]
    assert provenance["base_row_sha256"] == ROWS[check_id]["base_row_sha256"]
    assert provenance["base_catalog_row_sha256"] == ROWS[check_id]["base_catalog_row_sha256"]
    assert "superseded" in provenance["source_relationship"]
    assert provenance["prior_source"].startswith("https://github.com/")
    assert provenance["official_references"]
    assert "no FAIL path" in base["fail_when"]
    assert base["description"] != corrected["description"]
    assert hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() == ROWS[check_id]["base_row_sha256"]


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_source_row_drift_rejected(check_id):
    checks = deepcopy(_compliance()[1]["checks"])
    checks[check_id]["pass_when"] += " drift"
    with pytest.raises(ValueError, match="original description changed"):
        validate_rows(checks)
    with pytest.raises(ValueError, match="original description changed"):
        description(check_id, checks[check_id])
