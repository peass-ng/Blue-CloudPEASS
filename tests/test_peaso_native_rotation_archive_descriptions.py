"""Public native configuration contracts preserve original signed metadata."""
import copy
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.catalog import description_for
from peaso.checks.native_rotation_archive_description_overlay import ROWS, description

@pytest.mark.parametrize("cid", tuple(ROWS))
def test_native_description_is_bound_to_original_and_public_contract(cid):
    pack = json.loads((Path(__file__).resolve().parents[1]/"peaso/rulepacks/check_descriptions.json").read_text())["checks"]
    original = copy.deepcopy(pack[cid])
    corrected = description(cid, original)
    assert original == pack[cid]
    assert corrected == description_for(cid)
    assert corrected["description_correction"]["base_row_sha256"] == ROWS[cid]["base_row_sha256"]
    public = next(c for c in CHECKS if c.id == cid).public()
    assert public["description"] == corrected["description"]
    assert public["pass_when"] == corrected["pass_when"]
    if cid == "aws_log_archive_immutable":
        assert "cloudtrail_account_inventory" in public["dependencies"]
        assert "existing objects" in public["description"]
    else:
        assert "does not require a Lambda" in public["description"]
        assert "RotationLambdaRequired" not in str(public["evaluated"])
    original["description"] += " drift"
    with pytest.raises(ValueError, match="original description changed"):
        description(cid, original)
