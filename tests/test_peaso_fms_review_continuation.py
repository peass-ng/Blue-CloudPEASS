"""Malformed IDs anywhere in the scoped FMS association inventory block PASS."""
import pytest

from peaso.checks import evaluate_check
from tests.test_peaso_fms_multi_acl_priority import CONTROL, case


@pytest.mark.parametrize("bad_id", ["", "   "])
@pytest.mark.parametrize("attach_bad_acl", [False, True])
def test_nonblank_direct_policy_identity_required_across_inventory(bad_id, attach_bad_acl):
    policy, rows, index = case()
    other = {"PolicyId": bad_id, "SecurityServiceType": "WAFV2"}
    index["collections"]["fms_policy"][0]["items"].append(other)
    index["fms_policy"].append({
        "type": "fms_policy", "scope": index["context"]["scope"], "data": other,
    })
    if attach_bad_acl:
        rows[1]["PolicyId"] = bad_id
    assert evaluate_check(CONTROL, policy, index)[0] == "UNKNOWN"
