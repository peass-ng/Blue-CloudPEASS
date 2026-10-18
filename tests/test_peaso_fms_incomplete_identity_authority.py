"""Incomplete FMS detail does not exempt ACL identity and scope validation."""
import pytest
from test_peaso_fms_multi_acl_priority import case, CONTROL
from peaso.checks import evaluate_check

@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("mode", ["duplicate", "foreign_account", "foreign_region", "wrong_resource_type", "missing_identity"])
def test_incomplete_acl_identity_must_be_unambiguous_and_scoped(mode, reverse):
    policy, rows, index = case()
    rows[0]["Rules"][1]["Priority"] = 3
    rows[1]["complete"] = False
    if mode == "duplicate": rows[1]["WebACLArn"] = rows[0]["WebACLArn"]
    elif mode == "foreign_account": rows[1]["WebACLArn"] = rows[1]["WebACLArn"].replace("123456789012", "999999999999")
    elif mode == "foreign_region": rows[1]["WebACLArn"] = rows[1]["WebACLArn"].replace("us-east-1", "us-west-2")
    elif mode == "wrong_resource_type": rows[1]["WebACLArn"] = rows[1]["WebACLArn"].replace("/webacl/", "/ipset/")
    else: rows[1].pop("WebACLArn")
    if reverse:
        rows.reverse()
        index["fms_web_acl_rules"].reverse()
    assert evaluate_check(CONTROL, policy, index)[0] == "UNKNOWN"

@pytest.mark.parametrize("known_bad,expected", [(True, "FAIL"), (False, "UNKNOWN")])
def test_valid_separate_incomplete_acl_preserves_independent_observation(known_bad, expected):
    policy, rows, index = case()
    if known_bad: rows[0]["Rules"][1]["Priority"] = 3
    rows[1]["complete"] = False
    rows[1].pop("Rules")
    assert evaluate_check(CONTROL, policy, index)[0] == expected

@pytest.mark.parametrize("mode,expected", [("valid", "PASS"), ("bad_incomplete", "FAIL"), ("duplicate_incomplete", "UNKNOWN")])
def test_fms_incomplete_identity_via_public_snapshot(mode, expected):
    from copy import deepcopy
    from test_peaso_fms_multi_acl_priority import SCOPE
    from peaso.snapshot import make_snapshot
    from tests.archived_check_contract import evaluate_snapshot
    policy, rows, index = case()
    if mode != "valid":
        rows[0]["Rules"][1]["Priority"] = 3
        rows[1]["complete"] = False
    if mode == "duplicate_incomplete": rows[1]["WebACLArn"] = rows[0]["WebACLArn"]
    snapshot = make_snapshot("aws", [SCOPE], [deepcopy(c) for cs in index["collections"].values() for c in cs], metadata=index["context"]["metadata"])
    findings = evaluate_snapshot(snapshot, checks=[CONTROL], include_not_applicable=True)["findings"]
    assert findings and {f["status"] for f in findings} == {expected}, findings
