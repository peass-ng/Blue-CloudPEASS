"""A wildcard rule requires an authoritative nonempty verbs list."""
import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


def verdict(kind, rules):
    cid = "k8s.rbac.role_no_wildcards" if kind == "role" else "k8s.rbac.no_wildcards"
    snapshot = make_snapshot("k8s", ["*"], [{"type": kind, "scope": "*", "status": "collected", "items": [{"rules": rules}]}], created_at="2026-10-17T00:00:00Z")
    rows = [r for r in evaluate_snapshot(snapshot, checks=[cid])["findings"] if r["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]


INVALID = [
    {"resources": ["*"]},
    {"verbs": [], "resources": ["*"]},
    {"verbs": None, "resources": ["*"]},
    {"verbs": [42], "resources": ["*"]},
    {"verbs": ["get"], "resources": ["*"], "_coverage": {"verbs": {"status": "denied"}}},
]
VALID_WILDCARD = {"verbs": ["get"], "resources": ["*"]}


@pytest.mark.parametrize("kind", ["role", "clusterrole"])
@pytest.mark.parametrize("invalid", INVALID)
def test_invalid_required_verbs_cannot_create_failure(kind, invalid):
    assert verdict(kind, [invalid]) == "UNKNOWN"


@pytest.mark.parametrize("kind", ["role", "clusterrole"])
@pytest.mark.parametrize("invalid", INVALID)
@pytest.mark.parametrize("reverse", [False, True])
def test_separate_valid_wildcard_keeps_failure(kind, invalid, reverse):
    rows = [invalid, VALID_WILDCARD]
    if reverse:
        rows.reverse()
    assert verdict(kind, rows) == "FAIL"


@pytest.mark.parametrize("kind", ["role", "clusterrole"])
def test_optional_selectors_and_valid_wildcards(kind):
    assert verdict(kind, [{"verbs": ["get"]}]) == "PASS"
    assert verdict(kind, [{"verbs": ["get"], "nonResourceURLs": ["*"]}]) == "FAIL"
