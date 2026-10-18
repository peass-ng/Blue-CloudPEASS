"""Directed, synthetic ingress evidence for three original Azure SW20 controls."""
import copy
import json
from pathlib import Path

import pytest

from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

CASES = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())
ROTATE90 = "azure.other.certificate_rotation_90_days"
ROTATE180 = "azure.other.certificate_rotation_180_days"
DISABLED = "azure.other.disabled_identity_24h"


def _findings(cid, state="pass", mutate=None):
    index = copy.deepcopy(CASES[cid][state + "_index"])
    if mutate:
        mutate(index)
    context = index["context"]
    envelopes = []
    for kind, batches in index["collections"].items():
        for batch in batches:
            batch.setdefault("type", kind)
            envelopes.append(batch)
    snapshot = make_snapshot("azure", [context["scope"]], envelopes,
        metadata=context["metadata"], created_at=context["created_at"])
    request = {"connector": {"provider": "azure", "scopes": [context["scope"]],
        "options": {"snapshot": snapshot}}, "checks": [cid]}
    admitted = collect_snapshot(request)
    assert admitted == snapshot
    return [row for row in evaluate_snapshot(admitted, checks=[cid],
        include_not_applicable=True)["findings"] if row["check_id"] == cid]


@pytest.mark.parametrize("cid", [ROTATE90, ROTATE180, DISABLED])
@pytest.mark.parametrize("state,expected", [("pass", "PASS"), ("fail", "FAIL"), ("unknown", "UNKNOWN")])
def test_full_contract_baseline(cid, state, expected):
    assert {row["status"] for row in _findings(cid, state)} == {expected}


def test_idp_subject_join_is_scoped_by_idp_for_measured_violation():
    def two_idps(index):
        users = index["collections"]["entra_user"][0]["items"]
        other = copy.deepcopy(users[0])
        other["id"] = "user-other-idp"
        other["source_idp_id"] = "other-idp"
        other["cloudAccessRemoval"]["principal_id"] = other["id"]
        other["cloudAccessRemoval"]["identity_active"] = False
        other["accountEnabled"] = False
        users.append(other)
    assert {row["status"] for row in _findings(DISABLED, "fail", two_idps)} == {"FAIL"}


def test_idp_subject_join_is_scoped_by_idp_for_timely_removal():
    def two_idps(index):
        users = index["collections"]["entra_user"][0]["items"]
        other = copy.deepcopy(users[0])
        other["id"] = "user-other-idp"
        other["source_idp_id"] = "other-idp"
        other["cloudAccessRemoval"]["principal_id"] = other["id"]
        users.append(other)
    assert {row["status"] for row in _findings(DISABLED, "pass", two_idps)} == {"PASS"}


def test_old_active_binding_is_90_day_violation_even_if_enabled_flag_false():
    def disabled(index):
        index["collections"]["vault_certificate"][0]["items"][0]["enabled"] = False
    assert {row["status"] for row in _findings(ROTATE90, "fail", disabled)} == {"FAIL"}


@pytest.mark.parametrize("cid", [ROTATE90, ROTATE180, DISABLED])
def test_partial_collection_never_supplies_compliance(cid):
    def partial(index):
        for batches in index["collections"].values():
            for batch in batches:
                batch["status"] = "partial"
    assert {row["status"] for row in _findings(cid, "pass", partial)} <= {"UNKNOWN", "DENIED"}


def test_duplicate_mapping_within_same_idp_remains_ambiguous():
    def duplicate(index):
        users = index["collections"]["entra_user"][0]["items"]
        other = copy.deepcopy(users[0])
        other["id"] = "user-duplicate"
        other["cloudAccessRemoval"]["principal_id"] = other["id"]
        users.append(other)
    assert {row["status"] for row in _findings(DISABLED, "pass", duplicate)} == {"UNKNOWN"}
