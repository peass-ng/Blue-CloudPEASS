"""Directed original SW20 identity ingress and external evidence joins."""
import copy
import json
from pathlib import Path

import pytest
from peaso.snapshot import make_snapshot
from tests.archived_check_contract import evaluate_snapshot

DATA = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())
MFA = "azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled"
FEDERATED = "azure.other.human_federated_signin"


def case(cid):
    return copy.deepcopy(DATA[cid]["pass"]), copy.deepcopy(DATA[cid]["pass_index"])


def status(cid, item, index):
    context = index["context"]
    envelopes = [dict(batch, service="external:inert-fixture") for batches in index["collections"].values() for batch in batches]
    snapshot = make_snapshot("azure", [context["scope"]], envelopes,
                             metadata=context["metadata"], created_at=context["created_at"])
    rows = [row for row in evaluate_snapshot(snapshot, checks=[cid], include_not_applicable=True)["findings"]
            if row["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]


@pytest.mark.parametrize("kind", ["history", "proof", "domain"])
def test_federation_rejects_explicit_foreign_source_subject(kind):
    item, index = case(FEDERATED)
    user = index["collections"]["entra_user"][0]["items"][0]
    history = index["collections"]["human_signin_history"][0]["items"][0]
    proof = history["authenticationEvidence"][0]
    domain = index["collections"]["domain_federation"][0]["items"][0]
    selected = {"history": history, "proof": proof, "domain": domain}[kind]
    selected["source_subject_id"] = "other-subject"
    assert status(FEDERATED, item, index) == "UNKNOWN"


@pytest.mark.parametrize("kind", ["history", "proof", "domain"])
def test_federation_rejects_explicit_foreign_idp(kind):
    item, index = case(FEDERATED)
    history = index["collections"]["human_signin_history"][0]["items"][0]
    selected = {"history": history, "proof": history["authenticationEvidence"][0],
                "domain": index["collections"]["domain_federation"][0]["items"][0]}[kind]
    selected["source_idp_id"] = "foreign-idp"
    assert status(FEDERATED, item, index) == "UNKNOWN"


def test_measured_mfa_bypass_survives_unrelated_malformed_path():
    item, index = case(MFA)
    paths = index["collections"]["entra_user"][0]["items"][0]["managementSignInDecisions"]["items"][0]["allowed_paths"]
    paths[:] = [{"required_controls": "unreadable", "required_authentication_strength_ids": []},
                {"required_controls": [], "required_authentication_strength_ids": []}]
    assert status(MFA, item, index) == "FAIL"


def test_matching_explicit_federation_identity_and_capture_still_pass():
    item, index = case(FEDERATED)
    index["context"]["metadata"].update(credential_context_id="cred-1", customer_context_id="customer-1")
    user = index["collections"]["entra_user"][0]["items"][0]
    history = index["collections"]["human_signin_history"][0]["items"][0]
    rows = [history, history["authenticationEvidence"][0],
            index["collections"]["domain_federation"][0]["items"][0]]
    for row in rows:
        row["tenant_id"] = "tenant-1"
        row["source_idp_id"] = user["source_idp_id"]
        row["source_subject_id"] = user["source_subject_id"]
        row["_provenance"] = {**row.get("_provenance", {}), "tenant_id": "tenant-1",
                              "credential_context_id": "cred-1", "customer_context_id": "customer-1"}
    assert status(FEDERATED, item, index) == "PASS"
