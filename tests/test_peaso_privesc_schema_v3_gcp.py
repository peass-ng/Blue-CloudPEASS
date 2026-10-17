"""GCP challenge evidence is exact and cannot manufacture a definite path."""
from __future__ import annotations

import copy

import pytest

from peaso import privesc
from peaso.privesc.schema import validate_entry
from peaso.privesc.versioned_catalog import _verified_prior
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_gcp import gsnap


ENTRIES = [{k: v for k, v in item.items() if k != "_file"}
           for item in privesc.load_catalog()["entries"] if item["id"].startswith("gcp-v3-")]
SCOPE = "projects/p1"
ACTOR = "user:alice@corp.com"


def _source(entry):
    glob = (entry.get("source_selector") or {}).get("source_id_glob")
    if glob:
        return glob.replace("*", SCOPE)
    return ACTOR


def _target(entry):
    kind = entry["target"]["kind"]
    return {
        "gcp_service_account": "serviceAccount:target@p1.iam.gserviceaccount.com",
        "gcp_user": "user:target@corp.com",
        "gcp_workspace_user": "user:target@corp.com",
        "gcp_group": "group:admins@corp.com",
        "k8s_service_account": "k8s:cluster-1:sa:default:target",
    }.get(kind, "application-or-policy-resource-1")


def _fact(entry, **changes):
    fact = {"TechniqueId": entry["id"], "SourceId": _source(entry),
            "TargetKind": entry["target"]["kind"], "TargetId": _target(entry),
            "TargetScope": SCOPE, "Status": "verified", "VerifiedPreconditions": True}
    fact.update(changes)
    return fact


def _snapshot(status="collected", facts=()):
    role = "projects/p1/roles/challengeTester"
    snap = gsnap([{"role": role, "members": [ACTOR]}])
    actions = {r["action"] for e in ENTRIES for r in e["requires"].get("all_of", ())}
    next(c for c in snap["collections"] if c["type"] == "iam_role")["items"].append(
        {"name": role, "includedPermissions": sorted(actions)})
    if status is not None:
        snap["collections"].append({"type": "gcp_privesc_challenge_evidence", "scope": SCOPE,
                                    "service": "privesc", "status": status,
                                    "items": list(facts), "error": None})
    return snap


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e["id"])
def test_every_gcp_challenge_entry_validates_and_verified_path_is_conditional(entry):
    assert validate_entry(entry)[0] == []
    result = privesc.analyze(_snapshot(facts=[_fact(entry)]), entries=[entry])
    got = reached(result, _source(entry), entry["id"])
    assert len(got) == 1, (entry["id"], got, result["coverage"])
    assert set(got.values()) == {"conditional"}
    assert all(f["status"] != "FAIL" for f in result["findings"])


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e["id"])
def test_collected_empty_or_wrong_source_has_no_path(entry):
    for facts in ([], [_fact(entry, SourceId="user:wrong@corp.com")], [_fact(entry, Status="disproven")]):
        result = privesc.analyze(_snapshot(facts=facts), entries=[entry])
        assert not reached(result, _source(entry), entry["id"])


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e["id"])
def test_missing_or_incomplete_facts_are_only_unresolved(entry):
    for status, facts in ((None, ()), ("partial", [_fact(entry)]),
                          ("collected", [_fact(entry, VerifiedPreconditions=False)])):
        result = privesc.analyze(_snapshot(status, facts), entries=[entry])
        assert all(f["status"] != "FAIL" for f in result["findings"])
        assert any(f["status"] == "UNKNOWN" for f in result["findings"]), entry["id"]


def test_evidence_selector_is_bound_to_its_technique_and_conditional_confidence():
    prior, _ = _verified_prior()
    archived_id = "gcp-v3-40-issue-a-certificate-for-another-identity"
    assert archived_id not in {item["id"] for item in privesc.load_catalog()["entries"]}
    entry = copy.deepcopy(prior[archived_id])
    entry["target"]["selector"]["gcp_challenge_fact"] = "gcp-v3-other"
    assert any("must equal the technique id" in e for e in validate_entry(entry)[0])
    entry = copy.deepcopy(prior[archived_id])
    entry["confidence"] = "derived"
    assert any("must remain conditional" in e for e in validate_entry(entry)[0])
