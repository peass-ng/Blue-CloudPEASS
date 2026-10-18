"""Azure challenge paths and adjacent provider rows require exact, conditional evidence."""
from __future__ import annotations

import copy

import pytest

from peaso import privesc
from peaso.privesc.schema import validate_entry
from peaso.privesc.versioned_catalog import _verified_prior
from tests.test_peaso_privesc_schema_ext import reached, snapshot
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az
from tests.test_peaso_privesc_schema_ext_k8s import crole, crb, k8s_snap, user


PRIOR_ENTRIES, _ = _verified_prior()
ENTRIES = [{k: v for k, v in item.items() if k != "_file"}
           for item in PRIOR_ENTRIES.values()
           if "-v3-" in item["id"] and item["id"].split("-", 1)[0] in
           ("azure", "k8s", "digitalocean", "ibm")]


def test_historical_challenge_contract_is_inactive():
    assert len(ENTRIES) == 34
    active_ids = {entry["id"] for entry in privesc.load_catalog(strict=True)["entries"]}
    assert not active_ids.intersection(entry["id"] for entry in ENTRIES)


def _case(entry, status="collected", *, facts="verified"):
    provider = entry["provider"]
    if provider == "azure":
        scope = SUB
        source = (f"azure_challenge_foothold:{SUB}:" +
                  ("broker_token" if "-v3-03-" in entry["id"] else "anonymous")) \
            if "azure_challenge_foothold" in entry.get("source_kind", ()) else "u-alice"
        target = "target-principal" if entry["target"]["kind"] != "azure_verified_authority" else "eventhub-or-resource-1"
        kind = entry["target"]["kind"]
        if kind == "azure_user":
            snap = az(users=("u-alice", target))
        elif kind == "azure_service_principal":
            snap = az(sps=(target,))
        elif kind == "azure_managed_identity":
            snap = az(vms=[{"id": f"{SUB}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/target",
                            "type": "Microsoft.Compute/virtualMachines",
                            "identity": {"principalId": target}}])
        else:
            snap = az()
    elif provider == "k8s":
        scope, source, target = "c1", "k8s:c1:user:dev", "k8s:c1:sa:a:victim"
        snap = k8s_snap(clusterroles=[crole("view", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}])],
                        crbs=[crb("view-binding", "view", user("dev"))])
    else:
        scope, source, target = f"{provider}:account", f"{provider}:user:alice", "bounded-target-1"
        snap = snapshot(provider, [(provider + "_principal", scope, [{"Id": source}])])
    fact = {"TechniqueId": entry["id"], "SourceId": source,
            "TargetKind": entry["target"]["kind"], "TargetId": target,
            "TargetScope": scope, "Status": "verified", "VerifiedPreconditions": True,
            "EvidenceRef": "reviewed-exact-join-1"}
    if facts == "wrong_source":
        fact["SourceId"] = source + "-other"
    elif facts == "disproven":
        fact["Status"] = "disproven"
    elif facts == "unverified":
        fact["VerifiedPreconditions"] = False
    records = [] if facts == "empty" else [fact]
    if status is not None:
        snap["collections"].append({"type": provider + "_privesc_challenge_evidence", "scope": scope,
                                    "service": "privesc", "status": status, "items": records, "error": None})
    return snap, source


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e["id"])
def test_exact_verified_path_is_only_conditional(entry):
    assert validate_entry(entry)[0] == []
    snap, source = _case(entry)
    result = privesc.analyze(snap, entries=[entry])
    got = reached(result, source, entry["id"])
    assert len(got) == 1, (entry["id"], got)
    assert set(got.values()) == {"conditional"}
    assert all(f["status"] != "FAIL" for f in result["findings"])


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e["id"])
def test_complete_empty_or_disproven_collection_has_no_path(entry):
    for facts in ("empty", "disproven", "wrong_source"):
        snap, source = _case(entry, facts=facts)
        result = privesc.analyze(snap, entries=[entry])
        assert not reached(result, source, entry["id"]), (entry["id"], facts)


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e["id"])
def test_missing_partial_or_unverified_facts_are_unresolved(entry):
    for status, facts in ((None, "empty"), ("partial", "verified"), ("collected", "unverified")):
        snap, source = _case(entry, status, facts=facts)
        result = privesc.analyze(snap, entries=[entry])
        assert all(f["status"] != "FAIL" for f in result["findings"])
        if status is None:
            # No source-specific exploit input was observed. Preserve the coverage gap
            # without assigning a speculative path to every principal in the tenant.
            assert not reached(result, source, entry["id"])
            assert result["coverage"]
        else:
            # Historical evidence can remain incomplete without producing a
            # synthetic UNKNOWN principal or an actionable graph edge.
            assert not reached(result, source, entry["id"]), (entry["id"], status, facts)
            diagnostic = privesc.analyze(snap, entries=[entry], include_unknown=True)
            assert any(f["status"] == "UNKNOWN" for f in diagnostic["findings"])


def test_evidence_selector_cannot_claim_another_technique_or_derived_confidence():
    entry = copy.deepcopy(ENTRIES[0])
    selector = entry["target"]["selector"]
    key = next(iter(selector))
    selector[key] = "azure-v3-different"
    assert any("must equal the technique id" in e for e in validate_entry(entry)[0])
    entry = copy.deepcopy(ENTRIES[0])
    entry["confidence"] = "derived"
    assert any("must remain conditional" in e for e in validate_entry(entry)[0])


def test_exact_azure_principal_fact_reaches_inventory_id_only():
    entry = next(e for e in ENTRIES if e["provider"] == "azure" and
                 e["target"]["kind"] == "azure_service_principal")
    snap, source = _case(entry)
    assert reached(privesc.analyze(snap, entries=[entry]), source, entry["id"]) == {
        "target-principal": "conditional"}
    directory = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    directory["items"] = []
    result = privesc.analyze(snap, entries=[entry])
    assert not any(target.startswith("exact:") or target == "target-principal"
                   for target in reached(result, source, entry["id"]))
    assert any("exact target principal target-principal not in snapshot" in c.get("reason", "")
               for c in result["coverage"])


def test_mismatched_scope_and_conflicting_attestations_cannot_make_a_path():
    entry = next(e for e in ENTRIES if e["provider"] == "azure" and "-v3-09-" in e["id"])
    snap, source = _case(entry)
    collection = next(c for c in snap["collections"] if c["type"] == "azure_privesc_challenge_evidence")
    collection["items"][0]["TargetScope"] = SUB + "/resourceGroups/other"
    assert not reached(privesc.analyze(snap, entries=[entry]), source, entry["id"])
    collection["items"][0]["TargetScope"] = SUB
    collection["items"].append(copy.deepcopy(collection["items"][0]))
    result = privesc.analyze(snap, entries=[entry])
    assert all(f["status"] != "FAIL" for f in result["findings"])
    assert not reached(result, source, entry["id"])
    diagnostic = privesc.analyze(snap, entries=[entry], include_unknown=True)
    assert any(f["status"] == "UNKNOWN" for f in diagnostic["findings"])


def test_historical_ml_marquee_alias_is_inactive_without_exact_run_proof():
    ident = "azure-ml-compute-code-execution-marquee"
    assert ident not in {e["id"] for e in privesc.load_catalog()["entries"]}
    entry = {k: v for k, v in PRIOR_ENTRIES[ident].items() if k != "_file"}
    workspace = f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/w"
    compute = f"{workspace}/computes/c"
    resource = {"id": compute, "name": "c", "type": "Microsoft.MachineLearningServices/workspaces/computes",
                "identity": {"principalId": "mi-c", "type": "SystemAssigned"}}
    def run(*, action=True, resource_present=True, inventory="collected"):
        actions = ["Microsoft.MachineLearningServices/workspaces/jobs/write"] if action else ["Microsoft.Resources/deployments/read"]
        snap = az(assignments=[("u-alice", "User", SUB, ROLE_ID)], roles={ROLE_ID: (actions, [])},
                  graph=[resource] if resource_present else [])
        if inventory != "collected":
            next(c for c in snap["collections"] if c["type"] == "resource_graph")["status"] = inventory
        return privesc.analyze(snap, entries=[entry])
    # The archived rule produced a credential edge from jobs/write and a
    # compute attachment without proving the submitted job actually ran.
    assert reached(run(), "u-alice", entry["id"]) == {"mi-c": "conditional"}
    assert not reached(run(action=False), "u-alice", entry["id"])
    incomplete = run(resource_present=False, inventory="partial")
    assert all(f["status"] != "FAIL" for f in incomplete["findings"])
    assert not reached(incomplete, "u-alice", entry["id"])
