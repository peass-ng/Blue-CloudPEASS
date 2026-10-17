"""Indirect BigLake/BigQuery gains need exact source actions and before/after proof."""
from __future__ import annotations

import copy
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached, snapshot

SCOPE = "projects/p1"
SOURCE = "user:alice@corp.com"
ENTRIES = yaml.safe_load((Path(__file__).resolve().parents[1]
                          / "peaso/privesc/catalog/gcp/bounded_access.yaml").read_text())


def proof(entry):
    mechanism = entry["target"]["selector"]["gcp_bounded_mechanism"]
    connection = SCOPE + "/locations/us-central1/connections/c1"
    dataset = SCOPE + "/datasets/d1"
    source_dataset = SCOPE + "/datasets/sensitive"
    if mechanism == "biglake_connection_table":
        mutation, intermediate, protected = dataset, dataset + "/tables/t1", "gs://bucket/private/object.parquet"
    elif mechanism == "bigquery_remote_function":
        mutation, intermediate, protected = dataset, dataset + "/routines/r1", SCOPE + "/locations/us-central1/services/run1"
    elif mechanism == "bigquery_authorized_routine":
        mutation, intermediate, protected = source_dataset, dataset + "/routines/r1", source_dataset + "/tables/private"
    elif mechanism == "bigquery_authorized_view":
        mutation, intermediate, protected = source_dataset, dataset + "/tables/view1", source_dataset + "/tables/private"
    else:
        mutation, intermediate, protected = source_dataset, dataset + "/tables/view1", source_dataset + "/tables/private"
    bindings = {}
    for req in entry["requires"]["all_of"]:
        action = req["action"]
        bindings[action] = (connection if action.startswith("bigquery.connections.") else
                            mutation if action in ("bigquery.tables.create", "bigquery.routines.create")
                            or action.startswith("bigquery.datasets.") else
                            intermediate if action in ("bigquery.tables.get", "bigquery.tables.getData", "bigquery.routines.get")
                            else SCOPE)
    action = ("bigquery.tables.create" if mechanism == "biglake_connection_table" else
              "bigquery.routines.create" if mechanism == "bigquery_remote_function" else
              "bigquery.datasets.setIamPolicy")
    record = {"TechniqueId": entry["id"], "SourceId": SOURCE, "TargetScope": SCOPE,
              "Mechanism": mechanism, "MutationAction": action, "MutationResource": mutation,
              "IntermediateResource": intermediate, "ProtectedResource": protected,
              "GainedAction": entry["target"]["grants"][0], "ActionResources": bindings,
              "BeforeTestedAction": entry["target"]["grants"][0],
              "AfterTestedAction": entry["target"]["grants"][0],
              "BeforeTestedResource": protected, "AfterTestedResource": protected,
              "AfterAccessPath": intermediate, "PriorSourceAccessDenied": True,
              "MutationAccepted": True, "IntermediateUsable": True,
              "AfterIndirectActionAllowed": True, "PriorAccessCheckedAt": "2026-10-16T11:01:00Z",
              "MutationObservedAt": "2026-10-16T11:02:00Z",
              "AfterAccessCheckedAt": "2026-10-16T11:03:00Z",
              "EvidenceObservedAt": "2026-10-16T11:04:00Z",
              "Status": "verified", "EvidenceRef": "reviewed-indirect-access-1"}
    if mechanism in ("biglake_connection_table", "bigquery_remote_function"):
        record.update(ConnectionResource=connection,
                      ConnectionPrincipalId="serviceAccount:connection@p1.iam.gserviceaccount.com",
                      ConnectionBoundToIntermediate=True,
                      ConnectionCanAccessProtectedResource=True)
    elif mechanism == "bigquery_authorized_dataset":
        record.update(AuthorizationEntryResource=mutation,
                      AuthorizedDatasetResource=dataset,
                      AuthorizationEntryMatchesDataset=True,
                      AuthorizationTargetTypes=["VIEWS"],
                      IntermediateExistingBeforeMutation=True)
    else:
        record.update(AuthorizationEntryResource=mutation,
                      AuthorizationEntryMatchesIntermediate=True,
                      IntermediateExistingBeforeMutation=True)
    return record


def case(entry, records=None, *, status="collected", permissions=None):
    actions = [req["action"] for req in entry["requires"]["all_of"]]
    role = {"name": SCOPE + "/roles/accessWriter",
            "includedPermissions": actions if permissions is None else permissions}
    snap = snapshot("gcp", [
        ("project", SCOPE, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", SCOPE, [{"name": SCOPE, "bindings": [{"role": role["name"], "members": [SOURCE]}]}]),
        ("iam_role", SCOPE, [role]), ("service_account", SCOPE, []),
        ("iam_deny_policy", SCOPE, [], "empty"),
        ("gcp_bounded_access_gain_evidence", SCOPE,
         [proof(entry)] if records is None else records, status),
    ])
    snap["created_at"] = "2026-10-16T11:05:00Z"
    return snap


def paths(entry, snap):
    result = privesc.analyze(snap, entries=[entry])
    return {target: confidence for target, confidence in reached(result, SOURCE, entry["id"]).items()
            if not target.startswith(("unknown:", "unresolved:"))}


def test_all_five_narrow_bounded_gains_need_unique_exact_proof():
    for entry in ENTRIES:
        assert validate_entry(entry)[0] == []
        got = paths(entry, case(entry))
        assert len(got) == 1, entry["id"]
        assert next(iter(got)).startswith("gcp_verified_authority:bounded:")
        assert set(got.values()) == {"conditional"}
        assert paths(entry, case(entry, [])) == {}
        assert paths(entry, case(entry, status="partial")) == {}
        assert paths(entry, case(entry, [proof(entry), proof(entry)])) == {}


def test_wrong_action_resource_scope_connection_acl_or_after_result_fails_closed():
    for entry in ENTRIES:
        base = proof(entry)
        action = next(iter(base["ActionResources"]))
        for field, value in (("SourceId", "user:bob@corp.com"),
                             ("TargetScope", "projects/p2"),
                             ("PriorSourceAccessDenied", False),
                             ("MutationAccepted", False),
                             ("AfterIndirectActionAllowed", False),
                             ("AfterAccessPath", SCOPE + "/datasets/other/tables/x"),
                             ("AfterTestedResource", SCOPE + "/datasets/other/tables/x"),
                             ("MutationObservedAt", "2026-10-16T11:00:00Z"),
                             ("EvidenceRef", "")):
            altered = copy.deepcopy(base)
            altered[field] = value
            assert paths(entry, case(entry, [altered])) == {}, (entry["id"], field)
        altered = copy.deepcopy(base)
        altered["ActionResources"][action] = SCOPE + "/datasets/wrong"
        assert paths(entry, case(entry, [altered])) == {}
        altered = copy.deepcopy(base)
        altered["IntermediateResource"] = SCOPE + "/datasets/d1/services/wrong"
        altered["AfterAccessPath"] = altered["IntermediateResource"]
        assert paths(entry, case(entry, [altered])) == {}
        altered = copy.deepcopy(base)
        altered["ProtectedResource"] = SCOPE + "/datasets/sensitive/views/wrong"
        altered["BeforeTestedResource"] = altered["ProtectedResource"]
        altered["AfterTestedResource"] = altered["ProtectedResource"]
        assert paths(entry, case(entry, [altered])) == {}
        missing = entry["requires"]["all_of"][0]["action"]
        assert paths(entry, case(entry, permissions=[a for a in base["ActionResources"] if a != missing])) == {}
        if base["Mechanism"] in ("biglake_connection_table", "bigquery_remote_function"):
            altered = {**base, "ConnectionResource": SCOPE + "/locations/x/connections/wrong"}
        else:
            altered = {**base, "AuthorizationEntryResource": SCOPE + "/datasets/wrong"}
        assert paths(entry, case(entry, [altered])) == {}
        if base["Mechanism"] not in ("biglake_connection_table", "bigquery_remote_function"):
            altered = {**base, "IntermediateExistingBeforeMutation": False}
            assert paths(entry, case(entry, [altered])) == {}
        if base["Mechanism"] == "bigquery_authorized_dataset":
            for field, value in (("AuthorizedDatasetResource", SCOPE + "/datasets/wrong"),
                                 ("AuthorizationTargetTypes", ["ROUTINES"]),
                                 ("AuthorizationEntryMatchesDataset", False)):
                altered = copy.deepcopy(base)
                altered[field] = value
                assert paths(entry, case(entry, [altered])) == {}, (entry["id"], field)
