"""A connection policy write must add use on the same named connection."""

import sys
import types
from pathlib import Path

import pytest

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
FIRST = PROJECT + "/locations/US/connections/first"
SECOND = PROJECT + "/locations/US/connections/second"
ACTOR = "user:operator@example.com"
WRITER = PROJECT + "/roles/connectionPolicyWriter"


def snapshot(*, connection_policy="collected", project_writer=False, prior_use=False,
             duplicate=False, details="collected"):
    def row(kind, entries, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind, "status": status,
                "items": entries, "error": None}

    def connection(name, bindings):
        return {"name": name, "cloudSql": {"instanceId": "p1:us-central1:db", "database": "app"},
                "iamPolicy": {"bindings": bindings},
                "_coverage": {"connectionDetails": {"status": details},
                              "iamPolicy": {"status": connection_policy}}}

    local_binding = {"role": WRITER, "members": [ACTOR]}
    rows = [connection(FIRST, [local_binding]), connection(SECOND, [])]
    if duplicate:
        rows.append(connection(FIRST, [local_binding]))
    project_bindings = []
    if project_writer:
        project_bindings.append(local_binding)
    if prior_use:
        project_bindings.append({"role": "roles/bigquery.connectionUser", "members": [ACTOR]})
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT], "metadata": {},
            "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [{"name": WRITER,
                                  "includedPermissions": ["bigquery.connections.setIamPolicy"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": project_bindings}]),
                row("bigquery_connection", rows),
                row("org_policy_effective", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
            ]}


def found(snap):
    entry = next(e for e in privesc.catalog()["entries"]
                 if e["id"] == "gcp-bigquery-connections-setiampolicy-connection-self-grant")
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == ACTOR
            for target, grant in reach.targets.items()}


def test_only_exact_connection_with_new_use_permission_is_reported():
    got = found(snapshot())
    assert got == {"gcp_verified_authority:possible-bigquery-connection-self-grant:" + FIRST:
                   "conditional"}
    assert not any("second" in target for target in got)
    assert not any(target.startswith("unresolved:") for target in got)


@pytest.mark.parametrize("kind", ["cloudResource", "aws", "azure", "spark"])
def test_other_named_connection_types_can_gain_use_without_claiming_execution(kind):
    snap = snapshot()
    first = next(row for row in snap["collections"] if row["type"] == "bigquery_connection")["items"][0]
    first.pop("cloudSql")
    first[kind] = {"configured": True}
    assert found(snap)["gcp_verified_authority:possible-bigquery-connection-self-grant:" + FIRST] == "conditional"


def test_existing_use_and_duplicate_connection_do_not_become_a_gain():
    assert not any(target.startswith("gcp_verified_authority:")
                   for target in found(snapshot(prior_use=True)))
    assert not any(target.startswith("gcp_verified_authority:")
                   for target in found(snapshot(duplicate=True)))


def test_incomplete_connection_policy_or_details_stays_unresolved():
    for snap in (snapshot(connection_policy="denied", project_writer=True),
                 snapshot(details="denied", project_writer=True)):
        got = found(snap)
        assert not any(target.startswith("gcp_verified_authority:") for target in got)
        assert any(target.startswith("unresolved:") for target in got)
    snap = snapshot()
    next(row for row in snap["collections"] if row["type"] == "group_membership")["status"] = "denied"
    assert not any(target.startswith("gcp_verified_authority:") for target in found(snap))


def test_unsearched_regions_remain_visible_when_known_regions_are_empty():
    snap = snapshot(project_writer=True)
    connection = next(row for row in snap["collections"] if row["type"] == "bigquery_connection")
    connection["items"] = []
    connection["status"] = "empty"
    snap["metadata"] = {"collector": "native-gcp",
                        "bigquery_connection_location_mode": "dataset_and_selected"}
    assert any(target.startswith("unknown:gcp_verified_authority:") for target in found(snap)), found(snap)


@pytest.mark.parametrize("dataset,explicit_location", [(True, False), (False, True)])
def test_collector_reads_policy_for_non_spark_connection(monkeypatch, dataset, explicit_location):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def request(self, method, url, **kwargs):
            if url.endswith("/datasets"):
                return {"datasets": ([{"id": "p1:app", "datasetReference":
                    {"projectId": "p1", "datasetId": "app"}}] if dataset else [])}, "datasets"
            if url.endswith("/datasets/app"):
                return {"id": "p1:app", "datasetReference":
                    {"projectId": "p1", "datasetId": "app"}, "location": "US", "access": []}, "dataset"
            if url.endswith("/connections"):
                return {"connections": [{"name": FIRST, "cloudSql": {"instanceId": "db"}}]}, "connections"
            if url.endswith("/connections/first"):
                return {"name": FIRST, "cloudSql": {"instanceId": "db"}}, "details"
            if url.endswith("/connections/first:getIamPolicy"):
                return {"bindings": []}, "policy"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigquery_connection"], "include_inherited": False,
        **({"bigquery_connection_locations": ["US"]} if explicit_location else {}),
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    collector._data_project_binding = lambda scope: {"project_id": "p1", "project_number": "111"}
    collected = collector.collect()
    row = next(row for row in collected["collections"] if row["type"] == "bigquery_connection")
    assert row["status"] == "collected"
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert collected["metadata"]["bigquery_connection_location_mode"] == "dataset_and_selected"
    model = GcpModel(collected)
    model.current_selector = {"gcp_resource_self_grant": True}
    model.current_entry = {"id": "gcp-bigquery-connections-setiampolicy-connection-self-grant"}
    assert model.unknown_target_scopes("gcp_verified_authority")[PROJECT] == "unsearched_connection_locations"


def test_reviewed_mutation_requires_same_connection_binding_and_ordered_proof():
    technique = "gcp-bigquery-connections-setiampolicy-connection-self-grant"
    review = {"TechniqueId": technique, "SourceId": ACTOR, "TargetScope": PROJECT,
              "TargetResource": FIRST, "GrantedResource": FIRST,
              "AccessPermission": "bigquery.connections.setIamPolicy",
              "GrantedPrincipalId": ACTOR, "GrantedPermissions": ["bigquery.connections.use"],
              "PriorTestedPermission": "bigquery.connections.use",
              "AfterTestedPermission": "bigquery.connections.use",
              "PriorTestedResource": FIRST, "AfterTestedResource": FIRST,
              "AcceptedBindingMember": ACTOR,
              "AcceptedBindingRole": "roles/bigquery.connectionUser",
              "BindingPresentAtSnapshot": True,
              "PriorAccessCheckedAt": "2026-10-21T10:00:00Z",
              "PolicyMutationObservedAt": "2026-10-21T10:01:00Z",
              "AfterAccessCheckedAt": "2026-10-21T10:02:00Z",
              "BindingCheckedAt": "2026-10-21T10:03:00Z",
              "EvidenceObservedAt": "2026-10-21T10:04:00Z",
              "PriorPermissionAbsent": True, "PolicyMutationAuthorized": True,
              "PolicyMutationAccepted": True, "AfterPermissionAllowed": True,
              "Status": "verified", "EvidenceRef": "reviewed-connection-policy-1"}

    def reviewed(record):
        snap = snapshot(project_writer=True)
        snap["created_at"] = "2026-10-21T10:05:00Z"
        connection = next(row for row in snap["collections"] if row["type"] == "bigquery_connection")
        connection["items"][0]["iamPolicy"]["bindings"] = [
            {"role": "roles/bigquery.connectionUser", "members": [ACTOR]}]
        snap["collections"].append({"type": "gcp_resource_self_grant_evidence",
            "scope": PROJECT, "service": "reviewed", "status": "collected", "items": [record]})
        return found(snap)

    assert any(target.startswith("gcp_verified_authority:self-grant:")
               for target in reviewed(review))
    wrong = dict(review, AfterTestedResource=SECOND)
    assert not any(target.startswith("gcp_verified_authority:self-grant:")
                   for target in reviewed(wrong))
