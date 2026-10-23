"""Mongo administrator reset reaches only an exact usable primary cluster."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-cosmos-mongocluster-admin-password"
CLUSTER = RG + "/providers/Microsoft.DocumentDB/mongoClusters/main"
OTHER = RG + "/providers/Microsoft.DocumentDB/mongoClusters/other"
ACTION = "Microsoft.DocumentDB/mongoClusters/write"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _cluster(*, rid=CLUSTER, state="Succeeded", mode="Default", auth=("NativeAuth",)):
    return {"id": rid, "type": "Microsoft.DocumentDB/mongoClusters", "name": rid.rsplit("/", 1)[-1],
            "properties": {"provisioningState": state, "createMode": mode,
                           "authConfig": {"allowedModes": list(auth)}}}


def _run(*, rows=None, scope=CLUSTER, actions=(ACTION,), status="collected", graph=()):
    rows = [_cluster()] if rows is None else rows
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=graph, extra=[("mongo_cluster", SUB, rows if status == "collected" else [], status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   "u-alice", TID)


def test_exact_native_primary_cluster_and_inherited_permission():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + CLUSTER.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    # The same write can re-enable NativeAuth during password reset.
    assert _run(rows=[_cluster(auth=("MicrosoftEntraID",))]) == expected


def test_unrelated_grants_and_unusable_or_replica_clusters_are_excluded():
    assert _run(scope=OTHER) == {}
    assert _run(actions=("Microsoft.DocumentDB/mongoClusters/read",)) == {}
    assert _run(rows=[_cluster(state="Failed")]) == {}
    assert _run(rows=[_cluster(mode="GeoReplica")]) == {}
    linked_replica = _cluster()
    linked_replica["properties"]["replicaParameters"] = {"sourceResourceId": OTHER}
    assert _run(rows=[linked_replica]) == {}
    assert set(_run(rows=[_cluster(state="Updating")]).values()) == {"unknown"}


def test_resource_graph_alone_does_not_substitute_for_native_cluster_state():
    graph = [_cluster()]
    assert set(_run(status="denied", graph=graph).values()) == {"unknown"}
    assert _run(rows=[], status="empty", graph=graph) == {}


def test_native_cluster_detail_keeps_state_and_never_stores_administrator_password():
    path = Path(__file__).resolve().parents[1] / "peaso/collectors/azure_mongo_cluster_metadata.py"
    spec = importlib.util.spec_from_file_location("mongo_cluster_metadata_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    row = _cluster()
    row["properties"]["administrator"] = {"userName": "admin", "password": "private-password"}
    row["properties"]["replicaParameters"] = {"sourceResourceId": OTHER, "connectionString": "secret"}
    safe = module.project(row)
    assert safe["properties"]["provisioningState"] == "Succeeded"
    assert safe["properties"]["replicaParameters"] == {"sourceResourceId": OTHER}
    assert "private-password" not in repr(safe)
    assert "secret" not in repr(safe)
