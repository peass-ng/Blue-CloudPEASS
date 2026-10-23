"""Mongo cluster root grants require the caller's exact child and usable auth."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-cosmos-mongocluster-user-write"
SOURCE = "11111111-1111-1111-1111-111111111111"
OTHER_USER = "22222222-2222-2222-2222-222222222222"
CLUSTER = RG + "/providers/Microsoft.DocumentDB/mongoClusters/main"
OTHER = RG + "/providers/Microsoft.DocumentDB/mongoClusters/other"
USER_WRITE = "Microsoft.DocumentDB/mongoClusters/users/write"
CLUSTER_WRITE = "Microsoft.DocumentDB/mongoClusters/write"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _cluster(*, rid=CLUSTER, state="Succeeded", mode="Default", auth=("MicrosoftEntraID",)):
    return {"id": rid, "type": "Microsoft.DocumentDB/mongoClusters",
            "properties": {"provisioningState": state, "createMode": mode,
                           "authConfig": {"allowedModes": list(auth)}}}


def _run(*, row=None, scope=None, actions=(USER_WRITE,), status="collected", principal_type="User"):
    row = _cluster() if row is None else row
    scope = scope or CLUSTER
    snap = az([(SOURCE, principal_type, scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              users=(SOURCE,) if principal_type == "User" else (),
              sps=(SOURCE,) if principal_type == "ServicePrincipal" else (),
              extra=[("mongo_cluster", SUB, [row] if status == "collected" else [], status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True), SOURCE, TID)


def test_self_root_grant_accepts_inherited_or_exact_child_scope():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + CLUSTER.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=CLUSTER + "/users/" + SOURCE) == expected
    assert _run(principal_type="ServicePrincipal") == expected


def test_other_user_or_cluster_permission_does_not_grant_self_root():
    assert set(_run(scope=CLUSTER + "/users/" + OTHER_USER).values()) == {"unknown"}
    assert _run(scope=OTHER) == {}
    assert _run(actions=(CLUSTER_WRITE,)) == {}
    assert _run(row=_cluster(mode="GeoReplica")) == {}
    assert _run(row=_cluster(state="Failed")) == {}


def test_disabled_entra_auth_needs_cluster_write_to_enable():
    row = _cluster(auth=("NativeAuth",))
    assert _run(row=row) == {}
    expected = {"azure_dataplane_admin:" + CLUSTER.casefold(): "conditional"}
    assert _run(row=row, actions=(USER_WRITE, CLUSTER_WRITE)) == expected
    assert set(_run(row=_cluster(state="Updating")).values()) == {"unknown"}
    assert set(_run(status="denied").values()) == {"unknown"}
