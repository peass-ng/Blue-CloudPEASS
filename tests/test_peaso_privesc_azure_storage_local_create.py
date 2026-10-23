"""New Storage local-user paths require an exact writable account and container."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_scoped_credentials import CONTAINER, LOCAL_USER, STORAGE_ACCOUNT, storage_case


TID = "azure-storage-local-user-create-with-sftp-access"
ENTRY = next({key: value for key, value in item.items() if not key.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
PROBE = STORAGE_ACCOUNT.lower() + "/localusers/peassprobe"


def _run(*, account_write=True, change=None):
    snap, parent, local = storage_case(ENTRY)
    if account_write:
        next(c for c in snap["collections"] if c["type"] == "role_assignment")["items"][0]["properties"]["scope"] = STORAGE_ACCOUNT
    if change:
        change(snap, parent, local)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)])


def test_create_user_on_verified_sftp_account_with_existing_container():
    assert validate_entry(ENTRY)[0] == []
    result = _run()
    target_id = "azure_storage_local_user:" + PROBE
    assert reached(result, "u-alice", TID) == {target_id: "conditional"}
    target = next(node for node in result["graph"]["nodes"] if node["id"] == target_id)
    assert target["attrs"]["prospective"] is True
    assert target["attrs"]["effective_rights"] == []
    assert target["attrs"]["assignable_rights"] == [{"container": CONTAINER.lower(), "permissions": "r"}]


def test_child_write_cannot_create_a_sibling_user():
    assert reached(_run(account_write=False), "u-alice", TID) == {}


def test_unverified_account_or_container_does_not_establish_new_identity():
    changes = [
        lambda snap, parent, local: parent["properties"].update(isSftpEnabled=False),
        lambda snap, parent, local: parent["properties"].update(isLocalUserEnabled=False),
        lambda snap, parent, local: next(c for c in snap["collections"] if c["type"] == "storage_container").update(status="partial"),
        lambda snap, parent, local: next(c for c in snap["collections"] if c["type"] == "storage_local_user").update(status="denied"),
        lambda snap, parent, local: next(c for c in snap["collections"] if c["type"] == "storage_container")["items"].clear(),
    ]
    for change in changes:
        assert "conditional" not in reached(_run(change=change), "u-alice", TID).values()


def test_empty_user_inventory_allows_create_and_taken_probe_name_is_avoided():
    def empty_users(snap, parent, local):
        next(c for c in snap["collections"] if c["type"] == "storage_local_user").update(status="empty", items=[])
    assert reached(_run(change=empty_users), "u-alice", TID) == {
        "azure_storage_local_user:" + PROBE: "conditional"}

    def taken_name(snap, parent, local):
        next(c for c in snap["collections"] if c["type"] == "storage_local_user")["items"].append({
            "id": STORAGE_ACCOUNT + "/localUsers/peassprobe", "properties": local["properties"]})
    assert reached(_run(change=taken_name), "u-alice", TID) == {
        "azure_storage_local_user:" + PROBE + "1": "conditional"}
