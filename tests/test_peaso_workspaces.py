from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import SQLiteStore


class WorkspaceIdentities:
    def authenticate(self, authorization):
        accounts = {
            "Bearer owner": Identity("owner", True, email="owner@example.com", email_verified=True),
            "Bearer reader": Identity("reader", False, email="reader@example.com", email_verified=True),
            "Bearer writer": Identity("writer", False, email="writer@example.com", email_verified=True),
            "Bearer outsider": Identity("outsider", False, email="outsider@example.com", email_verified=True),
        }
        if authorization not in accounts:
            raise HTTPException(401, "Invalid authentication")
        return accounts[authorization]

    def find_user_by_email(self, email):
        mapping = {"reader@example.com": "reader", "writer@example.com": "writer", "outsider@example.com": "outsider"}
        return {"user_id": mapping[email], "email": email} if email in mapping else None


def test_workspace_invitation_roles_and_isolation(tmp_path):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", auth_mode="cognito")
    store = SQLiteStore(settings.state_dir)
    app = create_app(settings, store=store, authenticator=WorkspaceIdentities())
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        owner = {"Authorization": "Bearer owner"}
        reader = {"Authorization": "Bearer reader"}
        writer = {"Authorization": "Bearer writer"}
        outsider = {"Authorization": "Bearer outsider"}
        assert client.get("/api/workspaces", headers=owner).json()["items"][0]["name"] == "Personal Workspace"
        created = client.post("/api/workspaces", headers=owner, json={"name": "Team Alpha"})
        assert created.status_code == 201, created.text
        workspace_id = created.json()["id"]
        selected = {"X-Workspace-Id": workspace_id}
        private_auth = app.state.cipher.encrypt({"auth": {}, "options": {}})
        store.add_connector("owner", {"name": "Private connector", "provider": "aws", "scopes": [], "options": {}}, private_auth)
        shared = store.add_connector(workspace_id, {"name": "Shared connector", "provider": "aws", "scopes": [], "options": {}}, private_auth)
        assert client.post("/api/workspaces", headers=reader, json={"name": "Other Team"}).status_code == 403
        assert client.post("/api/workspaces/personal/invitations", headers=owner, json={"email": "reader@example.com", "role": "read"}).status_code == 403
        assert client.post(f"/api/workspaces/{workspace_id}/invitations", headers=owner, json={"email": "missing@example.com", "role": "read"}).status_code == 404
        assert client.post(f"/api/workspaces/{workspace_id}/invitations", headers=owner, json={"email": "reader@example.com", "role": "read"}).status_code == 201
        assert client.get("/api/connectors", headers=reader | selected).status_code == 403
        assert client.get("/api/workspaces/invitations", headers=reader).json()["items"][0]["name"] == "Team Alpha"
        assert client.post(f"/api/workspaces/invitations/{workspace_id}/accept", headers=reader).status_code == 200
        visible = client.get("/api/connectors", headers=reader | selected)
        assert visible.status_code == 200
        assert [item["name"] for item in visible.json()["items"]] == ["Shared connector"]
        assert client.delete(f"/api/connectors/{shared['id']}", headers=reader | selected).status_code == 403
        assert client.post("/api/scans", headers=reader | selected, json={"connector_id": "missing"}).status_code == 403
        assert client.post(f"/api/workspaces/{workspace_id}/invitations", headers=reader, json={"email": "writer@example.com", "role": "write"}).status_code == 403
        assert client.post(f"/api/workspaces/{workspace_id}/invitations", headers=owner, json={"email": "writer@example.com", "role": "write"}).status_code == 201
        assert client.post(f"/api/workspaces/invitations/{workspace_id}/accept", headers=writer).status_code == 200
        assert client.post("/api/scans", headers=writer | selected, json={"connector_id": "missing"}).status_code == 404
        assert client.post(f"/api/workspaces/{workspace_id}/invitations", headers=writer, json={"email": "outsider@example.com", "role": "read"}).status_code == 403
        assert client.get("/api/connectors", headers=outsider | selected).status_code == 403
        assert client.patch(f"/api/workspaces/{workspace_id}/members/reader", headers=owner, json={"role": "admin"}).status_code == 200
        assert client.post(f"/api/workspaces/{workspace_id}/invitations", headers=reader, json={"email": "outsider@example.com", "role": "read"}).status_code == 201
        assert client.post(f"/api/workspaces/invitations/{workspace_id}/decline", headers=outsider).status_code == 200
        assert client.get("/api/connectors", headers=outsider | selected).status_code == 403
        assert client.post(f"/api/workspaces/{workspace_id}/invitations", headers=reader, json={"email": "outsider@example.com", "role": "read"}).status_code == 201
        assert client.delete(f"/api/workspaces/{workspace_id}/invitations/outsider", headers=owner).status_code == 204
        assert client.get("/api/workspaces/invitations", headers=outsider).json()["items"] == []
        assert client.patch(f"/api/workspaces/{workspace_id}/members/reader", headers=owner, json={"role": "read"}).status_code == 200
        assert client.post(f"/api/workspaces/{workspace_id}/invitations", headers=reader, json={"email": "outsider@example.com", "role": "read"}).status_code == 403
        assert [item["name"] for item in client.get("/api/connectors", headers=owner).json()["items"]] == ["Private connector"]
        assert client.delete(f"/api/connectors/{shared['id']}", headers=writer | selected).status_code == 204


def test_workspace_name_and_owner_limits(tmp_path):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", auth_mode="cognito")
    with TestClient(create_app(settings, authenticator=WorkspaceIdentities()), base_url="http://127.0.0.1:8000") as client:
        owner = {"Authorization": "Bearer owner"}
        for number in range(5):
            assert client.post("/api/workspaces", headers=owner, json={"name": f"Team {number}"}).status_code == 201
        assert client.post("/api/workspaces", headers=owner, json={"name": "Team 0"}).status_code == 403
        assert client.post("/api/workspaces", headers=owner, json={"name": "Team 5"}).status_code == 403


def test_workspace_names_and_people_limit_are_transactional(tmp_path):
    from peaso.storage import StoreError
    store = SQLiteStore(tmp_path / "state")
    first = store.create_workspace("owner", "Research", "research", "owner@example.com")
    try:
        store.create_workspace("another", "RESEARCH", "research", "another@example.com")
    except StoreError as exc:
        assert exc.status == 409
    else:
        raise AssertionError("Case-insensitive duplicate workspace name was accepted")
    for index in range(100):
        store.invite_workspace(first["id"], f"user-{index}", f"user-{index}@example.com", "read", "owner")
    try:
        store.invite_workspace(first["id"], "user-100", "user-100@example.com", "read", "owner")
    except StoreError as exc:
        assert exc.status == 403
    else:
        raise AssertionError("The 101st person was invited")
    store.respond_workspace_invitation(first["id"], "user-0", True)
    try:
        store.invite_workspace(first["id"], "user-100", "user-100@example.com", "read", "owner")
    except StoreError as exc:
        assert exc.status == 403
    else:
        raise AssertionError("Accepting an invitation freed a person slot")
    store.respond_workspace_invitation(first["id"], "user-1", False)
    store.invite_workspace(first["id"], "user-100", "user-100@example.com", "read", "owner")
    members, pending = store.workspace_people(first["id"])
    assert len(members) == 2 and len(pending) == 99
