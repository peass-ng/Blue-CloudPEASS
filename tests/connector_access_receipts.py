"""Synthetic connector readiness receipts for API tests unrelated to cloud access."""


def mock_access_pass(monkeypatch):
    monkeypatch.setattr("peaso.server.access_check.check_access", lambda *args, **kwargs: {
        "status": "pass", "issues": [], "principals": []})


def checked_create(client, body):
    checked = client.post("/api/connectors/check-access", json=body)
    assert checked.status_code == 200, checked.text
    assert checked.json()["status"] == "pass", checked.text
    return {**body, "check_token": checked.json()["check_token"]}


def checked_edit(client, ident, *, name, provider, scopes, options, auth=None, prepared_id=None):
    candidate = {"name": name, "provider": provider, "scopes": scopes,
                 "options": options, "auth": auth or {}, "connector_id": ident}
    if prepared_id is not None:
        candidate["prepared_id"] = prepared_id
    checked = client.post("/api/connectors/check-access", json=candidate)
    assert checked.status_code == 200, checked.text
    assert checked.json()["status"] == "pass", checked.text
    return checked.json()["check_token"]
