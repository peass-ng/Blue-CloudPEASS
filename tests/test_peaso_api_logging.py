"""Unexpected API failures log safe source metadata without exception/request contents."""
import json
import logging
import uuid

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore


@pytest.fixture
def failing_app(tmp_path, monkeypatch):
    # Exercise the real HTTP middleware with fully local dependencies. A failed
    # test request must never initialize a hosted credential or identity client.
    import peaso.server.app as module

    monkeypatch.setattr(module, "CredentialCipher", lambda identity_dir: object())
    settings = Settings(
        state_dir=tmp_path / "state",
        identity_dir=tmp_path / "identity",
        auth_mode="local",
        origins=("http://127.0.0.1:8000",),
    )
    app = create_app(
        settings,
        store=SQLiteStore(settings.state_dir),
        artifacts=FileArtifacts(tmp_path / "artifacts"),
        authenticator=object(),
    )

    @app.post("/api/logging-failure/{ident}")
    async def raised_failure(ident: str, request: Request):
        body = await request.json()
        # The exception itself contains sensitive values: safe extras alone are
        # insufficient if a logging formatter can still render exc_info.
        raise RuntimeError(" ".join([
            "EXCEPTION_SECRET_SENTINEL", ident, request.query_params["password"],
            request.headers["authorization"], request.headers["cookie"],
            request.headers["x-request-id"], body["password"], body["refresh_token"],
        ]))

    @app.post("/api/logging-rejection")
    async def expected_rejection():
        raise HTTPException(400, "Expected rejection")

    return app


def test_unexpected_exception_logs_safe_metadata_without_exception_or_request_contents(failing_app, caplog):
    caplog.set_level(logging.ERROR, logger="peaso.server")
    markers = {
        "exception_secret": "EXCEPTION_SECRET_SENTINEL",
        "path": "PATH_SENSITIVE_SENTINEL",
        "query": "QUERY_SENSITIVE_SENTINEL",
        "header": "HEADER_SENSITIVE_SENTINEL",
        "cookie": "COOKIE_SENSITIVE_SENTINEL",
        "body": "BODY_SENSITIVE_SENTINEL",
        "request_id": "CLIENT_REQUEST_ID_SENTINEL",
    }
    with TestClient(failing_app, base_url="http://127.0.0.1:8000") as client:
        for _ in range(2):
            response = client.post(
                "/api/logging-failure/" + markers["path"],
                params={"password": markers["query"]},
                headers={
                    "Authorization": "Bearer " + markers["header"],
                    "Cookie": "refresh=" + markers["cookie"],
                    "X-Request-ID": markers["request_id"],
                },
                json={"password": markers["body"], "refresh_token": markers["body"]},
            )
            assert response.status_code == 500
            assert response.json() == {"detail": "Request processing failed"}

    records = [record for record in caplog.records if record.name == "peaso.server"]
    assert len(records) == 2
    standard = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)
    request_ids = []
    for record in records:
        assert record.getMessage().startswith("requestfailed type=RuntimeError source=peaso/server/app.py:")
        assert record.exc_info is None
        assert record.exc_text is None
        assert record.exception_type == "RuntimeError"
        assert record.source_file == "peaso/server/app.py"
        assert record.source_function == "protect"
        assert isinstance(record.source_line, int) and record.source_line > 0
        custom = set(record.__dict__) - standard - {"message", "asctime"}
        assert custom == {"method", "route", "request_id", "exception_type", "source_file", "source_function", "source_line"}
        assert record.method == "POST"
        assert record.route == "/api/logging-failure/{ident}"
        assert uuid.UUID(record.request_id).version == 4
        request_ids.append(record.request_id)
        metadata = json.dumps({name: getattr(record, name) for name in custom})
        assert all(marker not in metadata for marker in markers.values())
    assert len(set(request_ids)) == 2
    assert "type=RuntimeError" in caplog.text
    assert "source=peaso/server/app.py:" in caplog.text
    assert "function=protect" in caplog.text
    assert "Traceback" not in caplog.text
    assert "raised_failure" not in caplog.text
    assert all(marker not in caplog.text for marker in markers.values())


def test_expected_http_error_is_not_logged_as_an_unexpected_failure(failing_app, caplog):
    caplog.set_level(logging.ERROR, logger="peaso.server")
    with TestClient(failing_app, base_url="http://127.0.0.1:8000") as client:
        response = client.post("/api/logging-rejection")
    assert response.status_code == 400
    assert response.json() == {"detail": "Expected rejection"}
    assert not [record for record in caplog.records if record.name == "peaso.server"]
