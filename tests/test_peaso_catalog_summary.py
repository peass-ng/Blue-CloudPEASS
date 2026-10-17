"""Console selector metadata retains every native ID and framework version."""
import json

import pytest
from fastapi.testclient import TestClient

from peaso.analysis import ANALYSIS_CHECKS
from peaso.checks import CHECKS
from peaso.checks.catalog import framework_catalog
from peaso.server import create_app
from peaso.server.catalog_view import summary
from peaso.server.config import Settings


def test_summary_preserves_all_native_ids_and_framework_filter_inputs():
    value = summary()
    assert {c["id"] for c in value["checks"]} == {c.id for c in CHECKS} | {c["id"] for c in ANALYSIS_CHECKS}
    assert value["framework_versions"] == framework_catalog()
    assert value["upstream_coverage"]["upstream"]["pending"] >= 0
    assert len(json.dumps(value, separators=(",", ":")).encode()) < 2 * 1024 * 1024
    assert value["details_url"] == "/api/catalog"


def test_summary_does_not_build_full_rule_or_technique_catalog(monkeypatch):
    import peaso.engine as engine
    summary.cache_clear()
    def forbidden():
        pytest.fail("Summary unexpectedly loaded the full catalog")
    monkeypatch.setattr(engine, "get_catalog", forbidden)
    monkeypatch.setattr(engine, "privesc_techniques", forbidden)
    assert summary()["view"] == "summary"


def test_summary_endpoint_is_authenticated_and_view_parameter_is_validated(tmp_path):
    token = "summary-fixture-token-0123456789abcdef"
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token=token)
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8000") as client:
        assert client.get("/api/catalog?view=summary").status_code == 401
        client.headers["Authorization"] = "Bearer " + token
        response = client.get("/api/catalog?view=summary")
        assert response.status_code == 200 and response.json()["view"] == "summary"
        assert client.get("/api/catalog?view=invalid").status_code == 422
