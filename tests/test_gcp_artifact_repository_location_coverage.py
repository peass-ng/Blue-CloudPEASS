"""A location blocked by policy cannot prove a gcr.io repository is absent."""

import sys
import types
from pathlib import Path


def test_location_policy_skip_is_preserved_in_snapshot(monkeypatch):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def request(self, method, url, **kwargs):
            assert url.endswith("/projects/p1/locations/us/repositories")
            raise gcp.ReadError("denied", "location_restricted", http_status=403,
                                reason="LOCATION_POLICY_VIOLATED")

    connector = {"provider": "gcp", "scopes": ["projects/p1"], "options": {
        "inventories": ["artifact_repository"], "artifactregistry_locations": ["us"],
        "include_inherited": False, "concurrency": 1}}
    result = gcp.GCPCollector(connector, transport=Transport()).collect()
    assert result["metadata"]["regional_policy_skips"] == {
        "artifactregistry": {"projects/p1": ["us"]}}
    row = next(row for row in result["collections"] if row["type"] == "artifact_repository")
    assert row["status"] == "empty"
