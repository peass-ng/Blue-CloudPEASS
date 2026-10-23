"""Source-only App Hosting repointing remains documented but cannot emit a scan edge."""
from __future__ import annotations

import json
from pathlib import Path

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]
MANUAL_ID = "gcp-firebaseapphosting-backends-update-source"


def test_source_only_repointing_is_excluded_from_active_catalog_and_ui_copy():
    active = {entry["id"] for entry in privesc.catalog()["entries"]}
    assert MANUAL_ID not in active
    assert "gcp-firebaseapphosting-backends-update-actas" in active
    assert "gcp-firebaseapphosting-build-rollout-existing-backend" in active
    excluded = (ROOT / "peaso/privesc/catalog/gcp/_excluded.yaml").read_text()
    assert MANUAL_ID in excluded and "Manual-only path" in excluded
    for path in (ROOT / "peaso/privesc/finding_explanation.json",
                 ROOT / "peaso/privesc/gcp_observed_impact.json"):
        assert MANUAL_ID not in json.loads(path.read_text())
