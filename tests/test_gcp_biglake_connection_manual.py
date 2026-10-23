"""The BigLake connection path needs manual proof and is not a scan check."""

import json
from pathlib import Path

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]
ID = "gcp-biglake-connection-table-bounded-storage-read"


def test_manual_only_biglake_connection_path_is_not_runnable_or_displayed():
    assert ID not in {entry["id"] for entry in privesc.catalog()["entries"]}
    for file in ("peaso/privesc/gcp_observed_impact.json",
                 "peaso/privesc/finding_explanation.json"):
        assert ID not in json.loads((ROOT / file).read_text())
    excluded = (ROOT / "peaso/privesc/catalog/gcp/_excluded.yaml").read_text()
    assert "connection-backed BigLake table" in excluded
