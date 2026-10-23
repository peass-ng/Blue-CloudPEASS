"""Existing authorized-dataset view proof is manual-only."""

import json
from pathlib import Path

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]
IDS = {
    "gcp-bigquery-authorized-dataset-existing-view-bounded-table-access",
    "gcp-bigquery-authorized-view-bounded-table-access",
}


def test_existing_authorized_dataset_view_is_not_runnable_or_displayed():
    active = {entry["id"] for entry in privesc.catalog()["entries"]}
    assert IDS.isdisjoint(active)
    for file in ("peaso/privesc/gcp_observed_impact.json",
                 "peaso/privesc/finding_explanation.json"):
        assert IDS.isdisjoint(json.loads((ROOT / file).read_text()))
    excluded = (ROOT / "peaso/privesc/catalog/gcp/_excluded.yaml").read_text()
    assert "existing view in an authorized dataset" in excluded
