"""Manually proven GCP paths must not appear in the active technique catalog."""

import json
from pathlib import Path

import pytest
import yaml

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]
IDS = (
    "gcp-audit-s01-02-loosen-access-level-for-atta",
    "gcp-audit-s01-03-create-a-bridge-perimeter-jo",
    "gcp-audit-s01-04-delete-a-perimeter-or-access",
    "gcp-audit-s01-06-delete-or-weaken-a-group-con",
    "gcp-audit-s01-21-repoint-accessible-gateway-a",
    "gcp-audit-s01-35-widen-a-view-caller-can-alre",
    "gcp-biglake-connection-table-bounded-storage-read",
    "gcp-bigquery-authorized-routine-bounded-table-access",
    "gcp-bigquery-authorized-view-bounded-table-access",
    "gcp-bigquery-authorized-dataset-existing-view-bounded-table-access",
    "gcp-dataproc-staging-object-plant",
    "gcp-bigquery-table-row-credential",
    "gcp-bigtable-row-credential",
    "gcp-bms-direct-initial-secret-exact-server-user",
    "gcp-bigquery-remote-function-bounded-cloudrun-invoke",
    "gcp-composer-environments-executeairflowcommand",
    "gcp-compute-images-create-family-poison",
)


@pytest.mark.parametrize("ident", IDS)
def test_manual_path_is_documented_and_not_in_active_catalog(ident):
    excluded = yaml.safe_load((ROOT / "peaso/privesc/catalog/gcp/_excluded.yaml").read_text())
    records = [row for row in excluded if row.get("id") == ident]
    assert len(records) == 1
    assert records[0]["source"].startswith("src/pentesting-cloud/gcp-security/")
    assert records[0]["reason"].startswith("Manual-only:")
    assert ident not in {entry["id"] for entry in privesc.catalog()["entries"]}
    assert ident not in json.loads((ROOT / "peaso/privesc/finding_explanation.json").read_text())
