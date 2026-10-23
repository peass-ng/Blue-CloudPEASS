"""Externally verified actuation routes are documented outside active scans."""

from pathlib import Path

import yaml

from peaso import privesc


IDS = {
    "gcp-saasservicemgmt-release-unit-actuation",
    "gcp-secretmanager-managed-rotation-exact-cloudsql-user",
}


def test_manual_external_actuation_is_not_an_active_check():
    active = {entry["id"] for entry in privesc.catalog()["entries"]}
    excluded_path = (Path(__file__).resolve().parents[1]
                     / "peaso/privesc/catalog/gcp/_excluded.yaml")
    excluded = {entry.get("id"): entry for entry in yaml.safe_load(excluded_path.read_text())}
    assert IDS.isdisjoint(active)
    for ident in IDS:
        record = excluded[ident]
        assert "Manual-only" in record["reason"]
        assert record["source"].startswith("src/pentesting-cloud/")
