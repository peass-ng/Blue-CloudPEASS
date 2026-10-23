"""Workspace pivots needing tenant or user interaction stay out of the active map."""

from pathlib import Path

import yaml

from peaso import privesc


MANUAL_IDS = {
    "gcp-workspace-dwd-keyless-signjwt",
    "gcp-workspace-dwd-key-create",
    "gcp-workspace-cloud-dns-admin-recovery",
    "gcp-workspace-addons-deployment-update",
}


def test_unverifiable_workspace_pivots_are_documented_but_not_loaded():
    root = Path(__file__).resolve().parents[1]
    excluded = yaml.safe_load((root / "peaso/privesc/catalog/gcp/_excluded.yaml").read_text())
    documented = {item.get("id") for item in excluded if isinstance(item, dict)}
    active = {item["id"] for item in privesc.catalog()["entries"]}
    assert MANUAL_IDS <= documented
    assert MANUAL_IDS.isdisjoint(active)
