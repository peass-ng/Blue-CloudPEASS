"""Evidence-only resource self-grants stay outside automatic CSPM checks."""

from pathlib import Path

import yaml

from peaso import privesc


IDS = {
    "gcp-runtimeconfig-configs-setiampolicy-config-self-grant",
    "gcp-servicedirectory-namespaces-setiampolicy-self-grant",
    "gcp-servicedirectory-services-setiampolicy-self-grant",
    "gcp-spanner-databases-setiampolicy-database-self-grant",
    "gcp-spanner-instances-setiampolicy-instance-self-grant",
}


def test_manual_self_grants_are_documented_but_not_active_checks():
    active = {entry["id"] for entry in privesc.catalog()["entries"]}
    excluded_path = (Path(__file__).resolve().parents[1]
                     / "peaso/privesc/catalog/gcp/_excluded.yaml")
    excluded = {entry.get("id"): entry for entry in yaml.safe_load(excluded_path.read_text())}
    assert IDS.isdisjoint(active)
    for ident in IDS:
        record = excluded[ident]
        assert "Manual-only" in record["reason"]
        assert record["source"].startswith("src/pentesting-cloud/")
