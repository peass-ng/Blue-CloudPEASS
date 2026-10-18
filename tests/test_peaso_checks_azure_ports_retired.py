"""Retirement adjudication is resource-generation-specific, never missing-fact rejection."""
from datetime import date
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / "peaso/rulepacks/reviewed_azure_ports_retired.json").read_text())


def test_every_retired_reference_binds_single_server_generation_and_version_evidence():
    assert len(REVIEWS) == 54
    assert len({row["source_review"]["query_id"] for row in REVIEWS.values()}) == 12
    for row in REVIEWS.values():
        assert row["disposition"] == "rejected" and row["native_checks"] == []
        assert row["review_classification"] == "obsolete_definition"
        source = row["source_review"]
        assert source["legacy_table"] in ("azure_mysql_server", "azure_postgresql_server")
        assert source["resource_generation"] in ("Microsoft.DBforMySQL/servers", "Microsoft.DBforPostgreSQL/servers")
        assert date.fromisoformat(source["retired_on"]) < date.fromisoformat(source["reviewed_at"])
        assert source["query_sha256"] and source["generation_adapter_source"]
        assert source["arguments"] == [] and row["official_docs"]


def test_flexible_server_sources_and_transferred_ids_are_not_rejected_as_legacy():
    claude = set(json.loads((ROOT / "peaso/rulepacks/port_partitions_claude.json").read_text())["partitions"]["claude_azure"]["check_ids"])
    assert not set(REVIEWS) & claude
    assert all("flexible" not in row["source_review"]["query_id"] for row in REVIEWS.values())
