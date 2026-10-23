"""Retired APIM built-in Git deployment cannot create a current escalation edge."""
from pathlib import Path

import yaml

from peaso import privesc


RETIRED = "azure-apim-tenant-git-deploy-managed-identity-token"


def test_retired_git_deploy_is_only_in_excluded_catalog():
    ids = {entry["id"] for entry in privesc.load_catalog()["entries"]}
    assert RETIRED not in ids
    assert "azure-apim-policy-write-managed-identity-token" in ids
    excluded = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/azure/_excluded_main_reconciliation.yaml"
    records = yaml.safe_load(excluded.read_text())
    record = next(record for record in records if record["id"] == RETIRED)
    assert "15 March 2025" in record["reason"]
