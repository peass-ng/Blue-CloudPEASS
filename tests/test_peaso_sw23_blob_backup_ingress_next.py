"""Directed public-ingress checks for SW23 blob and backup evidence."""
import copy
import json
from pathlib import Path

from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

FIXTURE = Path(__file__).parent / "fixtures" / "bulk_pending_behavior.json"
BACKUP = "azure.other.infrastructure_configuration_backup"


def _finding(cid, mutate):
    index = copy.deepcopy(json.loads(FIXTURE.read_text())[cid]["pass_index"])
    context = index["context"]
    envelopes = [copy.deepcopy(batch) for batches in index["collections"].values() for batch in batches]
    evidence = next(batch for batch in envelopes if batch["type"] == (
        "configuration_backup_evidence" if cid == BACKUP else "blob_access_evidence"))["items"][0]["payload"]
    mutate(evidence)
    snapshot = make_snapshot("azure", [context["scope"]], envelopes,
                             metadata=context.get("metadata", {}), created_at=context["created_at"])
    collected = collect_snapshot({"connector": {"provider": "azure", "scopes": [context["scope"]],
                                  "auth": {}, "options": {"snapshot": snapshot}}, "checks": [cid]})
    findings = [f for f in evaluate_snapshot(collected, checks=[cid],
                                             include_not_applicable=True)["findings"]
                if f["check_id"] == cid]
    assert len(findings) == 1
    return findings[0]


def test_uniform_foreign_effective_grant_container_stays_unresolved():
    def foreign_grant(evidence):
        container = evidence["containers"]["items"][0]
        container["objects"]["items"][0]["container_id"] = container["id"] + "-foreign"
    assert _finding("azure.other.blob_uniform_access", foreign_grant)["status"] == "UNKNOWN"
