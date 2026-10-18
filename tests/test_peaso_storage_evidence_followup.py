"""Inert imported evidence regressions for SW23 storage contracts."""
import copy
import json
from pathlib import Path

from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

FIXTURE = Path(__file__).parent / "fixtures" / "bulk_pending_behavior.json"
AUDIT = "azure.other.audit_storage_access_logging"
UNIFORM = "azure.other.blob_uniform_access"


def _finding(mutate, cid=AUDIT):
    index = copy.deepcopy(json.loads(FIXTURE.read_text())[cid]["pass_index"])
    context = index["context"]
    envelopes = [copy.deepcopy(batch) for batches in index["collections"].values() for batch in batches]
    payload = next(batch for batch in envelopes if batch["type"] == ("audit_storage_access_evidence" if cid == AUDIT else "blob_access_evidence"))["items"][0]["payload"]
    mutate(payload)
    snapshot = make_snapshot("azure", [context["scope"]], envelopes,
                             metadata=context.get("metadata", {}), created_at=context["created_at"])
    before = copy.deepcopy(snapshot)
    imported = collect_snapshot({"connector": {"provider": "azure", "scopes": [context["scope"]],
                       "auth": {}, "options": {"snapshot": snapshot}}, "checks": [cid]})
    findings = [row for row in evaluate_snapshot(imported, checks=[cid],
                include_not_applicable=True)["findings"] if row["check_id"] == cid]
    assert len(findings) == 1 and snapshot == before and imported == before
    return findings[0]


def test_same_account_child_destination_cannot_pass_as_independent_sink():
    def mutate(payload):
        event = payload["events"]["items"][0]
        event["sink"]["id"] = event["source_account_id"] + "/blobServices/default/containers/logs"
    row = _finding(mutate)
    assert row["status"] == "FAIL"
    assert row["evidence"]["absent_or_same_account_access_logs"] == ["read"]


def test_malformed_destination_identity_cannot_pass_as_secure_sink():
    def mutate(payload):
        payload["events"]["items"][0]["sink"]["id"] = "/subscriptions/not-a-uuid"
    assert _finding(mutate)["status"] == "UNKNOWN"


def test_uniform_duplicate_object_inventory_is_unresolved():
    def mutate(payload):
        objects = payload["containers"]["items"][0]["objects"]["items"]
        objects.append(copy.deepcopy(objects[0]))
    assert _finding(mutate, UNIFORM)["status"] == "UNKNOWN"


def test_uniform_foreign_explicit_grant_scope_is_unresolved():
    def mutate(payload):
        container = payload["containers"]["items"][0]
        container["objects"]["items"][0]["container_id"] = container["id"] + "-foreign"
    assert _finding(mutate, UNIFORM)["status"] == "UNKNOWN"


def test_uniform_partial_object_inventory_is_unresolved():
    def mutate(payload):
        payload["containers"]["items"][0]["objects"]["collection_status"] = "partial"
    assert _finding(mutate, UNIFORM)["status"] == "UNKNOWN"


def test_sink_arm_uri_aliases_and_case_boundaries():
    def with_sink(sink_id):
        def mutate(payload):
            payload["events"]["items"][0]["sink"]["id"] = sink_id
        return _finding(mutate)

    source = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs"
    separate = source + "-separate"
    assert with_sink(separate)["status"] == "PASS"
    assert with_sink(source.upper() + "/blobServices/default")["status"] == "FAIL"
    for malformed in (separate + "?api-version=1", separate + "#fragment",
                      separate + "%2Fchild", separate + "/./child",
                      separate + "/../child", separate + "\\child"):
        assert with_sink(malformed)["status"] == "UNKNOWN", malformed
