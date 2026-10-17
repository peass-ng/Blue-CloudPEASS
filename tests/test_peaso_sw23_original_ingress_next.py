"""Original SW23 signed-log ingress regression cases with inert snapshot data."""
import base64
import copy
import json
from pathlib import Path

from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot


COMPLETENESS = "azure.other.signed_log_completeness"
FIXTURE = Path(__file__).parent / "fixtures" / "bulk_pending_behavior.json"


def _finding(mutate):
    index = copy.deepcopy(json.loads(FIXTURE.read_text())[COMPLETENESS]["pass_index"])
    context = index["context"]
    envelopes = [copy.deepcopy(batch) for batches in index["collections"].values() for batch in batches]
    container = next(row for row in envelopes if row["type"] == "signed_log_evidence")["items"][0]["payload"]["containers"]["items"][0]
    mutate(container)
    snapshot = make_snapshot("azure", [context["scope"]], envelopes,
                             metadata=context.get("metadata", {}), created_at=context["created_at"])
    collected = collect_snapshot({"connector": {"provider": "azure", "scopes": [context["scope"]],
                                  "auth": {}, "options": {"snapshot": snapshot}}, "checks": [COMPLETENESS]})
    findings = [f for f in evaluate_snapshot(collected, checks=[COMPLETENESS],
                                             include_not_applicable=True)["findings"]
                if f["check_id"] == COMPLETENESS]
    assert len(findings) == 1
    return findings[0]


def test_equivalent_policy_window_timestamps_join_by_instant():
    def offset(container):
        container["baseline"]["window_start"] = "2026-10-12T13:00:00+02:00"
        container["baseline"]["window_end"] = "2026-10-12T14:00:00+02:00"
    assert _finding(offset)["status"] == "PASS"


def test_unmanifested_listed_blob_cannot_pass_signed_completeness():
    def extra_blob(container):
        container["blobs"]["items"].append({
            "blobName": "orphan-inert", "versionId": "v1",
            "content_base64": base64.b64encode(b"inert orphan").decode(),
            "read_complete": True, "version_consistent": True,
        })
    assert _finding(extra_blob)["status"] == "UNKNOWN"


def test_signed_sequence_outside_complete_independent_baseline_cannot_pass():
    def narrow(container):
        container["baseline"]["expected_sequences"] = []
    assert _finding(narrow)["status"] == "UNKNOWN"


def test_untrusted_public_key_fingerprint_cannot_verify_manifest():
    def wrong_pin(container):
        container["trusted_key"]["pinned_spki_sha256"] = "0" * 64
    assert _finding(wrong_pin)["status"] == "UNKNOWN"


def test_manifest_signer_must_match_pinned_key_version():
    def wrong_signer(container):
        container["manifest"]["kid"] = "https://approved.vault.azure.net/keys/archive/other-version"
    assert _finding(wrong_signer)["status"] == "UNKNOWN"


def test_distinct_policy_window_remains_unresolved():
    def different_window(container):
        container["baseline"]["window_start"] = "2026-10-12T12:00:01+01:00"
    assert _finding(different_window)["status"] == "UNKNOWN"
