"""Inert normalized snapshot ingress for the original TLS check."""
import copy
import json
from pathlib import Path

import pytest
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

FIXTURE = Path(__file__).parent / "fixtures" / "bulk_pending_behavior.json"
TLS = "azure.other.endpoint_certificate_trust"


def verdict(cid, change=None):
    index = json.loads(FIXTURE.read_text())[cid]["pass_index"]
    collections = [copy.deepcopy(env) for group in index["collections"].values() for env in group]
    by_kind = {env["type"]: env for env in collections}
    if change is not None:
        change(by_kind)
    context = index["context"]
    snapshot = make_snapshot("azure", [context["scope"]], collections,
                             created_at=context["created_at"], metadata=context["metadata"])
    matches = [row for row in evaluate_snapshot(snapshot, checks=[cid])["findings"]
               if row["check_id"] == cid]
    assert len(matches) == 1
    return matches[0]["status"]


def reading(env):
    return env["tls_endpoint_observation"]["items"][0]


def test_explicit_tls_baseline_passes_normalized_ingress():
    assert verdict(TLS) == "PASS"


@pytest.mark.parametrize("change", [
    lambda env: reading(env).pop("presentedChainSha256"),
    lambda env: reading(env).update(leafSha256="c" * 64),
    lambda env: reading(env).update(trustRootSha256="c" * 64),
    lambda env: reading(env).update(validatedAgainstRootSha256=["c" * 64]),
    lambda env: reading(env)["_provenance"].pop("validationEngine"),
    lambda env: reading(env).update(observedAt="2026-10-11T12:00:00Z"),
    lambda env: env["app_service_endpoint_inventory"]["items"][0].update(certificateEndpointsComplete=False),
])
def test_tls_missing_foreign_or_stale_chain_evidence_is_unknown(change):
    assert verdict(TLS, change) == "UNKNOWN"
