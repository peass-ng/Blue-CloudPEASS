"""A terminal collector can resume only a same-scan cumulative checkpoint."""
import copy
import time
from types import SimpleNamespace

import pytest

from peaso.server.scan_resume import recoverable_sources, resume_stage, validate_resume_proof
from peaso.snapshot import make_snapshot
from peaso.storage.artifacts import FileArtifacts, job_prefix
from peaso.storage.sqlite import SQLiteStore, StoreError
from peaso.worker import _resume_prior, _partial_reuse_allowed


SCOPE = "123456789012/us-east-1"
SECOND = "987654321098/us-east-1"
SCOPES = [SCOPE, SECOND]


def prepared(tmp_path):
    store = SQLiteStore(tmp_path / "state")
    artifacts = FileArtifacts(tmp_path / "artifacts")
    tenant = "owner"
    connector = store.add_connector(tenant, {"provider": "aws", "scopes": SCOPES,
                                             "input_mode": "live"}, "sealed-auth")
    now = time.time()
    job = store.enqueue(tenant, {"connector_id": connector["id"]}, timeout=120, now=now)
    assert store.admit(tenant, job["id"], now=now + 1)
    claim = store.claim("collector", tenant=tenant, ident=job["id"], now=now + 2)
    row = {"type": "instance", "scope": SCOPE, "status": "empty", "items": []}
    second = {"type": "instance", "scope": SECOND, "status": "empty", "items": []}
    batch = make_snapshot("aws", SCOPES, [row, second], metadata={
        "requested_scopes": SCOPES, "intentional_partial": True,
        "incremental": {"sequence": 1, "phase": "collecting", "completed_collections": 2,
                        "batch_revisions": [1, 1]}})
    batch_ref = artifacts.put(tenant, job["id"], "snapshot", batch)
    assert store.record_checkpoint(tenant, job["id"], claim["owner"], 1, batch_ref,
                                   kind="__checkpoint_batch__", scope="1", now=now + 3)
    partial = make_snapshot("aws", SCOPES, [row, second], metadata={
        "requested_scopes": SCOPES, "intentional_partial": True,
        "incremental": {"sequence": 1, "phase": "collecting", "completed_collections": 2}})
    partial_ref = artifacts.put(tenant, job["id"], "snapshot", partial)
    report_ref = artifacts.put(tenant, job["id"], "report", {
        "publication": {"state": "partial", "phase": "collecting", "sequence": 1}})
    assert store.record_checkpoint(tenant, job["id"], claim["owner"], 1, partial_ref,
                                   report_ref=report_ref, now=now + 4)
    assert store.finish(job["id"], claim["owner"], "failed", now=now + 5)
    return store, artifacts, tenant, job, connector, now


def test_partial_resume_validates_and_keeps_exact_scan(tmp_path):
    store, artifacts, tenant, job, connector, now = prepared(tmp_path)
    prior = store.job(tenant, job["id"])
    assert prior["snapshot"] is None
    assert store.public_job(prior)["resumable"] is True
    assert recoverable_sources(prior, store, artifacts) == "collector"
    from peaso.collectors.resume import partition
    saved = artifacts.get(tenant, prior["partial_snapshot"])
    remaining, retained = partition({"provider": "aws", "scopes": SCOPES, "options": {}},
                                    ["instance", "bucket"], saved)
    assert remaining == ["bucket"] and len(retained) == 2
    store.resume_job(tenant, job["id"], store.connector(tenant, connector["id"]), now + 6)
    resumed = store.job(tenant, job["id"])
    assert resumed["id"] == prior["id"] and resumed["resume_phase"] == "collector"
    assert resumed["partial_snapshot"] == prior["partial_snapshot"]
    assert resumed["checkpoint_sequence"] == 1
    assert store.checkpoint_collections(tenant, job["id"])[0]["reference"]


def test_http_uses_only_metadata_then_claimed_child_verifies_contents(tmp_path):
    store, artifacts, tenant, job, connector, now = prepared(tmp_path)
    terminal = store.job(tenant, job["id"])

    class HeadOnly:
        def __init__(self):
            self.references = []

        def size(self, owner, reference):
            self.references.append((owner, reference))
            return artifacts.size(owner, reference)

        def get(self, *_):
            raise AssertionError("HTTP preflight must not download a snapshot")

    preflight = HeadOnly()
    assert recoverable_sources(terminal, store, preflight, metadata_only=True) == "collector"
    assert len(preflight.references) == 2
    store.resume_job(tenant, job["id"], store.connector(tenant, connector["id"]), now + 6)
    claimed = store.job(tenant, job["id"])
    entries = store.checkpoint_collections(tenant, job["id"])
    proof = {"row": {key: claimed.get(key) for key in (
        "tenant", "id", "connector", "resume_phase", "snapshot", "partial_snapshot",
        "partial_report", "partial_report_sequence", "checkpoint_sequence")},
        "entries": entries}
    target = {"provider": "aws", "scopes": SCOPES}
    assert validate_resume_proof(proof, artifacts, tenant, job["id"], target,
                                 [entry["reference"] for entry in entries]) is None
    with pytest.raises(ValueError):
        validate_resume_proof(proof, artifacts, tenant, job["id"],
                              {"provider": "aws", "scopes": [SCOPE]},
                              [entry["reference"] for entry in entries])
    # The HTTP preflight can pass before a saved object becomes corrupt; the
    # child must still stop before collecting from it.
    batch_path = artifacts.root / entries[0]["reference"]
    body = batch_path.read_text().replace('"status":"empty"', '"status":"denied"', 1)
    batch_path.write_text(body)
    with pytest.raises(StoreError):
        validate_resume_proof(proof, artifacts, tenant, job["id"], target,
                              [entry["reference"] for entry in entries])


def test_later_batch_takes_precedence_over_lagging_partial_report(tmp_path):
    store, artifacts, tenant, job, _, _ = prepared(tmp_path)
    # The real collector can settle another native row after the latest
    # evaluated partial report. Preserve that newer durable fact on resume.
    later = {"type": "instance", "scope": SCOPE, "status": "denied", "items": [],
             "error": {"code": "AccessDenied"}}
    batch = make_snapshot("aws", [SCOPE], [later], metadata={
        "requested_scopes": SCOPES, "intentional_partial": True,
        "incremental": {"sequence": 2, "phase": "collecting", "completed_collections": 1,
                        "batch_revisions": [2]}})
    # Exercise the persisted terminal shape after a later acknowledged batch.
    reference = artifacts.put(tenant, job["id"], "snapshot", batch)
    with store.transaction() as db:
        db.execute("INSERT INTO scan_checkpoint_collections(tenant,scan_id,kind,scope,sequence,reference) "
                   "VALUES(?,?,?,?,?,?)", (tenant, job["id"], "__checkpoint_batch__", "2", 2, reference))
        db.execute("UPDATE jobs SET checkpoint_sequence=2 WHERE tenant=? AND id=?", (tenant, job["id"]))
    row = store.job(tenant, job["id"])
    assert recoverable_sources(row, store, artifacts) == "collector"
    prior = artifacts.get(tenant, row["partial_snapshot"])
    old_second = next(item for item in prior["collections"] if item["scope"] == SECOND)
    session = SimpleNamespace(collections={("instance", SCOPE): later,
                                           ("instance", SECOND): old_second})
    resumed = _resume_prior(session, prior)
    assert resumed["collections"] == [later, old_second]
    assert "intentional_partial" not in resumed["metadata"]
    assert "incremental" not in resumed["metadata"]


def test_partial_only_skips_kinds_under_exact_explicit_aws_plan():
    connector = {"provider": "aws", "scopes": [SCOPE]}
    assert _partial_reuse_allowed(connector, {"incremental": {"sequence": 1}})
    assert _partial_reuse_allowed(connector, {"incremental": {"scope_plan": [SCOPE]}})
    assert not _partial_reuse_allowed(connector, {"incremental": {
        "scope_plan": [SCOPE, "123456789012/us-west-2"]}})
    assert not _partial_reuse_allowed({"provider": "gcp", "scopes": ["projects/example"]},
                                      {"incremental": {"sequence": 1}})


@pytest.mark.parametrize("changed", ["tenant", "provider", "sequence", "plan", "missing_batch"])
def test_partial_resume_rejects_wrong_provenance(tmp_path, changed):
    store, artifacts, tenant, job, _, _ = prepared(tmp_path)
    candidate = copy.deepcopy(store.job(tenant, job["id"]))
    if changed == "tenant":
        candidate["partial_snapshot"] = candidate["partial_snapshot"].replace(
            job_prefix("owner", job["id"]), job_prefix("other", job["id"]))
    elif changed == "provider":
        candidate["connector"] = candidate["connector"].replace('"provider": "aws"', '"provider": "gcp"')
    elif changed == "sequence":
        candidate["partial_report_sequence"] = 2
        candidate["checkpoint_sequence"] = 2
    elif changed == "plan":
        candidate["connector"] = candidate["connector"].replace(SCOPE, "999999999999/us-west-2")
    else:
        candidate["checkpoint_sequence"] = 2
    assert resume_stage(candidate) == "collector"
    with pytest.raises(StoreError) as exc:
        recoverable_sources(candidate, store, artifacts)
    assert exc.value.status == 409


def test_http_preflight_cost_does_not_grow_with_batch_count(tmp_path):
    store, artifacts, tenant, job, _, _ = prepared(tmp_path)
    row = store.job(tenant, job["id"])
    entry = store.checkpoint_collections(tenant, job["id"])[0]
    entries = [dict(entry, sequence=n, scope=str(n)) for n in range(1, 167)]
    row["checkpoint_sequence"] = 166
    class ManyBatches:
        def checkpoint_collections(self, owner, ident):
            assert (owner, ident) == (tenant, job["id"])
            return entries
    class Metadata:
        def __init__(self): self.heads = []
        def size(self, owner, reference):
            self.heads.append(reference)
            return artifacts.size(owner, reference)
        def get(self, *_): raise AssertionError("No HTTP body reads")
    metadata = Metadata()
    assert recoverable_sources(row, ManyBatches(), metadata, metadata_only=True) == "collector"
    assert len(metadata.heads) == 2
    assert set(metadata.heads) == {row["partial_snapshot"], row["partial_report"]}
