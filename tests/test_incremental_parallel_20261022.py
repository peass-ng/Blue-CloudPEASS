"""Incremental evaluation must not block collection or discard partial positives."""
import threading

from tests.test_incremental_checkpoint import _session, SCOPE, TENANT


def test_slow_evaluation_does_not_block_new_native_settlement(monkeypatch, tmp_path):
    from peaso import engine
    session, artifacts, refs, _ = _session(monkeypatch, tmp_path)
    original = engine.evaluate_snapshot
    started, release, settled = threading.Event(), threading.Event(), threading.Event()

    def slow(snapshot, **options):
        started.set()
        assert release.wait(5)
        return original(snapshot, **options)

    monkeypatch.setattr(engine, "evaluate_snapshot", slow)
    try:
        session.on_collection({"type": "bucket", "scope": SCOPE, "status": "collected", "items": [{"id": "one"}]})
        assert started.wait(2)
        thread = threading.Thread(target=lambda: (session.on_collection({
            "type": "bucket", "scope": SCOPE, "status": "collected", "items": [{"id": "two"}]}), settled.set()))
        thread.start()
        assert settled.wait(1), "native collection waited behind report evaluation"
        release.set()
        thread.join(2)
        session.flush()
        reports = [(seq, artifacts.get(TENANT, report)) for seq, _, report in refs if report]
        assert reports[0][0] == reports[0][1]["publication"]["sequence"] == 1
        assert reports[-1][0] == reports[-1][1]["publication"]["sequence"] == 2
    finally:
        release.set()
        session.close()


def test_partial_native_positive_survives_without_premature_pass(monkeypatch, tmp_path):
    from peaso import engine
    session, artifacts, refs, published = _session(monkeypatch, tmp_path)
    session.native_checks[0].allow_incomplete_failure = True
    original = engine.evaluate_snapshot

    def evaluate(snapshot, **options):
        report = original(snapshot, **options)
        report["findings"].append(dict(report["findings"][0], status="PASS"))
        return report

    monkeypatch.setattr(engine, "evaluate_snapshot", evaluate)
    try:
        session.on_collection({"type": "bucket", "scope": SCOPE, "status": "partial",
                               "error": {"code": "page_limit"}, "items": [{"id": "positive"}]})
        assert published.wait(2)
        report = artifacts.get(TENANT, next(ref for _, _, ref in refs if ref))
        assert [row["status"] for row in report["findings"]] == ["FAIL"]
        assert report["coverage"] == []
        assert report["stats"]["coverage_complete"] is False
    finally:
        session.close()


def test_section_closure_has_a_new_durable_sequence_and_is_idempotent(monkeypatch, tmp_path):
    session, artifacts, refs, _ = _session(monkeypatch, tmp_path)
    try:
        session.on_collection({'type': 'bucket', 'scope': SCOPE, 'status': 'collected', 'items': [{'id': 'one'}]})
        session.flush()
        session.finish_collection()
        session.flush()
        session.finish_collection()
        assert session.sequence == 2
        assert [seq for seq, _, report in refs if report is None] == [1, 2]
        latest = artifacts.get(TENANT, [ref for _, _, ref in refs if ref][-1])
        assert latest['publication']['sequence'] == 2
        assert latest['publication']['sections']['hardening']['status'] == 'complete'
    finally:
        session.close()
