"""The collector can outlive (or lose) a later optional image phase."""
import json
import sys
import threading
import types
from types import SimpleNamespace

import pytest

from peaso.snapshot import seal
from peaso.storage.artifacts import FileArtifacts


SCOPE = "123456789012/us-east-1"
TENANT = "tenant-a"
SCAN = "a" * 32


def _session(monkeypatch, tmp_path, *, second=False, fail_second=False):
    from peaso import engine
    from peaso.incremental import CheckpointSession

    hardening = SimpleNamespace(id="test.hardening", category="hardening", kind="bucket",
                                dependencies=("bucket",))
    image = SimpleNamespace(id="test.image", category="vulnerability", kind="image",
                            dependencies=("image",))
    checks = [hardening, image] if second else [hardening]
    monkeypatch.setattr(engine, "_selection", lambda *args: ([c.category for c in checks], checks))
    monkeypatch.setattr(engine, "_analysis_selection", lambda *args: [])
    monkeypatch.setattr(engine, "_privesc_selected", lambda *args: None)
    analysis = types.ModuleType("peaso.analysis")
    analysis.REQUIRED_TYPES = {}
    analysis.privesc_required_types = lambda provider: []
    monkeypatch.setitem(sys.modules, "peaso.analysis", analysis)

    def evaluate(snapshot, *, checks, **_):
        if fail_second and "test.image" in checks:
            raise RuntimeError("interrupted analysis")
        findings = [{"check_id": check, "scope": SCOPE, "category":
                     "vulnerability" if check == "test.image" else "hardening",
                     "status": "FAIL", "severity": "high"} for check in checks]
        return {"findings": findings,
                "coverage": [{"level": "check", "check_id": check, "scope": SCOPE,
                              "status": "evaluated"} for check in checks],
                "stats": {"finding_count": len(findings), "coverage_complete": True,
                          "inventory_complete": True}}

    monkeypatch.setattr(engine, "evaluate_snapshot", evaluate)
    artifacts = FileArtifacts(tmp_path)
    refs = []
    published = threading.Event()

    def public_snapshot(snapshot):
        # A stand-in for the worker's secret_capture.public_snapshot + auth
        # credential redact + seal boundary. Nothing private reaches artifacts.
        public = json.loads(json.dumps(snapshot).replace("PRIVATE", "[REDACTED]"))
        return seal(public)

    def on_checkpoint(snapshot, report, sequence):
        snapshot_ref = artifacts.put(TENANT, SCAN, "snapshot", snapshot)
        report_ref = artifacts.put(TENANT, SCAN, "report", report) if report else None
        refs.append((sequence, snapshot_ref, report_ref))
        if report_ref:
            published.set()

    request = {"connector": {"provider": "aws", "scopes": [SCOPE]},
               "categories": [c.category for c in checks], "checks": [c.id for c in checks]}
    session = CheckpointSession(request, on_checkpoint, public_snapshot, interval=0.02)
    return session, artifacts, refs, published


def test_hardening_report_survives_blocked_image_and_private_value(monkeypatch, tmp_path):
    session, artifacts, refs, published = _session(monkeypatch, tmp_path, second=True)
    image_blocked = threading.Event()
    try:
        assert session.on_collection({"type": "bucket", "scope": SCOPE, "status": "collected",
                                      "items": [{"id": "b", "private_field": "PRIVATE"}]}) == 1
        assert published.wait(2), "hardening should publish while image phase is still blocked"
        assert not image_blocked.is_set()
        report_ref = next(report for _, _, report in refs if report)
        report = artifacts.get(TENANT, report_ref)
        assert [row["check_id"] for row in report["findings"]] == ["test.hardening"]
        assert report["publication"]["state"] == "partial"
        assert report["stats"]["coverage_complete"] is False
        assert "PRIVATE" not in json.dumps([artifacts.get(TENANT, ref) for _, ref, _ in refs])
        # A provider timeout or child termination after this point cannot
        # remove the already durable tenant/scan-scoped artifact.
        assert artifacts.get(TENANT, report_ref)["findings"] == report["findings"]
    finally:
        session.close()


def test_duplicate_settlement_does_not_advance_checkpoint(monkeypatch, tmp_path):
    session, _, refs, _ = _session(monkeypatch, tmp_path)
    envelope = {"type": "bucket", "scope": SCOPE, "status": "empty", "items": []}
    try:
        assert session.on_collection(envelope) == 1
        assert session.on_collection(envelope) == 1
        assert len([row for row in refs if row[2] is None]) == 1
    finally:
        session.close()


def test_interrupted_later_analysis_keeps_earlier_category(monkeypatch, tmp_path):
    session, artifacts, refs, published = _session(monkeypatch, tmp_path, second=True,
                                                   fail_second=True)
    try:
        session.on_collection({"type": "bucket", "scope": SCOPE, "status": "collected",
                               "items": [{"id": "b"}]})
        assert published.wait(2)
        first = next(report for _, _, report in refs if report)
        session.on_collection({"type": "image", "scope": SCOPE, "status": "collected",
                               "items": [{"id": "i"}]})
        with pytest.raises(RuntimeError, match="interrupted analysis"):
            session.flush()
        assert artifacts.get(TENANT, first)["publication"]["state"] == "partial"
        assert any(sequence == 2 and report is None for sequence, _, report in refs)
    finally:
        with pytest.raises(RuntimeError, match="checkpoint publication failed"):
            session.close()


def test_real_native_hardening_evaluation_publishes_before_optional_image_phase(tmp_path):
    from peaso.incremental import CheckpointSession

    artifacts = FileArtifacts(tmp_path)
    published = threading.Event()
    refs = []

    def on_checkpoint(snapshot, report, sequence):
        snapshot_ref = artifacts.put(TENANT, SCAN, "snapshot", snapshot)
        if report is not None:
            refs.append(artifacts.put(TENANT, SCAN, "report", report))
            published.set()
        assert snapshot_ref

    request = {"connector": {"provider": "aws", "scopes": [SCOPE]},
               "categories": ["hardening"], "checks": ["aws.s3.default_encryption"]}
    session = CheckpointSession(request, on_checkpoint, lambda snapshot: snapshot, interval=0.02)
    try:
        session.on_collection({"type": "bucket", "scope": SCOPE, "status": "collected",
                               "items": [{"Name": "baseline", "Encryption": {
                                   "ServerSideEncryptionConfiguration": {"Rules": [
                                       {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}}]})
        assert published.wait(5), "native hardening evaluation must settle before any image read"
        report = artifacts.get(TENANT, refs[-1])
        rows = [row for row in report["findings"]
                if row["check_id"] == "aws.s3.default_encryption"]
        assert len(rows) == 1 and rows[0]["status"] == "PASS"
        assert report["publication"]["state"] == "partial"
        assert report["stats"]["inventory_complete"] is False
    finally:
        session.close()


