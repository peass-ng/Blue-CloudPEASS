"""Scope accounting and private evidence gates; no cloud access or cloud writes."""
import json
from types import SimpleNamespace

import pytest

from peaso.snapshot import make_snapshot
from scripts.peaso_test_resources import gcp_live_acceptance as runner

SCOPES = ["projects/fixture-project", "organizations/123"]


def snapshot(status="empty", error=None):
    rows = [{"type": kind, "scope": scope, "status": status, "items": [],
             **({"error": {"code": error}} if error else {})}
            for kind, scope in [("project", SCOPES[0]), ("network", SCOPES[0]), ("organization", SCOPES[1])]]
    return make_snapshot("gcp", SCOPES, rows)


def test_discovery_pins_identity_clears_impersonation_and_preserves_all_active_scopes(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "foreign@example.invalid")
    calls = []
    def command(args, **kwargs):
        calls.append(args)
        assert kwargs["env"]["CLOUDSDK_CORE_ACCOUNT"] == "selected@example.invalid"
        assert kwargs["env"]["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"] == ""
        assert args[args.index("--account") + 1] == "selected@example.invalid"
        assert not any(flag in args for flag in ("--limit", "--page-size", "--impersonate-service-account"))
        rows = ([{"projectId": "fixture-project", "lifecycleState": "ACTIVE"},
                 {"projectId": "deleted-project", "lifecycleState": "DELETE_REQUESTED"}]
                if args[1] == "projects" else [{"name": "organizations/123"}])
        return SimpleNamespace(stdout=json.dumps(rows))
    monkeypatch.setattr(runner.subprocess, "run", command)
    assert runner.discover_scopes(tmp_path, "selected@example.invalid") == SCOPES
    assert len(calls) == 2
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in tmp_path.iterdir())


def test_discovery_failure_is_redacted_and_does_not_continue(tmp_path, monkeypatch):
    import subprocess
    def command(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "gcloud", stderr="private-credential-sentinel")
    monkeypatch.setattr(runner.subprocess, "run", command)
    with pytest.raises(runner.SessionError, match="^projects_discovery_failed$"):
        runner.discover_scopes(tmp_path, "selected@example.invalid")
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("status,error", [("denied", "credential_refresh_failed"), ("unknown", "call_limit"),
                                          ("partial", "page_limit")])
def test_unreadable_or_truncated_live_evidence_cannot_pass(status, error):
    assert runner.acceptance_status(snapshot(status, error), SCOPES)["outcome"] == "failed"


def test_readable_empty_scopes_pass_but_missing_scope_or_inventory_does_not():
    value = snapshot()
    assert runner.acceptance_status(value, SCOPES)["outcome"] == "passed"
    assert runner.acceptance_status(value, SCOPES + ["projects/missing"])["missing_scopes"] == ["projects/missing"]
    value["collections"] = [row for row in value["collections"] if row["type"] != "network"]
    gate = runner.acceptance_status(value, SCOPES)
    assert gate["outcome"] == "failed"
    assert gate["missing_inventories"] == [("network", SCOPES[0])]


def test_scope_errors_in_native_metadata_are_not_lost_in_summary():
    value = snapshot()
    value["metadata"]["scope_coverage"] = [{"scope": "discovery", "code": "scope_limit"}]
    # Metadata edits must be sealed before validate() in summarize().
    value = make_snapshot("gcp", SCOPES, value["collections"], metadata=value["metadata"])
    assert runner.summarize(value)["scope_errors"] == value["metadata"]["scope_coverage"]
    assert runner.acceptance_status(value, SCOPES)["outcome"] == "failed"


def test_summary_counts_retry_attempts_from_native_request_evidence():
    value = snapshot()
    value = make_snapshot("gcp", SCOPES, value["collections"], metadata={
        "source_requests": [{"http_attempts": 2}, {"http_attempts": 1}]})
    summary = runner.summarize(value)
    assert summary["requests"] == 2
    assert summary["http_attempts"] == 3


@pytest.mark.parametrize("source", ["request", "field"])
def test_hydration_budget_failure_prevents_false_success_even_when_envelopes_are_readable(source):
    value = snapshot()
    error = {"code": "call_limit"}
    metadata = {"source_requests": [{"error": error}]} if source == "request" else {}
    if source == "field":
        project = next(c for c in value["collections"] if c["type"] == "project")
        project.update(status="collected", items=[{"name": SCOPES[0], "_coverage": {
            "computeConfig": {"status": "unavailable", "error": error}}}])
    value = make_snapshot("gcp", SCOPES, value["collections"], metadata=metadata)
    assert runner.acceptance_status(value, SCOPES)["fatal_error_codes"] == ["call_limit"]
    assert runner.acceptance_status(value, SCOPES)["outcome"] == "failed"


def test_disabled_optional_service_remains_visible_without_invalidating_readable_scopes():
    value = snapshot()
    error = {"code": "api_error", "reason": "SERVICE_DISABLED"}
    project = next(c for c in value["collections"] if c["type"] == "project")
    project.update(status="collected", items=[{"name": SCOPES[0], "_coverage": {
        "computeConfig": {"status": "unavailable", "error": error}}}])
    value = make_snapshot("gcp", SCOPES, value["collections"], metadata={
        "source_requests": [{"http_status": 403, "status": "unavailable", "error": error, "http_attempts": 1}]})
    summary = runner.summarize(value)
    assert summary["http_statuses"] == {"403": 1}
    assert summary["request_error_reasons"] == {"SERVICE_DISABLED": 1}
    assert summary["field_error_reasons"] == {"SERVICE_DISABLED": 1}
    assert summary["field_coverage_statuses"] == {"unavailable": 1}
    assert runner.acceptance_status(value, SCOPES)["outcome"] == "passed"


def test_live_runner_preserves_capture_and_marks_concurrent_source_change_failed(tmp_path, monkeypatch):
    from peaso.collectors import gcp
    monkeypatch.setattr(runner, "discover_scopes", lambda *args: SCOPES)
    hashes = iter([{"gcp.py": "before"}, {"gcp.py": "after"}])
    monkeypatch.setattr(runner, "source_hashes", lambda: next(hashes))
    def collect(connector):
        assert connector["auth"]["impersonate_service_account"] == ""
        assert connector["options"]["inventories"] == runner.LIVE_INVENTORIES
        assert not connector["options"]["include_inherited"]
        return snapshot()
    monkeypatch.setattr(gcp, "collect", collect)
    summary = runner.collect_live(tmp_path)
    assert summary["acceptance"]["outcome"] == "failed"
    assert summary["evidence_mode"] == "live-gcloud"
    assert (tmp_path / "gcp-live-snapshot.json").exists()
    assert tmp_path.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in tmp_path.iterdir())
    with pytest.raises(runner.SessionError, match="live_evidence_already_exists"):
        runner.collect_live(tmp_path)
