"""Progress is transient diagnostics; redirected stdout remains machine-readable."""
import copy
import io
import json
import threading
from types import SimpleNamespace
import pytest
from peaso import cli, engine
from peaso.progress import ProgressReporter, current_callback, emit_progress, sanitize_event
from peaso.snapshot import make_snapshot


@pytest.fixture(autouse=True)
def native_only(monkeypatch):
    monkeypatch.setattr(engine, "CATEGORIES", ("hardening", "exposure", "least_privilege", "iam_graph", "network"))
    monkeypatch.setattr(engine, "privesc_techniques", lambda *args, **kwargs: [])
    monkeypatch.setattr(engine, "_run_privesc", lambda *args, **kwargs: pytest.fail("Excluded separately owned evaluator"))


def test_whitelist_redacts_credentials_and_controls_without_stringifying_objects():
    event = sanitize_event({"phase": "collecting", "provider": "azure", "scope": "token=PRIVATE_SENTINEL\n\x1b[31m", "completed": 2,
                            "total": 30, "resources": 4, "dynamic_total": True, "auth": {"token": "PRIVATE_SENTINEL"}, "native_data": "PRIVATE_SENTINEL"})
    assert event["total"] is None
    assert "PRIVATE_SENTINEL" not in json.dumps(event)
    assert "\n" not in event["scope"] and "\x1b" not in event["scope"]
    assert set(event) <= {"phase", "provider", "scope", "completed", "total", "resources", "dynamic_total"}
    assert sanitize_event({"phase": {}, "provider": [], "scope": object(), "completed": True}) == {"scope": "", "completed": None}


def test_optional_callback_error_cannot_abort_scan():
    def broken(event):
        raise RuntimeError("private callback diagnostic")
    assert emit_progress(broken, phase="collecting") is False


def test_out_of_order_settlement_cannot_regress_counts_or_produce_false_eta():
    reporter = ProgressReporter(stream=io.StringIO(), heartbeat=100)
    with reporter:
        emit_progress(phase="collecting", completed=4, resources=20, total=None, dynamic_total=True)
        emit_progress(phase="collecting", completed=2, resources=10)
        assert reporter.state["completed"] == 4 and reporter.state["resources"] == 20
        emit_progress(phase="collecting", completed=4, total=3, dynamic_total=False)
        assert reporter.state["total"] is None and reporter.state["dynamic_total"] is True
        emit_progress(phase="evaluating", completed=0, total=2, dynamic_total=False)
        assert reporter.state["completed"] == 0


def test_rate_limit_dynamic_eta_and_static_estimate():
    stream = io.StringIO();clock = [0.0]
    reporter = ProgressReporter(stream=stream, interval=2, heartbeat=100, clock=lambda: clock[0])
    with reporter:
        emit_progress(phase="collecting", provider="aws", completed=1, total=100, resources=3, dynamic_total=True)
        for value in range(2, 100):
            emit_progress(phase="collecting", completed=value, resources=value)
        assert len(stream.getvalue().splitlines()) == 2
        emit_progress(phase="evaluating", completed=0, total=4, dynamic_total=False)
        clock[0] = 10
        emit_progress(phase="evaluating", completed=2, total=4, dynamic_total=False)
    output = stream.getvalue()
    assert "ETA=unknown" in output
    assert "settled=2/4" in output and "ETA=10s estimated" in output
    assert output.rstrip().splitlines()[-1].startswith("peaso progress: completed")
    assert current_callback() is None


def test_immediate_start_and_heartbeat_during_blocked_call():
    received = threading.Event()
    class Stream(io.StringIO):
        def write(self, value):
            if len(self.getvalue().splitlines()) >= 1:
                received.set()
            return super().write(value)
    stream = Stream()
    with ProgressReporter(stream=stream, heartbeat=0.02):
        assert "starting" in stream.getvalue()
        assert received.wait(0.5), "heartbeat should arrive while main thread is waiting"
    assert "completed" in stream.getvalue()


def test_runtime_callback_copy_is_not_persisted_in_input_or_snapshot(monkeypatch):
    from peaso.collectors import collect_live
    request = {"provider": "aws", "scopes": ["111111111111/us-east-1"], "auth": {"profile": "fixture"}, "options": {}}
    original = copy.deepcopy(request)
    def collect(connector, requirements):
        # A function wrapper survives provider options deepcopy without copying
        # the reporter's stream/thread/lock.
        options = copy.deepcopy(connector["options"])
        emit_progress(options["_progress_callback"], phase="collecting", provider="aws", completed=1, total=1, resources=0, dynamic_total=False)
        return make_snapshot("aws", connector["scopes"], [])
    monkeypatch.setattr("importlib.import_module", lambda name: SimpleNamespace(collect=collect))
    with ProgressReporter(stream=io.StringIO(), heartbeat=100):
        snapshot = collect_live(request, [])
    assert request == original
    assert "_progress_callback" not in json.dumps(snapshot)


@pytest.mark.parametrize("command", ["scan", "collect"])
def test_cli_progress_stderr_leaves_stdout_valid_json(command, capsys):
    args = [command, "--provider", "aws", "--demo"]
    if command == "scan":
        args += ["--categories", "hardening", "--checks", "aws.rds.encryption"]
    assert cli.main(args) == 0
    output = capsys.readouterr()
    parsed = json.loads(output.out)
    assert parsed["provider"] == "aws"
    assert "peaso progress:" in output.err and "completed" in output.err
    assert "peaso progress:" not in output.out


def test_quiet_cli_suppresses_progress_and_keeps_same_data(capsys):
    assert cli.main(["collect", "--provider", "aws", "--demo", "--quiet"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["provider"] == "aws"
    assert output.err == ""


def test_evaluate_progress_and_error_completion(tmp_path, capsys):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(make_snapshot("aws", ["fixture"], [])))
    assert cli.main(["evaluate", str(path), "--categories", "hardening", "--checks", "aws.rds.encryption"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["provider"] == "aws"
    assert "evaluating" in output.err
    assert cli.main(["evaluate", str(tmp_path / "missing.json")]) == 2
    output = capsys.readouterr()
    assert "peaso progress: error" in output.err
    assert output.out == ""


def test_shared_collector_settlement_reports_empty_and_denied_without_contents():
    from peaso.collectors.base import Collector
    events = []
    collector = Collector("aws", ["fixture"], {"inventories": ["bucket"], "_progress_callback": events.append})
    collector.collect("bucket", "fixture", "s3", lambda: [])
    assert events[-1]["completed"] == 1 and events[-1]["resources"] == 0
    assert events[-1]["total"] is None
    assert "_progress_callback" not in json.dumps(collector.finish())
