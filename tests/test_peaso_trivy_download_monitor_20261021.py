"""Real local child-process checks. No scanner, images, DB or network access."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

spec = importlib.util.spec_from_file_location(
    "bounded_trivy", Path(__file__).resolve().parents[1] / "peaso/trivy_database_20261021.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture(autouse=True)
def quick_monitor(monkeypatch):
    monkeypatch.setattr(module, "DOWNLOAD_POLL_SECONDS", 0.01)
    monkeypatch.setattr(module, "DOWNLOAD_TIMEOUT_SECONDS", 2)


def launch(tmp_path, code):
    module._download([sys.executable, "-c", code, str(tmp_path)], tmp_path, dict(os.environ))


def assert_reaped(tmp_path):
    pid = int((tmp_path / "pid").read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_multi_file_growth_stops_and_reaps_child(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "MAX_CACHE_BYTES", 65536)
    # Disable only the per-file OS limit to prove aggregate observation acts.
    monkeypatch.setattr(module, "_limit_file_size", lambda: None)
    code = ("import os,pathlib,sys,time;p=pathlib.Path(sys.argv[1]);"
            "(p/'pid').write_text(str(os.getpid()));"
            "(p/'one').write_bytes(bytes(40000));"
            "(p/'two').write_bytes(bytes(40000));time.sleep(20)")
    started = time.monotonic()
    with pytest.raises(module.DatabaseUnavailable, match="cache size limit"):
        launch(tmp_path, code)
    assert time.monotonic() - started < 2
    assert_reaped(tmp_path)


def test_timeout_kills_and_reaps_child(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "DOWNLOAD_TIMEOUT_SECONDS", 0.2)
    with pytest.raises(subprocess.TimeoutExpired):
        launch(tmp_path, "import os,pathlib,sys,time;"
               "(pathlib.Path(sys.argv[1])/'pid').write_text(str(os.getpid()));time.sleep(20)")
    assert_reaped(tmp_path)


def test_nonzero_exit_is_not_success(tmp_path):
    with pytest.raises(subprocess.CalledProcessError) as error:
        launch(tmp_path, "raise SystemExit(7)")
    assert error.value.returncode == 7


def test_success_checked_and_reaped(tmp_path):
    launch(tmp_path, "import pathlib,sys;(pathlib.Path(sys.argv[1])/'ok').write_bytes(b'complete')")
    assert (tmp_path / "ok").read_bytes() == b"complete"


def test_link_or_entry_flood_is_rejected(tmp_path, monkeypatch):
    (tmp_path / "linked").symlink_to(tmp_path.parent)
    with pytest.raises(module.DatabaseUnavailable, match="linked"):
        module._size(tmp_path)
    (tmp_path / "linked").unlink()
    monkeypatch.setattr(module, "MAX_STAGING_ENTRIES", 2)
    for i in range(3):
        (tmp_path / str(i)).touch()
    with pytest.raises(module.DatabaseUnavailable, match="excessive"):
        module._size(tmp_path)


def test_reserved_space_loss_interrupts_child(tmp_path, monkeypatch):
    monkeypatch.setattr(module.shutil, "disk_usage", lambda _: type("Disk", (), {"free": 0})())
    with pytest.raises(module.DatabaseUnavailable, match="reserved disk"):
        launch(tmp_path, "import time;time.sleep(20)")
