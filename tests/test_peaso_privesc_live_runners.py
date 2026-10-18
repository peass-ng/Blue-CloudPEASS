"""Offline guards for the opt-in live credential experiments."""
import ast
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNNERS = [ROOT / "scripts/peaso_test_resources" / name for name in
           ("k8s_argocd_live_acceptance.py", "azure_sftp_live_acceptance.py")]


@pytest.mark.parametrize("runner", RUNNERS, ids=lambda p: p.stem)
def test_importing_live_runner_does_not_invoke_provider_commands(runner, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Importing an opt-in runner must not invoke external commands")

    monkeypatch.setattr(subprocess, "run", forbidden)
    spec = importlib.util.spec_from_file_location("offline_" + runner.stem, runner)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert callable(module.main)
    with pytest.raises(SystemExit) as result:
        module.main(["--help"])
    assert result.value.code == 0


@pytest.mark.parametrize("runner", RUNNERS, ids=lambda p: p.stem)
def test_live_runner_refuses_disabled_acceptance_assertions_before_creating_output(runner, tmp_path):
    output = tmp_path / "must-not-be-created"
    args = [sys.executable, "-O", str(runner), "--output", str(output)]
    if runner.name.startswith("azure"):
        args += ["--subscription", "00000000-0000-0000-0000-000000000001",
                 "--tenant", "00000000-0000-0000-0000-000000000002"]
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "acceptance assertions must remain enabled" in result.stderr
    assert not output.exists()


def test_argocd_container_proof_is_valid_standalone_python():
    tree = ast.parse(RUNNERS[0].read_text())
    programs = [node.value.value for node in ast.walk(tree)
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and any(isinstance(target, ast.Name) and target.id == "code" for target in node.targets)]
    assert len(programs) == 1
    # A previous wrapper refactor indented the literal after its first line and
    # broke the real Pod. Compile the exact argument passed to python3 -c.
    compile(programs[0], "argocd-container-proof", "exec")
