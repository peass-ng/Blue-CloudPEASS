"""CLI rejects the archived Bedrock control before any provider read."""
import json

from peaso.cli import main
from peaso.collectors import aws
from tests.test_peaso_aws_bedrock_reasoning_native import CHECK, REGION, ACCOUNT


def test_cli_scan_rejects_bedrock_native_only_selection(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(aws, "_session", lambda *_args, **_kwargs:
                        (_ for _ in ()).throw(AssertionError("provider session must not be opened")))
    options = tmp_path / "options.json"
    report = tmp_path / "report.json"
    snapshot = tmp_path / "snapshot.json"
    options.write_text(json.dumps({"service_concurrency": 1, "retry_attempts": 1}))
    status = main(["scan", "--provider", "aws", "--profile", "inert-readonly-fixture",
                   "--scopes", ACCOUNT + "/" + REGION, "--checks", CHECK,
                   "--options-file", str(options), "--embed-snapshot",
                   "--snapshot-output", str(snapshot), "--output", str(report), "--quiet"])
    assert status == 2
    assert "external policy or manual evidence" in capsys.readouterr().err
    assert not report.exists() and not snapshot.exists()
