"""CLI contract for the new producer, using SDK Stubber and zero AWS calls."""
import json
import pytest

from peaso.cli import main
from peaso.collectors import aws
from peaso.snapshot import validate
from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from tests.test_peaso_aws_bedrock_reasoning_native import queue, CHECK, PRIVATE


@pytest.mark.parametrize('mode,expected', [('pass', 'PASS'), ('one_missing', 'FAIL')])
def test_cli_scan_new_native_bedrock_and_render_same_capture(monkeypatch, sdk, tmp_path, mode, expected):
    session, stubs, calls = queue(sdk, mode, hosted=True)
    selected = []
    def pinned(auth, region):
        selected.append((dict(auth), region))
        return session, 'inert-sdk-fixture'
    monkeypatch.setattr(aws, '_session', pinned)
    options, report_path, snapshot_path, markdown_path = [tmp_path / name for name in
        ('options.json', 'report.json', 'snapshot.json', 'report.md')]
    options.write_text(json.dumps({'service_concurrency': 1, 'retry_attempts': 1}))
    assert main(['scan', '--provider', 'aws', '--profile', 'inert-readonly-fixture',
        '--scopes', ACCOUNT + '/' + REGION, '--checks', CHECK, '--options-file', str(options),
        '--embed-snapshot', '--snapshot-output', str(snapshot_path), '--output', str(report_path), '--quiet']) == 0
    report = json.loads(report_path.read_text())
    snapshot = validate(json.loads(snapshot_path.read_text()))
    findings = [f for f in report['findings'] if f['check_id'] == CHECK]
    assert findings and all(f['status'] == expected for f in findings)
    assert snapshot['metadata']['calls'] == calls
    assert selected == [({'profile': 'inert-readonly-fixture'}, REGION)]
    assert report['snapshot_id'] == snapshot['snapshot_id'] == report['snapshot']['snapshot_id']
    assert PRIVATE not in report_path.read_text() and PRIVATE not in snapshot_path.read_text()
    # Render the same embedded immutable capture; no second provider scan.
    assert main(['report', str(report_path), '--format', 'markdown', '--output', str(markdown_path)]) == 0
    markdown = markdown_path.read_text()
    assert expected in markdown and PRIVATE not in markdown
    assert selected == [({'profile': 'inert-readonly-fixture'}, REGION)]
    for stub in stubs: stub.assert_no_pending_responses()
