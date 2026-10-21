"""Actual pinned offline scanners over synthetic image contents, never cloud data."""
from importlib.metadata import version
import json

from test_gcp_image_stream_inspection import image, run, inspection, reviewed_predicate, index


def test_actual_dual_detectors_deduplicate_a_cross_window_synthetic_leak(tmp_path, monkeypatch):
    assert version('kingfisher-secret-scanner') == inspection.native.KINGFISHER_VERSION
    from peaso import secret_scanning as scanner
    assert scanner._trufflehog()
    monkeypatch.setattr(inspection.tempfile, 'tempdir', str(tmp_path))
    # Synthetic-format witness from the existing offline fixture. No validation
    # or credential-use operation is enabled in either scanner.
    token = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
    prefix = b'x\n' * ((inspection.WINDOW - 20) // 2) + b'github_token='
    body = prefix + token.encode() + b'\n' + b'x\n' * (4 * 1024 * 1024)
    row, blobs = image(body=body, compressed=True)
    result, _, _ = run(row, blobs)
    assert result['complete'] is True, {'status': result['status'], 'engines': result.get('engines')}
    assert len(result['leaks']) == 1
    assert {entry['engine'] for entry in result['leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert token not in json.dumps(result)
    row[inspection.native.MARKER] = result
    assert reviewed_predicate().evaluate(row, index(row))[0] == 'FAIL'
    assert list(tmp_path.iterdir()) == []
