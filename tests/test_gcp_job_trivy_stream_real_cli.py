"""Actual pinned Trivy ingestion; an unsupported synthetic image stays UNKNOWN."""
from pathlib import Path
import shutil

import pytest

from test_gcp_job_trivy_stream import stream, fixture, setup_large


def test_real_trivy_reads_streamed_archive_without_claiming_clean_coverage(tmp_path, monkeypatch):
    cli = shutil.which('trivy')
    import os
    cache = Path(os.environ['PEASO_TEST_TRIVY_DB']) if os.getenv('PEASO_TEST_TRIVY_DB') else None
    if cli is None or cache is None or not (cache / 'db/trivy.db').is_file():
        pytest.skip('actual pinned CLI and existing read-only DB cache required')
    monkeypatch.setattr(stream.tempfile, 'tempdir', str(tmp_path))
    selections, metadata, images, wire = setup_large(monkeypatch, compressed=True)
    scans = []
    def runner(*args, **kwargs):
        result = stream.collection.trivy.scan_image(*args, **kwargs)
        scans.append(result)
        return result
    result = stream.collect_native(wire, scope=fixture.SCOPE, selectors=selections, enabled=True,
        metadata_session=metadata, image_session=images, runner=runner,
        cli=cli, db_cache=cache, timeout=60, scratch_parent=tmp_path)
    assert len(scans) == 1
    scan = scans[0]
    assert scan['archive']['expanded_bytes'] > 8 * 1024 * 1024
    assert scan['invocation']['exit_code'] == 0, scan.get('diagnostics')
    assert scan['invocation']['stdout_bytes'] > 0
    assert scan['invocation']['process_group_cleanup'] is True
    assert scan['status'] == 'UNKNOWN'  # no supported OS/package scope in this image
    assert result['status'] == 'UNKNOWN'
    assert metadata.closed and images.closed
    assert list(tmp_path.iterdir()) == []
