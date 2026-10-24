"""Bounded image scan batching keeps ordered, source-bound observations."""
from contextlib import contextmanager

import pytest

from test_gcp_image_stream_inspection import image, run
from test_gcp_stream_file_continuation_20261021 import two_files
from peaso.collectors import gcp_image_stream_inspection_20261021 as inspection


def clean_scan(payload, path, timeout, **kwargs):
    return {'complete': True, 'engines': [
        {'engine': engine, 'status': 'complete', 'version': version}
        for engine, version in (('kingfisher', inspection.native.KINGFISHER_VERSION),
                                ('trufflehog', inspection.native.TRUFFLEHOG_VERSION))],
        'leaks': []}


def test_batch_preserves_order_and_exact_scanner_inputs(monkeypatch):
    batches, calls = [], []

    @contextmanager
    def batch(items, *, timeout):
        assert 0 < timeout <= 60
        batches.append(list(items))
        yield

    def scan(payload, path, timeout, **kwargs):
        calls.append((payload, path))
        return clean_scan(payload, path, timeout, **kwargs)

    monkeypatch.setattr(inspection, 'prepared_content_batch', batch)
    monkeypatch.setattr(inspection.native, 'scan_content', scan)
    row, blobs = two_files()
    result, _, _ = run(row, blobs)
    assert result['status'] == 'collected'
    assert len(batches) == 1
    assert batches[0] == calls[2:]
    assert [path for _, path in batches[0]] == [
        'member-1-name', 'member-1', 'member-2-name', 'member-2']


def test_later_archive_error_flushes_earlier_verified_positive(monkeypatch):
    original = inspection.visit_files
    batches = []

    @contextmanager
    def batch(items, *, timeout):
        batches.append(list(items))
        yield

    def broken(*args, **kwargs):
        original(*args, **kwargs)
        raise ValueError('later archive error')

    def scan(payload, path, timeout, **kwargs):
        result = clean_scan(payload, path, timeout, **kwargs)
        if path == 'member-2':
            result['leaks'] = [{'fingerprint': 'a' * 64,
                'detectors': [{'engine': 'kingfisher', 'rule': 'synthetic'}],
                'locations': [{'path': path, 'line': 1}]}]
        return result

    monkeypatch.setattr(inspection, 'prepared_content_batch', batch)
    monkeypatch.setattr(inspection, 'visit_files', broken)
    monkeypatch.setattr(inspection.native, 'scan_content', scan)
    result, _, _ = run(*two_files())
    assert result['status'] == 'partial' and result['complete'] is False
    assert [path for _, path in batches[0]][-1] == 'member-2'
    assert result['leaks'][0]['locations'][0]['path'] == 'member-2'
    assert result['source_reports'][0]['path'] == 'member-2'


def test_batched_window_keeps_original_line_offset(monkeypatch):
    @contextmanager
    def batch(items, *, timeout):
        yield

    def scan(payload, path, timeout, **kwargs):
        result = clean_scan(payload, path, timeout, **kwargs)
        if path == 'member-1' and len(payload) < inspection.WINDOW:
            result['leaks'] = [{'fingerprint': 'b' * 64,
                'detectors': [{'engine': 'trufflehog', 'rule': 'synthetic'}],
                'locations': [{'path': path, 'line': 1}]}]
        return result

    monkeypatch.setattr(inspection, 'prepared_content_batch', batch)
    monkeypatch.setattr(inspection.native, 'scan_content', scan)
    body = b'a\n' * (inspection.WINDOW // 2) + b'b\nc'
    result, _, _ = run(*image(body=body))
    assert result['status'] == 'collected'
    assert result['leaks'][0]['locations'][0]['line'] == (
        inspection.WINDOW // 2 - inspection.OVERLAP // 2 + 1)


def test_batch_cancel_stops_without_partial_publication(monkeypatch):
    @contextmanager
    def cancelled(items, *, timeout):
        raise TimeoutError('intentional_scan_deadline')
        yield

    monkeypatch.setattr(inspection, 'prepared_content_batch', cancelled)
    monkeypatch.setattr(inspection.native, 'scan_content', clean_scan)
    with pytest.raises(TimeoutError, match='intentional_scan_deadline'):
        run(*image())
