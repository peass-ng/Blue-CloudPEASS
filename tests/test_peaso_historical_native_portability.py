"""Source414 native history must survive without a retained source ZIP."""

import gzip
import hashlib
import json

import pytest

from tests import release_successor_history as history


MEMBER = history.SOURCE414_NATIVE_MEMBER
MANIFEST = "tests/fixtures/post_dfaf_integration/historical-release-manifests.json"


def _missing_archive(root):
    archive = root / history.PUBLISHED_SPRINT_ARCHIVE.name
    assert not archive.exists()
    return archive


def _copy_inputs(root):
    for relative in (history.SOURCE414_NATIVE_BASELINE, history.SOURCE414_NATIVE_DELTA, MANIFEST):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((history.ROOT / relative).read_bytes())


def test_no_zip_native_member_matches_published_release_digest(tmp_path):
    archive = _missing_archive(tmp_path)
    raw = history.historical_bytes(archive, MEMBER)
    manifest = history.historical_release(archive)
    assert hashlib.sha256(raw).hexdigest() == manifest["files"][MEMBER]
    assert hashlib.sha256(raw).hexdigest() == history.SOURCE414_NATIVE_SHA256
    assert len(json.loads(raw)["checks"]) == 3986


def test_tampered_immutable_base_is_rejected(tmp_path, monkeypatch):
    _copy_inputs(tmp_path)
    baseline = tmp_path / history.SOURCE414_NATIVE_BASELINE
    baseline.write_bytes(baseline.read_bytes() + b" ")
    monkeypatch.setattr(history, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="baseline archive digest"):
        history.historical_bytes(_missing_archive(tmp_path), MEMBER)


def test_tampered_compressed_delta_is_rejected(tmp_path, monkeypatch):
    _copy_inputs(tmp_path)
    delta = tmp_path / history.SOURCE414_NATIVE_DELTA
    delta.write_bytes(delta.read_bytes() + b"x")
    monkeypatch.setattr(history, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="delta digest"):
        history.historical_bytes(_missing_archive(tmp_path), MEMBER)


def test_repinned_changed_record_is_rejected_by_release_digest(tmp_path, monkeypatch):
    _copy_inputs(tmp_path)
    delta = tmp_path / history.SOURCE414_NATIVE_DELTA
    patch = json.loads(gzip.decompress(delta.read_bytes()))
    record = next(iter(patch["replacements"].values()))
    record["title"] += " (tampered)"
    packed = gzip.compress((json.dumps(patch, ensure_ascii=False, separators=(",", ":")) + "\n").encode(),
                           compresslevel=9, mtime=0)
    delta.write_bytes(packed)
    monkeypatch.setattr(history, "ROOT", tmp_path)
    monkeypatch.setattr(history, "SOURCE414_NATIVE_DELTA_SHA256", hashlib.sha256(packed).hexdigest())
    with pytest.raises(ValueError, match="reconstruction digest"):
        history.historical_bytes(_missing_archive(tmp_path), MEMBER)


def test_repinned_changed_baseline_is_rejected_by_original_digest(tmp_path, monkeypatch):
    _copy_inputs(tmp_path)
    baseline = tmp_path / history.SOURCE414_NATIVE_BASELINE
    original = gzip.decompress(baseline.read_bytes())
    packed = gzip.compress(original + b" ", compresslevel=9, mtime=0)
    baseline.write_bytes(packed)
    monkeypatch.setattr(history, "ROOT", tmp_path)
    monkeypatch.setattr(history, "SOURCE414_NATIVE_BASELINE_PACKED_SHA256", hashlib.sha256(packed).hexdigest())
    with pytest.raises(ValueError, match="baseline digest"):
        history.historical_bytes(_missing_archive(tmp_path), MEMBER)
