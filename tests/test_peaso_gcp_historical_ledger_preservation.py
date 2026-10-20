"""Retain the exact signed GCP ledger independently of current corrections."""
import gzip
import hashlib
from pathlib import Path

import pytest

from tests import release_successor_history as history


def retained_root(tmp_path, monkeypatch):
    original = history.ROOT
    for relative in (history.PRE_REVIEW_LEDGER_BUNDLE, history.PRE_REVIEW_GCP_PCI):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((original / relative).read_bytes())
    monkeypatch.setattr(history, 'ROOT', tmp_path)


def test_original_gcp_pci_bytes_match_the_unchanged_signed_manifest(tmp_path, monkeypatch):
    retained_root(tmp_path, monkeypatch)
    retained = history.retained_ledger_inputs()
    assert hashlib.sha256(retained['gcp-pci.json']).hexdigest() == history.PRE_REVIEW_GCP_PCI_SHA256
    # No mutable current ledger is present in this isolated root.
    assert not (tmp_path / 'docs/compliance-ledgers/gcp-pci.json').exists()


def test_packed_gcp_predecessor_rejects_additional_bytes(tmp_path, monkeypatch):
    retained_root(tmp_path, monkeypatch)
    path = tmp_path / history.PRE_REVIEW_GCP_PCI
    path.write_bytes(path.read_bytes() + b'tampered')
    with pytest.raises(ValueError, match='GCP PCI packed digest'):
        history.retained_ledger_inputs()


def test_repacked_changed_source_still_rejects_original_content_digest(tmp_path, monkeypatch):
    retained_root(tmp_path, monkeypatch)
    path = tmp_path / history.PRE_REVIEW_GCP_PCI
    packed = gzip.compress(gzip.decompress(path.read_bytes()) + b' ', mtime=0)
    path.write_bytes(packed)
    monkeypatch.setattr(history, 'PRE_REVIEW_GCP_PCI_PACKED_SHA256', hashlib.sha256(packed).hexdigest())
    with pytest.raises(ValueError, match='GCP PCI source digest'):
        history.retained_ledger_inputs()
