"""Exact redundant predecessor bytes for source archives that omit runtime gzip."""
import gzip
import hashlib
from pathlib import Path

ORIGINAL = 'peaso/rulepacks/upstream_manifest.json.gz'
RETAINED = 'tests/fixtures/native_admission_upstream_predecessor_20261020.json.gz'
SHA256 = '6232725153003d431a816193dd1c507cca76f7edea1bc0621063436affc391ff'


def original_bytes(root):
    root = Path(root)
    retained = root / RETAINED
    raw = (retained if retained.exists() else root / ORIGINAL).read_bytes()
    assert len(raw) == 2721260 and hashlib.sha256(raw).hexdigest() == SHA256
    assert gzip.decompress(raw) == (root / ORIGINAL.removesuffix('.gz')).read_bytes()
    if (root / ORIGINAL).exists():
        assert (root / ORIGINAL).read_bytes() == raw
    return raw
