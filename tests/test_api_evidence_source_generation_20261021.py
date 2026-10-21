"""Released native initializer successors must retain API presentation parity."""
import hashlib
from pathlib import Path

from peaso.server import evidence_static


def test_api_evidence_manifest_pins_the_released_native_initializer():
    root = Path(__file__).resolve().parents[1]
    relative = 'peaso/checks/__init__.py'
    assert evidence_static.MANIFEST[relative] == hashlib.sha256((root / relative).read_bytes()).hexdigest()
    evidence_static.verify_closure()
