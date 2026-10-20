"""Public synthetic derivatives of private customer policy history.

Source IDs name historical versions; they are not hashes of these public bytes.
The fixture replaces the private operator account and role name with synthetic
values while preserving policy documents and their order for delta tests.
"""

from __future__ import annotations

from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path


FIXTURE = Path(__file__).parent / "fixtures/aws-customer-policy-history-synthetic.json.gz"
FIXTURE_SHA256 = "ec5645c47a286863f9caa5f058ad827ff374fde9169b5835fef21d753245bf73"


@lru_cache(maxsize=1)
def _versions() -> dict:
    compressed = FIXTURE.read_bytes()
    assert hashlib.sha256(compressed).hexdigest() == FIXTURE_SHA256
    package = json.loads(gzip.decompress(compressed))
    assert package["schema_version"] == 1
    return package["versions"]


def historical_role_bytes(source_id: str) -> bytes:
    """Return deterministic derivative bytes after checking their own digest."""
    entry = _versions()[source_id]
    raw = json.dumps(entry["template"], sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
    return raw


def historical_role_template(source_id: str) -> dict:
    return json.loads(historical_role_bytes(source_id))


def historical_derivative_sha256(source_id: str) -> str:
    return _versions()[source_id]["sha256"]
