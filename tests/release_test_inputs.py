"""Restore pinned public regression inputs omitted from the runtime archive.

The bundle contains synthetic cases and historical check research, never live
cloud snapshots. Existing files belong to the checkout and are not overwritten.
Only missing inputs are materialized, and pytest removes those on exit.
"""
from __future__ import annotations

import lzma
import hashlib
import json
from pathlib import Path

BUNDLE_SHA256 = "22a461142de5b0d876f0a8e4e036aea3e9b46d5318f7a49958c1e58f7fd1cd28"
MAX_EXPANDED_BYTES = 16_000_000


def restore_missing_inputs(root: Path) -> list[Path]:
    bundle = root / "tests/fixtures/release-test-inputs.json.xz"
    packed = bundle.read_bytes()
    if hashlib.sha256(packed).hexdigest() != BUNDLE_SHA256:
        raise ValueError("Release regression input bundle digest differs")
    decoder = lzma.LZMADecompressor(memlimit=64 * 1024 * 1024)
    raw = decoder.decompress(packed, max_length=MAX_EXPANDED_BYTES + 1)
    if len(raw) > MAX_EXPANDED_BYTES:
        raise ValueError("Release regression input bundle exceeds expanded limit")
    if not decoder.eof or decoder.unused_data:
        raise ValueError("Release regression input bundle is truncated or has trailing data")
    payload = json.loads(raw)
    if payload.get("schema") != 1 or len(payload.get("files", {})) != 74:
        raise ValueError("Release regression input bundle schema differs")
    pending = []
    for name, entry in payload["files"].items():
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts or (relative.suffix != ".json" and name not in {"tests/fixtures/privesc_bounded/aws.yaml", "tests/fixtures/privesc_bounded/azure.yaml", "tests/fixtures/privesc_bounded/gcp.yaml"})
                or not name.startswith(("tests/fixtures/", "docs/compliance-ledgers/.work/swarm/"))):
            raise ValueError("Unexpected release regression input path")
        target = root / relative
        if not target.resolve().is_relative_to(root.resolve()):
            raise ValueError("Release regression input escapes checkout")
        data = entry["text"].encode()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("Release regression input digest differs")
        if not target.exists():
            pending.append((target, data))
    created = []
    try:
        for target, data in pending:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
            created.append(target)
    except BaseException:
        for path in created:
            path.unlink()
        raise
    return created
