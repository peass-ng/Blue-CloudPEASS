"""Main resource-identity aliases preserve the exact historical source proof."""
import hashlib
from pathlib import Path

import pytest

from peaso.checks import private_secret_shared_source_successor_20261021 as shared
from peaso.checks import k8s_annotation_native_source_successor_20261021 as annotation


def test_snapshot_source_successor_reconstructs_original_and_rejects_unadmitted_bytes(tmp_path):
    root = Path(__file__).resolve().parents[1]
    current = (root / 'peaso/snapshot.py').read_bytes()
    before = shared._private_before('peaso/snapshot.py', current, root)
    assert hashlib.sha256(before).hexdigest() == annotation.SNAPSHOT_SHA
    assert before != current
    assert b'"apigatewayv2_domain_name": "DomainName"' in current
    assert b'"apigatewayv2_domain_name": "DomainName"' not in before
    copied = tmp_path / 'peaso/snapshot.py'
    copied.parent.mkdir()
    copied.write_bytes(current + b'\n# unadmitted source change\n')
    with pytest.raises(RuntimeError, match='current source changed'):
        shared._private_before('peaso/snapshot.py', copied.read_bytes(), tmp_path)
