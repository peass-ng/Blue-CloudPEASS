"""Only the two reviewed native-adapter edits may supersede signed SW19 bytes."""
import hashlib
import json
from pathlib import Path

import pytest

from peaso.checks.bulk_pending import MANIFEST, _reviewed_source_admitted

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / 'docs/check-review/azure-sw19-native-source-successor-20261020.json'


def source_pair():
    raw = PROOF.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '7e3f47c4e1eea99f93d8d62cd5cf709a9d84d0e8067862440d22bcde4dcdfe11'
    proof = json.loads(raw)
    actual = (ROOT / proof['path']).read_text()
    digest = hashlib.sha256(actual.encode()).hexdigest()
    assert digest in (proof['predecessor_sha256'], proof['successor_sha256'])
    before = after = actual
    if digest == proof['predecessor_sha256']:
        for edit in proof['replacements']:
            assert after.count(edit['before']) == 1
            after = after.replace(edit['before'], edit['after'], 1)
    else:
        for edit in reversed(proof['replacements']):
            assert before.count(edit['after']) == 1
            before = before.replace(edit['after'], edit['before'], 1)
    assert hashlib.sha256(before.encode()).hexdigest() == proof['predecessor_sha256']
    assert hashlib.sha256(after.encode()).hexdigest() == proof['successor_sha256']
    return proof, before.encode(), after.encode()


def test_manifest_retains_original_pin_and_both_exact_reviewed_versions_are_accepted():
    proof, before, after = source_pair()
    pin = MANIFEST['modules']['compliance_new_sw19']
    assert pin == proof['predecessor_sha256']
    assert _reviewed_source_admitted('compliance_new_sw19', before, pin)
    assert _reviewed_source_admitted('compliance_new_sw19', after, pin)


@pytest.mark.parametrize('fault', ['append', 'helper', 'dependency', 'unrelated', 'module', 'pin'])
def test_unreviewed_source_or_admission_identity_is_rejected(fault):
    proof, _, after = source_pair()
    module, pin = 'compliance_new_sw19', proof['predecessor_sha256']
    if fault == 'append': after += b'\n'
    elif fault == 'helper': after = after.replace(b'if native is not None:', b'if native:', 1)
    elif fault == 'dependency': after = after.replace(b'azure_identity_enforcement_native', b'arbitrary_inventory', 1)
    elif fault == 'unrelated': after = after.replace(b'def _direct(', b'def _unreviewed_direct(', 1)
    elif fault == 'module': module = 'compliance_new_sw52'
    else: pin = '0' * 64
    assert not _reviewed_source_admitted(module, after, pin)
