"""The native backup optional-field adapter must reverse to the signed source."""
import hashlib
import json
from pathlib import Path

import pytest

from peaso.checks.bulk_pending import MANIFEST, _reviewed_source_admitted

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / 'peaso/checks/azure_backup_source_successor_20261020.json'


def source_pair():
    raw = PROOF.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'e771377b8994a0155d7c10d8779001d9aea7003a93b87a2a77941d7224034911'
    proof = json.loads(raw)
    actual = (ROOT / proof['path']).read_text()
    digest = hashlib.sha256(actual.encode()).hexdigest()
    assert digest in (proof['before_module_sha256'], proof['after_module_sha256'])
    if digest == proof['before_module_sha256']:
        assert actual.count(proof['before_function']) == 1
        after = actual.replace(proof['before_function'], proof['new_local_helper'] + proof['after_function'], 1)
        before = actual
    else:
        after = actual
        assert after.count(proof['after_function']) == after.count(proof['new_local_helper']) == 1
        before = after.replace(proof['after_function'], proof['before_function'], 1).replace(proof['new_local_helper'], '', 1)
    assert hashlib.sha256(before.encode()).hexdigest() == proof['before_module_sha256']
    assert hashlib.sha256(after.encode()).hexdigest() == proof['after_module_sha256']
    return proof, before.encode(), after.encode()


def test_original_pin_and_exact_reversible_backup_successor_are_accepted():
    proof, before, after = source_pair()
    pin = MANIFEST['modules']['compliance_new_sw13']
    assert pin == proof['before_module_sha256']
    assert _reviewed_source_admitted('compliance_new_sw13', before, pin)
    assert _reviewed_source_admitted('compliance_new_sw13', after, pin)


@pytest.mark.parametrize('fault', ['append', 'helper', 'operation', 'unrelated', 'module', 'pin'])
def test_unreviewed_backup_source_or_identity_is_rejected(fault):
    proof, _, after = source_pair()
    module, pin = 'compliance_new_sw13', proof['before_module_sha256']
    if fault == 'append':
        after += b'\n'
    elif fault == 'helper':
        after = after.replace(b"proof.get('read_only') is not True", b"proof.get('read_only') is False", 1)
    elif fault == 'operation':
        after = after.replace(b'BackupPolicies_List', b'Unreviewed_List', 1)
    elif fault == 'unrelated':
        after = after.replace(b'def backup_semantics(', b'def changed_semantics(', 1)
    elif fault == 'module':
        module = 'compliance_new_sw19'
    else:
        pin = '0' * 64
    assert not _reviewed_source_admitted(module, after, pin)


def test_proof_artifact_drift_is_rejected(monkeypatch):
    proof, _, after = source_pair()
    read_bytes = Path.read_bytes

    def altered(path):
        data = read_bytes(path)
        return data + b'\n' if path == PROOF else data

    monkeypatch.setattr(Path, 'read_bytes', altered)
    assert not _reviewed_source_admitted('compliance_new_sw13', after, proof['before_module_sha256'])
