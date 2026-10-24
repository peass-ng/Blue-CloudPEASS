"""Sealed native-shaped ACR evidence must retain exact engine semantics."""
from copy import deepcopy
import pytest
from peaso import engine
from peaso.snapshot import make_snapshot
from peaso.collectors import azure_acr_image_vulnerabilities_20261021 as native
from peaso.checks import azure_acr_image_vulnerabilities_20261021 as check
from tests import test_azure_acr_image_vulnerabilities_20261021 as fixture
from tests import test_azure_acr_image_secret_review_20261020 as wire

from peaso.collectors import azure_acr_image_secret_indicators as acr, azure
PROPOSAL = (acr, azure, native, check)


def _snapshot(monkeypatch, tmp_path, mode):
    runner = fixture.fake_runner(mode if mode != 'PARTIAL' else 'FAIL')
    if mode == 'PARTIAL':
        def runner(image, manifest, config, layers, **kwargs):
            report = fixture.fake_runner('FAIL')(image, manifest, config, layers, **kwargs)
            report.update(complete=False, scan_complete=False, coverage_status='UNKNOWN', database={'fresh': False})
            return report
    result = fixture.collect(PROPOSAL, monkeypatch, tmp_path, runner=runner)
    _, idx = fixture.index(native, result, wire.SCOPE)
    return make_snapshot('azure', [wire.SCOPE], [idx['collections'][native.KIND][0]], metadata=idx['context']['metadata'])


def _statuses(snapshot):
    return [f['status'] for f in engine.evaluate_snapshot(snapshot, checks=[native.CHECK])['findings']]


@pytest.mark.parametrize(('mode','expected'), [('FAIL','FAIL'), ('PARTIAL','FAIL'), ('PASS','PASS')])
def test_sealed_native_engine_status(monkeypatch, tmp_path, mode, expected):
    snapshot = _snapshot(monkeypatch, tmp_path, mode)
    assert _statuses(snapshot) == [expected]


@pytest.mark.parametrize('damage', ['wrong_source','wrong_image','wrong_hash','bool_number'])
def test_sealed_malformed_evidence_unknown(monkeypatch, tmp_path, damage):
    snapshot = _snapshot(monkeypatch, tmp_path, 'FAIL')
    collection = snapshot['collections'][0]
    item = collection['items'][0]
    marker = item[native.MARKER]
    if damage == 'wrong_source':
        collection['_provenance']['credential_context_id'] = 'other-credential'
    elif damage == 'wrong_image':
        marker['image']['manifest_digest'] = 'sha256:' + '0'*64
    elif damage == 'wrong_hash':
        receipt = snapshot['metadata'][native.KIND+'_receipts'][3]
        receipt['digest'] = 'sha256:' + '0'*64
    else:
        marker['complete'] = 1
    snapshot = make_snapshot('azure', [wire.SCOPE], [collection], metadata=snapshot['metadata'])
    assert _statuses(snapshot) == ['UNKNOWN']


@pytest.mark.parametrize('container', ['list', 'dict'])
def test_arbitrary_container_subclass_rejected(monkeypatch, tmp_path, container):
    result = fixture.collect(PROPOSAL, monkeypatch, tmp_path, runner=fixture.fake_runner('FAIL'))
    item, idx = fixture.index(native, result, wire.SCOPE)
    class OtherList(list): pass
    class OtherDict(dict): pass
    if container == 'list':
        idx['collections'][native.KIND][0]['items'] = OtherList(idx['collections'][native.KIND][0]['items'])
    else:
        item[native.MARKER]['image'] = OtherDict(item[native.MARKER]['image'])
    assert check.evaluate(item, idx)[0] == 'UNKNOWN'
