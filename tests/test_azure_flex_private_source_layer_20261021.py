"""Native Function and Blob ZIP source to encrypted owner finding proof."""
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch

from peaso import secret_evidence, secret_scanning


def fixture():
    path = Path(__file__).resolve().parents[1] / 'tests/test_azure_flex_configured_archives.py'
    spec = importlib.util.spec_from_file_location('flex_native_fixture_private_layer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def finding(native, item, evidence):
    return {'check_id': native.flex.CHECK, 'provider': 'azure', 'status': 'FAIL',
            'finding_type': 'secrets', 'scope': native.SCOPE,
            'resource_id': item['id'], 'native_resource_id': item['id'], 'evidence': evidence}


def detector(native):
    def scan(data, path, timeout):
        return [(native.TOKEN, 'fixture-rule', 1)] if native.TOKEN.encode() in data else []
    return scan


def test_exact_child_layer_rebinds_owner_and_excludes_foreign_blob(monkeypatch):
    native = fixture()
    cipher = secret_evidence.EphemeralCipher()
    secret_scanning._RESULTS.clear()
    scan = detector(native)
    with patch.object(secret_scanning, '_scan_kingfisher', scan), \
         patch.object(secret_scanning, '_scan_trufflehog', scan), \
         secret_evidence.capture(cipher, tenant='offline', scan_id='a' * 32) as sink:
        status, evidence, item, trace, _ = native.run(monkeypatch, [(native.BLOB, native.zipdata(native.TOKEN))])
        secret_evidence.scan_with_source(secret_scanning.scan_content, native.TOKEN.encode(), 'foreign-blob',
            source={'resource_id': 'foreign-blob-id', 'scope': native.SCOPE,
                    'layer': 'foreign-blob-layer'})
    assert status == 'FAIL' and len([call for call in trace.calls if call[0] == 'content']) == 1
    public = finding(native, item, evidence)
    document = sink.document()
    assert native.TOKEN not in json.dumps((item, public, document), default=str)
    detail = secret_evidence.details(public, document, cipher, tenant='offline', scan_id='a' * 32)
    assert detail['status'] == 'available'
    assert {match['value'] for match in detail['matches']} == {native.TOKEN}
    locations = [loc for match in detail['matches'] for loc in match['locations']]
    assert locations and all(loc['resource_id'] == item['id'] and loc['scope'] == native.SCOPE for loc in locations)
    assert all(loc['layer'].startswith('flex-selected-archive:' + item['id'] + ':') for loc in locations)
    assert all(loc['path'] != 'foreign-blob' for loc in locations)
    foreign = {**public, 'resource_id': 'foreign-blob-id', 'native_resource_id': 'foreign-blob-id'}
    assert secret_evidence.details(foreign, document, cipher, tenant='offline', scan_id='a' * 32)['matches'] == []
    foreign = {**public, 'scope': '/subscriptions/99999999-9999-9999-9999-999999999999'}
    assert secret_evidence.details(foreign, document, cipher, tenant='offline', scan_id='a' * 32)['matches'] == []


def test_native_drift_keeps_positive_public_but_unbound_private(monkeypatch):
    native = fixture()
    cipher = secret_evidence.EphemeralCipher()
    secret_scanning._RESULTS.clear()
    scan = detector(native)
    with patch.object(secret_scanning, '_scan_kingfisher', scan), \
         patch.object(secret_scanning, '_scan_trufflehog', scan), \
         secret_evidence.capture(cipher, tenant='offline', scan_id='a' * 32) as sink:
        status, evidence, item, _, _ = native.run(monkeypatch,
            [(native.BLOB, native.zipdata(native.TOKEN))], fault='site_drift')
    assert status == 'FAIL' and evidence['complete'] is False
    detail = secret_evidence.details(finding(native, item, evidence), sink.document(), cipher,
                                     tenant='offline', scan_id='a' * 32)
    assert detail['matches'] == []
