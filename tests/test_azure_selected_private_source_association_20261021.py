"""Native selected Azure sources bind encrypted values to their owner findings."""
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from peaso import secret_evidence
from peaso import secret_scanning

STAGE = Path(__file__).resolve().parents[1]


def fixture_module(name):
    path = STAGE / 'tests' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name + '_private', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def finding(check, scope, item, evidence):
    return {'check_id': check, 'provider': 'azure', 'status': 'FAIL',
            'finding_type': 'secrets', 'scope': scope,
            'resource_id': item['id'], 'native_resource_id': item['id'],
            'evidence': evidence}


def assert_bound(sink, cipher, result, owner, scope, check, value):
    assert result[0] == 'FAIL'
    public = finding(check, scope, owner, result[1])
    document = sink.document()
    assert value not in json.dumps((owner, public, document), default=str)
    detail = secret_evidence.details(public, document, cipher, tenant='offline', scan_id='a' * 32)
    assert detail['status'] == 'available', detail
    assert {match['value'] for match in detail['matches']} == {value}
    assert all(loc['resource_id'] == owner['id'] for match in detail['matches'] for loc in match['locations'])
    other = {**public, 'resource_id': 'foreign-selected-resource',
             'native_resource_id': 'foreign-selected-resource'}
    assert secret_evidence.details(other, document, cipher, tenant='offline', scan_id='a' * 32)['matches'] == []
    other = {**public, 'scope': '/subscriptions/99999999-9999-9999-9999-999999999999'}
    assert secret_evidence.details(other, document, cipher, tenant='offline', scan_id='a' * 32)['matches'] == []


def test_flex_native_archive_private_owner(monkeypatch):
    native = fixture_module('test_azure_flex_configured_archives')
    cipher = secret_evidence.EphemeralCipher()
    def detector(data,path,timeout):
        return [(native.TOKEN,'fixture-rule',1)] if native.TOKEN.encode() in data else []
    secret_scanning._RESULTS.clear()
    with patch.object(secret_scanning,'_scan_kingfisher',detector), patch.object(secret_scanning,'_scan_trufflehog',detector), \
            secret_evidence.capture(cipher, tenant='offline', scan_id='a' * 32) as sink:
        result = native.run(monkeypatch, [(native.BLOB, native.zipdata(native.TOKEN))])
    status, evidence, item, _, _ = result
    assert status=='FAIL',item[native.flex.MARKER]['reason']
    assert_bound(sink, cipher, (status, evidence), item, native.SCOPE, native.flex.CHECK, native.TOKEN)


def test_ml_code_asset_private_owner():
    native = fixture_module('test_azure_ml_job_code_binding_20261021')
    cipher = secret_evidence.EphemeralCipher()
    with secret_evidence.capture(cipher, tenant='offline', scan_id='a' * 32) as sink:
        _, _, item, result, _ = native.run_case(hit=True, capture=True)
    assert result[0]=='FAIL',(result[0], [(k, len(v) if k=='leaks' else v) for k,v in item[native.source.MARKER].items() if k in ('native_complete','complete','coverage','status','error','leaks')])
    assert_bound(sink, cipher, result, item, native.SUB,
                 native.source.PROFILES['code']['check'], 'private-value')


def test_ml_job_private_owner(monkeypatch):
    native = fixture_module('test_azure_ml_selected_job_secret_review_20261020')
    cipher = secret_evidence.EphemeralCipher()
    with secret_evidence.capture(cipher, tenant='offline', scan_id='a' * 32) as sink:
        snapshot, rows, _ = native.collect(monkeypatch, literal=native.TOKEN)
    item = native.own(snapshot)['items'][0]
    row, = [r for r in rows if r['status']=='FAIL']
    assert_bound(sink, cipher, ('FAIL', row['evidence']), item,
                 native.SCOPE, native.source.CHECK, native.TOKEN)


def test_aks_native_oci_private_owner():
    native = fixture_module('test_azure_selected_aks_image_20261021')
    from copy import deepcopy
    from peaso.collectors import k8s_selected_registry_image_20261021 as image
    unit = native.NativeTests('runTest')
    unit.setUp()
    wire = native.Wire(unit.blobs)
    def detector(data, path, timeout):
        return [('mode=ready', 'fixture-rule', 1)] if b'mode=ready' in data else []
    cipher = secret_evidence.EphemeralCipher()
    secret_scanning._RESULTS.clear()
    with patch.object(secret_scanning, '_scan_kingfisher', detector), \
         patch.object(secret_scanning, '_scan_trufflehog', detector), \
         secret_evidence.capture(cipher, tenant='offline', scan_id='a' * 32) as sink:
        marker = native.bridge.inspect_selected(unit.target,
            arm_get=lambda _: deepcopy(unit.arm), namespace_get=lambda: deepcopy(unit.ns),
            pod_get=lambda _: deepcopy(unit.pod), context=unit.context, tenant='tenant-id',
            allowed_hosts=['ghcr.io'],
            registry_factory=lambda h,r,c,**kw:image.RegistryReader(h,r,c,open_https=wire,**kw),
            scanner=image._scan)
    item = {'id': native.bridge.identity(unit.target), 'SelectedAksImage': marker}
    index = {'context': {'provider': 'azure', 'scope': native.SCOPE,
             'metadata': {native.bridge.KIND+'_authorized': True, native.bridge.OPTION: [unit.target]}},
             'collections': {native.bridge.KIND: [{'scope': native.SCOPE, 'status': 'collected', 'items': [item]}]}}
    result = native.review.evaluate(item, index)
    assert_bound(sink, cipher, result, item, native.SCOPE, native.bridge.CHECK, 'mode=ready')
