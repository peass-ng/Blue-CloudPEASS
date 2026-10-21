"""Selected package JVM constants are inspectable without executing Java."""
import importlib.util
import io
import json
from pathlib import Path
import struct
import socket
import zipfile
import pytest
from peaso import jvm_class_constant_text_20261021 as jvm
from peaso import secret_scanning
from peaso.collectors import gcp_dataflow_referenced_source_20261020 as source

TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
ROOT = Path(__file__).resolve().parents[1]
# The retained native HTTP harness supplies actual GET bodies and framing.
HARNESS = None


def class_bytes(value=b'ordinary', *, major=61, minor=0, extra=b''):
    def utf(value): return b'\x01' + len(value).to_bytes(2, 'big') + value
    pool = utf(b'Fixture') + b'\x07\x00\x01' + utf(b'java/lang/Object') + b'\x07\x00\x03' + utf(value) + b'\x08\x00\x05'
    return b'\xca\xfe\xba\xbe' + struct.pack('>HHH', minor, major, 7) + pool + struct.pack('>7H', 0x21, 2, 4, 0, 0, 0, 0) + extra


@pytest.mark.parametrize('major', [45, 52, 61, 69])
def test_supported_constant_pool_text(major):
    text = jvm.extract_constant_text(class_bytes(TOKEN.encode(), major=major))
    assert TOKEN.encode() in text and b'java/lang/Object' in text
    assert not text.startswith(b'\xca\xfe\xba\xbe')


@pytest.mark.parametrize('encoded,expected', [(b'left\xc0\x80right', b'left\nright'),
    (b'hello\xed\xa0\xbd\xed\xb8\x80', 'hello😀'.encode()), (b'\xc2\xa3', '£'.encode())])
def test_modified_utf8_preserves_boundaries(encoded, expected):
    assert expected in jvm.extract_constant_text(class_bytes(encoded))


@pytest.mark.parametrize('encoded', [b'\x00', b'\xc0\x81', b'\xc1\x80', b'\xe0\x80\x80', b'\xf0\x9f\x98\x80', b'\xed\xa0\xbd', b'\xff'])
def test_malformed_encoding_rejected(encoded):
    with pytest.raises(ValueError): jvm.extract_constant_text(class_bytes(encoded))


@pytest.mark.parametrize('value', [b'', b'not a class', class_bytes()[:12], class_bytes(major=70),
    class_bytes(major=56, minor=1), class_bytes()[:-1], b'\xca\xfe\xba\xbe'+b'\0'*30])
def test_bad_framing_or_unknown_version_rejected(value):
    with pytest.raises(ValueError): jvm.extract_constant_text(value)


def test_unknown_tag_and_constant_limits_rejected(monkeypatch):
    bad = bytearray(class_bytes()); bad[10] = 2
    with pytest.raises(ValueError): jvm.extract_constant_text(bytes(bad))
    monkeypatch.setattr(jvm, 'MAX_CONSTANTS', 4)
    with pytest.raises(ValueError): jvm.extract_constant_text(class_bytes())


def test_text_budget_and_class_byte_budget(monkeypatch):
    monkeypatch.setattr(jvm, 'MAX_TEXT_BYTES', 4)
    with pytest.raises(ValueError): jvm.extract_constant_text(class_bytes())
    monkeypatch.setattr(jvm, 'MAX_CLASS_BYTES', 24)
    with pytest.raises(ValueError): jvm.extract_constant_text(class_bytes())


def harness():
    global HARNESS
    if HARNESS is None:
        p = ROOT/'tests/gcp_dataflow_referenced_source_20261020_test.py'
        spec = importlib.util.spec_from_file_location('jvm_native_http_harness', p)
        HARNESS = importlib.util.module_from_spec(spec); spec.loader.exec_module(HARNESS)
    return HARNESS


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def block(*a, **kw): raise AssertionError('no live credentials/network allowed')
    monkeypatch.setattr(socket, 'create_connection', block)
    monkeypatch.setattr(socket.socket, 'connect', block)
    secret_scanning._RESULTS.clear()
    yield
    secret_scanning._RESULTS.clear()


@pytest.mark.parametrize('positive', [False, True])
def test_full_native_package_to_existing_consumer(monkeypatch, positive):
    native = harness()
    monkeypatch.setattr(native, 'source', source)
    def detector(payload, path, timeout):
        return [(TOKEN, 'github-pat', 1)] if TOKEN.encode() in payload else []
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', detector)
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', detector)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as archive:
        archive.writestr('Fixture.class', class_bytes(TOKEN.encode() if positive else b'ordinary'))
        archive.writestr('config.properties', b'mode=ready\n')
    capture, outcomes, calls, auth = native.capture(monkeypatch, buf.getvalue(), targets=[native.target('zip')])
    status, evidence = outcomes[0]
    assert status == ('FAIL' if positive else 'UNKNOWN'), (status, evidence)
    assert not capture['items'][0]['complete'] and len(calls) == 9 and len(auth) == 9
    assert len(capture['items'][0]['parts']) == 2  # class extraction does not stop later member scanning
    assert TOKEN not in json.dumps(capture)
    if positive:
        assert evidence['complete'] is False
        assert len(evidence['secret_leaks']) == 1
        assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']} == {'kingfisher','trufflehog'}


def test_clean_text_archive_still_passes(monkeypatch):
    native = harness(); monkeypatch.setattr(native, 'source', source)
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', lambda *a: [])
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as archive: archive.writestr('source.py', b'mode=ready\n')
    capture, outcomes, _, _ = native.capture(monkeypatch,buf.getvalue(),targets=[native.target('zip')])
    assert outcomes[0][0]=='PASS' and capture['items'][0]['complete']


def test_malformed_class_never_clean_pass(monkeypatch):
    native = harness(); monkeypatch.setattr(native,'source',source)
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as archive: archive.writestr('Broken.class', class_bytes()[:12])
    capture,outcomes,_,_=native.capture(monkeypatch,buf.getvalue(),targets=[native.target('zip')])
    assert outcomes[0][0]=='UNKNOWN' and not capture['items'][0]['complete']


@pytest.mark.parametrize('fault_kind', ['generation', 'denied', 'association'])
def test_native_binding_failure_never_reaches_class_scan(monkeypatch, fault_kind):
    native=harness();monkeypatch.setattr(native,'source',source)
    calls=[]
    monkeypatch.setattr(secret_scanning,'_scan_kingfisher',lambda *a: calls.append(True) or [])
    monkeypatch.setattr(secret_scanning,'_scan_trufflehog',lambda *a: calls.append(True) or [])
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as archive: archive.writestr('Fixture.class',class_bytes())
    def fault(op,data,response):
        if fault_kind=='generation' and op=='content':response.headers['X-Goog-Generation']='999'
        if fault_kind=='denied' and op=='content':response.status_code=403
        if fault_kind=='association' and op=='reference_after':
            data['environment']['workerPools'][0]['packages'][0]['location']='storage.googleapis.com/foreign-bucket/x.jar'
            response.payload=json.dumps(data).encode();response.stream=io.BytesIO(response.payload);response.headers['Content-Length']=str(len(response.payload))
    capture,outcomes,_,_=native.capture(monkeypatch,buf.getvalue(),targets=[native.target('zip')],fault=fault)
    assert outcomes[0][0]=='UNKNOWN' and not calls


def test_secret_before_bad_class_retained(monkeypatch):
    native=harness();monkeypatch.setattr(native,'source',source)
    def detector(payload,path,timeout): return [(TOKEN,'github-pat',1)] if TOKEN.encode() in payload else []
    monkeypatch.setattr(secret_scanning,'_scan_kingfisher',detector)
    monkeypatch.setattr(secret_scanning,'_scan_trufflehog',detector)
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as archive:
        archive.writestr('config.py', ('token='+TOKEN).encode())
        archive.writestr('Broken.class',class_bytes()[:12])
    capture,outcomes,_,_=native.capture(monkeypatch,buf.getvalue(),targets=[native.target('zip')])
    assert outcomes[0][0]=='FAIL' and outcomes[0][1]['complete'] is False
