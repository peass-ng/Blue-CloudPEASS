"""Bounded expansion retains the existing full-object JSON/gzip contract."""
import gzip
import json
from types import SimpleNamespace

import pytest

from peaso.attack_detection import history_s3
from test_attack_detection_history_s3 import ObjectClient, object_manifest, record


def read(raw, **limits):
    day, obj = object_manifest(raw)
    client = ObjectClient(raw)
    try:
        return history_s3.read_cloudtrail_object(client, day, obj, **limits)
    finally:
        assert client.body.closed


@pytest.mark.parametrize('size', [65535, 65536, 65537, 1048575, 1048576, 1048577, 2097152])
def test_chunk_boundaries_and_exact_expansion_limit(size, monkeypatch):
    value = json.dumps({'Records': [record()]})
    payload = (value + ' ' * (size - len(value))).encode()
    # Multiple members exercise the compatibility path as well as boundaries.
    raw = gzip.compress(payload[:-1], mtime=0) + gzip.compress(payload[-1:], mtime=0)
    reads = []
    original = gzip.GzipFile

    class Observed(original):
        def read(self, size=-1):
            reads.append(size)
            return super().read(size)

    monkeypatch.setattr(gzip, 'GzipFile', Observed)
    assert read(raw, max_expanded=size).records == (record(),)
    assert max(reads) <= 1024 * 1024 and min(reads) >= 1
    with pytest.raises(history_s3.HistorySourceGap, match='^expanded_object_too_large$'):
        read(raw, max_expanded=size - 1)


def test_single_member_uses_bounded_decoder_without_buffered_reader(monkeypatch):
    payload = json.dumps({'Records': [record()]})
    raw = gzip.compress(payload.encode(), mtime=0)

    def unexpected(*args, **kwargs):
        pytest.fail('Ordinary single-member gzip should avoid the buffered reader')

    monkeypatch.setattr(gzip, 'GzipFile', unexpected)
    assert read(raw).records == (record(),)
    with pytest.raises(history_s3.HistorySourceGap, match='^expanded_object_too_large$'):
        read(raw, max_expanded=len(payload) - 1)


@pytest.mark.parametrize('mode', ['header-crc', 'reserved-header-flag'])
def test_unusual_header_keeps_standard_library_acceptance(mode):
    payload = json.dumps({'Records': [record()]}).encode()
    raw = gzip.compress(payload, mtime=0)
    if mode == 'header-crc':
        # GzipFile ignores FHCRC; zlib checks it. Its error must fall back to
        # the authoritative parser rather than rejecting an existing input.
        raw = raw[:3] + b'\x02' + raw[4:10] + b'\x00\x00' + raw[10:]
    else:
        raw = raw[:3] + b'\x20' + raw[4:]
    assert gzip.decompress(raw) == payload
    assert read(raw).records == (record(),)


@pytest.mark.parametrize('encoding', ['utf-8', 'utf-8-sig', 'utf-16', 'utf-16-le', 'utf-32'])
def test_json_encoding_duplicate_keys_and_multimember_gzip(encoding):
    # Last duplicate key wins, as in the existing json.loads(bytes) parser.
    expected = record() | {'detail': 'café λ', 'number': 1.25}
    value = '{"Records": [], "Records": [' + json.dumps(expected, ensure_ascii=False) + ']}'
    payload = value.encode(encoding)
    middle = len(payload) // 2
    raw = gzip.compress(payload[:middle], mtime=0) + gzip.compress(payload[middle:], mtime=0)
    assert read(raw).records == (expected,)
    assert read(raw + b'\0' * 10).records == (expected,)


@pytest.mark.parametrize('size', [1000, 65536, 140000, 1400000])
@pytest.mark.parametrize('damage', ['crc', 'truncated', 'trailing', 'json', 'size-low', 'size-high'])
def test_entire_object_rejected_after_valid_record_on_corrupt_tail(size, damage):
    value = json.dumps({'Records': [record()]}) + ' ' * size
    if damage == 'json':
        value += 'invalid trailing json'
    raw = gzip.compress(value.encode(), mtime=0)
    if damage == 'crc':
        raw = raw[:-8] + bytes([raw[-8] ^ 1]) + raw[-7:]
    elif damage == 'truncated':
        raw = raw[:-3]
    elif damage == 'trailing':
        raw += b'invalid gzip trailer'
    elif damage in {'size-low', 'size-high'}:
        raw = raw[:-4] + (0 if damage == 'size-low' else 0xffffffff).to_bytes(4, 'little')
    with pytest.raises(history_s3.HistorySourceGap, match='^invalid_cloudtrail_object$'):
        read(raw)


def test_small_last_member_and_zero_padding_cannot_truncate_expansion():
    payload = (json.dumps({'Records': [record()]}) + ' ' * 1400000).encode()
    raw = gzip.compress(payload[:-10], mtime=0) + gzip.compress(payload[-10:], mtime=0)
    assert read(raw).records == (record(),)
    assert read(raw + b'\0' * 32).records == (record(),)
    with pytest.raises(history_s3.HistorySourceGap, match='^expanded_object_too_large$'):
        read(raw, max_expanded=len(payload) - 1)


@pytest.mark.parametrize('mode', ['valid', 'too-large', 'corrupt'])
def test_interactive_preview_preserves_event_coverage_limits_and_errors(mode, monkeypatch):
    import io
    from peaso.server import attack_logs

    payload = json.dumps({'Records': [record()]}) + ' ' * 140000
    raw = gzip.compress(payload.encode(), mtime=0)
    if mode == 'corrupt':
        raw += b'invalid gzip trailer'
    bodies = []

    class Client:
        def list_objects_v2(self, **request):
            return {'Contents': [{'Key': 'logs.json.gz', 'Size': len(raw)}]}

        def get_object(self, **request):
            body = io.BytesIO(raw)
            bodies.append(body)
            return {'Body': body}

    session = SimpleNamespace(client=lambda *args, **kwargs: Client())
    monkeypatch.setattr(attack_logs, '_target_session', lambda *args: (session, '123456789012'))
    source = SimpleNamespace(kind='aws_cloudtrail_s3', region='us-east-1', role_arn=None,
        bucket='audit', prefix='AWSLogs/123456789012/CloudTrail/', day='2020-01-01')
    if mode == 'valid':
        value = attack_logs.analyze_aws_source({}, {}, source, rules=[])
        assert value['coverage']['events_read'] == 1
        assert value['coverage']['objects_read'] == 1
        assert not value['coverage']['truncated']
    else:
        if mode == 'too-large':
            monkeypatch.setattr(attack_logs, 'MAX_UNCOMPRESSED_OBJECT_BYTES', len(payload) - 1)
        code = 'decompressed_object_too_large' if mode == 'too-large' else 'malformed_cloudtrail_object'
        with pytest.raises(attack_logs.LogAccessError, match='^' + code + '$'):
            attack_logs.analyze_aws_source({}, {}, source, rules=[])
    assert bodies and all(body.closed for body in bodies)
