"""GCP page preparation preserves bounded per-message evidence and failures."""
from datetime import datetime, timedelta, timezone
import json
import time
from types import SimpleNamespace

import pytest
from peaso import secret_evidence as evidence
from peaso import secret_scanning as scanning, secret_scanning_batch as batch
from peaso.collectors import gcp_log_secret_indicators as logs


PRIMARY = 'synthetic-primary'
FULL = PRIMARY + ':' + 'A'*40
SCOPE = 'projects/offline-project'
LAST = datetime(2026, 10, 22, tzinfo=timezone.utc)


def page(count=50):
    rows = []
    for i in range(count):
        row = dict(logName=SCOPE+'/logs/application', timestamp=LAST.isoformat(),
                   insertId=f'event-{i}', resource={'type': 'global',
                   'labels': {'project_id': 'offline-project'}})
        row['textPayload' if i % 2 else 'jsonPayload'] = (
            f'event={i} value={FULL}' if i % 2 else {'event': i, 'value': FULL})
        rows.append(row)
    return {'entries': rows, 'nextPageToken': 'opaque-cursor'}


def project(data, **options):
    return logs.project_page(data, scope=SCOPE, first=LAST-timedelta(minutes=30), last=LAST,
        page_size=50, page_number=1, check_cancelled=options.pop('check_cancelled', lambda: None),
        **options)


@pytest.fixture
def detectors(monkeypatch):
    calls = {'prepared': [], 'serial': []}

    def output(payload):
        return json.dumps(dict(Raw=PRIMARY, RawV2=FULL, Verified=False, DetectorName='AWS')).encode()

    def prepare(items, timeout):
        calls['prepared'].append((items, timeout))
        return {item: output(item[0]) for item in items}

    def serial(argv, payload, timeout):
        calls['serial'].append(payload)
        return output(payload)

    monkeypatch.setattr(batch, '_prepare_trufflehog_batch', prepare)
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic')
    monkeypatch.setattr(scanning, '_run', serial)
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [(PRIMARY, 'synthetic', 1)])
    scanning._RESULTS.clear()
    yield calls
    scanning._RESULTS.clear()


@pytest.mark.parametrize('batch_failure', [False, True])
def test_fifty_messages_keep_native_order_and_full_private_sources(monkeypatch, detectors, batch_failure):
    if batch_failure:
        original = batch._prepare_trufflehog_batch

        def failed(items, timeout):
            original(items, timeout)
            raise RuntimeError('synthetic preparation failure')

        monkeypatch.setattr(batch, '_prepare_trufflehog_batch', failed)
    cipher = evidence.EphemeralCipher()
    with evidence.capture(cipher, tenant='offline', scan_id='a'*32) as sink:
        result, cursor = project(page())
        for value in (PRIMARY, FULL):
            record = cipher.decrypt(sink.records[scanning._fingerprint(value)])
            assert {json.loads(loc['source'])['insertId'] for loc in record['locations']} == {
                f'event-{i}' for i in range(50)}
            assert all(loc['resource_id'] == SCOPE+'/logs/application'
                       and loc['scope'] == SCOPE
                       and json.loads(loc['source'])['timestamp'] == LAST.isoformat()
                       for loc in record['locations'])
        assert not sink.incomplete
    assert cursor == 'opaque-cursor' and result['entries'] == 50 and result['complete']
    assert [len(items) for items, timeout in detectors['prepared']] == [50]
    assert 0 < detectors['prepared'][0][1] <= 10
    assert len(detectors['serial']) == (50 if batch_failure else 0)
    assert [row['path'] for row in result['scans']] == [
        f'page/1/message/{i+1}/'+('textPayload' if i % 2 else 'jsonPayload') for i in range(50)]
    assert all(row['complete'] for row in result['scans'])
    assert PRIMARY not in json.dumps(result) and FULL not in json.dumps(result)
    assert batch._PREPARED_BATCH.get() is None


@pytest.mark.parametrize('invalid', ['foreign', 'split', 'oversize', 'sample_budget'])
def test_invalid_page_never_enters_detector_preparation(detectors, invalid):
    value = page(2)
    options = {}
    if invalid == 'foreign':
        value['entries'][1]['logName'] = 'projects/foreign/logs/application'
    elif invalid == 'split':
        value['entries'][1]['split'] = {'uid': 'unreassembled'}
    elif invalid == 'oversize':
        value['entries'][1]['textPayload'] = 'x'*(logs.MAX_MESSAGE_BYTES+1)
    else:
        options['remaining_bytes'] = 1
    result, _ = project(value, **options)
    assert not result['complete'] and not result['scans'] and not result['leaks']
    assert not detectors['prepared'] and not detectors['serial']


@pytest.mark.parametrize('stopped', ['cancelled', 'expired'])
def test_stopped_page_never_prepares(detectors, stopped):
    options = {'deadline': time.monotonic()-1} if stopped == 'expired' else {
        'check_cancelled': lambda: (_ for _ in ()).throw(RuntimeError('cancelled'))}
    result, _ = project(page(2), **options)
    assert not result['complete'] and not result['scans']
    assert not detectors['prepared'] and not detectors['serial']


def test_deadline_after_preparation_is_not_reported_complete(monkeypatch, detectors):
    clock = [100.0]
    monkeypatch.setattr(logs, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    original = batch._prepare_trufflehog_batch

    def prepare(items, timeout):
        assert timeout == 4
        value = original(items, timeout)
        clock[0] = 109
        return value

    monkeypatch.setattr(batch, '_prepare_trufflehog_batch', prepare)
    result, _ = project(page(2), deadline=108)
    assert not result['complete'] and not result['scans']
    assert batch._PREPARED_BATCH.get() is None


def test_unavailable_engine_stays_incomplete_and_keeps_positive(detectors, monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a:
                        (_ for _ in ()).throw(RuntimeError('synthetic unavailable')))
    result, _ = project(page(2))
    assert not result['complete'] and len(result['scans']) == 2 and result['leaks']
    assert all(not row['complete'] for row in result['scans'])
    assert all(row['engines'][0]['status'] == 'unavailable' for row in result['scans'])


@pytest.mark.parametrize('count', [0, 1])
def test_empty_and_single_messages_keep_serial_negative_semantics(detectors, monkeypatch, count):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_run', lambda *a: b'')
    result, cursor = project(page(count))
    assert result['complete'] and result['entries'] == count and not result['leaks']
    assert cursor == 'opaque-cursor' and len(result['scans']) == 1
    assert not detectors['prepared']
    if not count:
        assert result['bytes'] == 0 and result['scans'][0]['path'] == 'page/1/empty'
    assert batch._PREPARED_BATCH.get() is None
