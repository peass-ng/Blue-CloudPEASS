import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import peaso

from peaso.collectors import gcp
from peaso import secret_scanning as scanning
from peaso.collectors import gcp_cloudbuild_logging_entries as reader
from peaso.collectors import gcp_cloudbuild_log_secret_indicators as producer
from peaso.checks import gcp_cloudbuild_log_secret_review_20261019 as consumer
import test_gcp_cloudbuild_log_secret_review_20261019 as old

def sample(monkeypatch, *, rows=None, after=None, statuses=None, options=None, pages=None):
    c, _, _, _, _ = old.fixture(monkeypatch, options=options, mock_engines=False)
    b = old.build()
    b.pop('logsBucket')
    b['options'] = {'logging': 'CLOUD_LOGGING_ONLY'}
    rows = [{'logName': 'projects/review/logs/cloudbuild', 'resource': {'type': 'build', 'labels': {
        'project_id': 'review', 'build_id': b['id'], 'build_trigger_id': ''}},
        'timestamp': '2026-10-19T10:00:02Z', 'textPayload': 'build completed\n'}] if rows is None else rows
    responses = [old.Response(b)] + [old.Response(page) for page in (pages if pages is not None else [{'entries': rows}])] + [old.Response(after if after is not None else b)]
    if statuses:
        for i, status in statuses.items():
            responses[i].status_code = status
    c._logging_test_responses = list(responses)
    calls = []
    def request(method, url, **kw):
        calls.append((method, url, kw))
        assert kw['stream'] is True and kw['allow_redirects'] is False
        assert kw['headers']['Accept-Encoding'] == 'identity'
        assert 'fake-transport-canary' in kw['headers']['Authorization']
        response = responses.pop(0)
        response.json = lambda: pytest.fail('cached JSON path')
        return response
    monkeypatch.setattr(c.transport, '_session', lambda: SimpleNamespace(request=request, auth=None))
    return c, calls, responses


def run(c):
    kind, scope, service, fetch = producer.jobs(c, old.SCOPE)[0]
    env = c.envelope(kind, scope, service, fetch)
    row, = env['items']
    index = {'context': {'provider': 'gcp', 'scope': old.SCOPE, 'metadata': producer.selection_metadata(c)},
        'collections': {kind: [env], 'project': [c.collections[('project', old.SCOPE)]],
                        'bucket': [c.collections[('bucket', old.SCOPE)]]}}
    return row, index, consumer.evaluate(row, index)


def test_clean_pipeline(monkeypatch):
    c, calls, pending = sample(monkeypatch)
    row, index, (status, evidence) = run(c)
    assert status == 'PASS', row
    assert evidence['coverage'] == 'selected_build_logging_window_only'
    assert len(calls) == 3 and not pending
    assert [x[0] for x in calls] == ['GET', 'POST', 'GET']
    assert calls[1][1] == reader.ENDPOINT
    body = json.loads(calls[1][2]['data'])
    assert body['resourceNames'] == ['projects/review']
    assert 'resource.labels.build_id="' + old.NAME.split('/')[-1] + '"' in body['filter']
    assert body['pageSize'] == reader.PAGE_SIZE
    assert 'build completed' not in json.dumps([row, index, evidence, c.transport.evidence])
    assert 'build completed' not in repr(c.transport.cache)


def test_real_dual_positive(monkeypatch):
    row = {'logName': 'projects/review/logs/cloudbuild', 'resource': {'type': 'build', 'labels': {
        'project_id': 'review', 'build_id': old.NAME.split('/')[-1], 'build_trigger_id': ''}},
        'timestamp': '2026-10-19T10:00:02Z', 'textPayload': 'token="' + old.TOKEN + '"\n'}
    c, _, _ = sample(monkeypatch, rows=[row])
    item, index, (status, evidence) = run(c)
    assert status == 'FAIL', item
    assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert old.TOKEN not in json.dumps([item, index, evidence, c.transport.evidence]) + repr(c.transport.cache)
    assert old.TOKEN not in repr(scanning._RESULTS)


@pytest.mark.parametrize('which', ['empty', 'foreign', 'denied', 'drift', 'cancel', 'deadline', 'oversize'])
def test_unknown_pipeline(monkeypatch, which):
    c, calls, pending = sample(monkeypatch, rows=[] if which == 'empty' else None,
        statuses={1: 403} if which == 'denied' else None,
        after={**old.build(), 'options': {'logging': 'CLOUD_LOGGING_ONLY'}, 'status': 'FAILURE', 'logsBucket': None} if which == 'drift' else None)
    if which == 'foreign':
        pending[1] = old.Response({'entries': [{'logName': 'projects/foreign/logs/cloudbuild',
            'resource': {'type':'build', 'labels': {'project_id':'foreign', 'build_id':'other'}},
            'timestamp':'2026-10-19T10:00:02Z','textPayload':'x'}]})
        c._logging_test_responses[1] = pending[1]
    if which == 'cancel':
        monkeypatch.setattr(c.transport, 'check_cancelled', lambda: (_ for _ in ()).throw(RuntimeError('stop')))
    if which == 'deadline':
        c.transport.deadline = 1
    if which == 'oversize':
        pending[1] = old.Response(raw=b' ' * (reader.MAX_RESPONSE_BYTES + 1))
        c._logging_test_responses[1] = pending[1]
    row, index, (status, _) = run(c)
    assert status == 'UNKNOWN'
    assert row[producer.MARKER]['complete'] is False
    assert all(r.closed for r in c._logging_test_responses if r not in pending)
    assert old.TOKEN not in json.dumps([row, index, c.transport.evidence])


def test_consumer_receipt_tamper(monkeypatch):
    c, _, _ = sample(monkeypatch)
    row, index, (status, _) = run(c)
    assert status == 'PASS'
    for mutate in (
        lambda x: x[producer.MARKER]['read_receipts'][1].update(method='GET'),
        lambda x: x[producer.MARKER]['logging'].update(pages=2),
        lambda x: x[producer.MARKER]['logging'].update(filter_sha256='0'*64),
        lambda x: x[producer.MARKER]['logging'].update(entries=0),
    ):
        import copy
        altered = copy.deepcopy(row)
        mutate(altered)
        index['collections'][producer.KIND][0]['items'] = [altered]
        assert consumer.evaluate(altered, index)[0] == 'UNKNOWN'


def test_paginated_complete_and_receipts(monkeypatch):
    entry = {'logName': 'projects/review/logs/cloudbuild', 'resource': {'type': 'build', 'labels': {
        'project_id': 'review', 'build_id': old.NAME.split('/')[-1], 'build_trigger_id': ''}},
        'timestamp': '2026-10-19T10:00:02Z', 'textPayload': 'page one\n'}
    c, calls, pending = sample(monkeypatch, pages=[{'entries': [entry], 'nextPageToken': 'opaque-next'},
        {'entries': [{**entry, 'textPayload': 'page two\n'}]}])
    row, index, (status, evidence) = run(c)
    assert status == 'PASS' and evidence['entries'] == 2
    assert [method for method, _, _ in calls] == ['GET', 'POST', 'POST', 'GET']
    first, second = (json.loads(calls[i][2]['data']) for i in (1, 2))
    assert first['filter'] == second['filter'] and first['resourceNames'] == second['resourceNames']
    assert second['pageToken'] == 'opaque-next' and 'pageToken' not in first
    assert len(row[producer.MARKER]['read_receipts']) == 4
    assert not pending


def test_page_limit_never_clean(monkeypatch):
    c, calls, _ = sample(monkeypatch, pages=[{'entries': [], 'nextPageToken': str(i)} for i in range(3)])
    row, index, (status, _) = run(c)
    assert status == 'UNKNOWN'
    assert len(calls) == 4


def test_filter_injection_selection_rejected_before_credentials(monkeypatch):
    bad = old.NAME + '" OR logName=projects/other/logs/cloudbuild'
    with pytest.raises(ValueError, match='bounded exact same-project'):
        sample(monkeypatch, options={producer.OPTION: [bad]})
    assert producer.BUILD_NAME.fullmatch(bad) is None


@pytest.mark.parametrize('case', ['empty_text', 'future_timestamp', 'repeated_token', 'malformed_json'])
def test_content_and_page_shape_unknown(monkeypatch, case):
    entry = {'logName': 'projects/review/logs/cloudbuild', 'resource': {'type': 'build', 'labels': {
        'project_id': 'review', 'build_id': old.NAME.split('/')[-1], 'build_trigger_id': ''}},
        'timestamp': '2026-10-19T10:00:02Z', 'textPayload': 'okay\n'}
    if case == 'empty_text':
        entry['textPayload'] = ''
    if case == 'future_timestamp':
        entry['timestamp'] = '2026-10-19T10:05:05.1Z'
    pages = [{'entries': [entry]}]
    if case == 'repeated_token':
        pages = [{'entries': [entry], 'nextPageToken': 'same'}, {'entries': [], 'nextPageToken': 'same'}]
    c, _, pending = sample(monkeypatch, pages=pages)
    if case == 'malformed_json':
        c._logging_test_responses[1].stream = __import__('io').BytesIO(b'{bad')
        c._logging_test_responses[1].headers['Content-Length'] = '4'
    row, index, (status, _) = run(c)
    assert status == 'UNKNOWN' and row[producer.MARKER]['complete'] is False
    assert all(r.closed for r in c._logging_test_responses if r not in pending)


def secret_entry(labels=None):
    return {'logName': 'projects/review/logs/cloudbuild', 'resource': {'type': 'build',
            'labels': {'project_id': 'review', 'build_id': old.NAME.split('/')[-1],
                       **({'build_trigger_id': ''} if labels is None else labels)}},
            'timestamp': '2026-10-19T10:00:02Z', 'textPayload': 'token="' + old.TOKEN + '"\n'}


@pytest.mark.parametrize('label', [None, '', 'trigger-123'])
def test_optional_trigger_label(monkeypatch, label):
    labels = {} if label is None else {'build_trigger_id': label}
    c, _, _ = sample(monkeypatch, rows=[secret_entry(labels)])
    row, index, (status, evidence) = run(c)
    assert status == 'FAIL' and evidence['complete'] is True
    assert old.TOKEN not in json.dumps([row, index, evidence, c.transport.evidence])


@pytest.mark.parametrize('labels', [
    {'build_trigger_id': 10}, {'foreign': 'x'}, {'project_id': 'foreign'}, {'build_id': 'other'}])
def test_foreign_or_malformed_resource_labels(monkeypatch, labels):
    c, _, _ = sample(monkeypatch, rows=[secret_entry(labels)])
    row, index, (status, _) = run(c)
    assert status == 'UNKNOWN' and row[producer.MARKER]['complete'] is False


@pytest.mark.parametrize('failure', ['denied', 'truncated', 'timeout', 'postread_denied'])
def test_positive_partial_after_later_failure(monkeypatch, failure):
    first = {'entries': [secret_entry()], 'nextPageToken': 'next'}
    pages = [first, {'entries': []}] if failure != 'postread_denied' else [{'entries': [secret_entry()]}]
    statuses = {2: 403} if failure == 'denied' else {2: 403} if failure == 'postread_denied' else None
    c, calls, pending = sample(monkeypatch, pages=pages, statuses=statuses)
    if failure == 'truncated':
        pending[2] = old.Response(raw=b'{"entries":[]')
        pending[2].headers['Content-Length'] = str(len(pending[2].payload) + 4)
        c._logging_test_responses[2] = pending[2]
    if failure == 'timeout':
        native_request = c.transport._session().request
        def request(method, url, **kw):
            if method == 'POST' and len([x for x in calls if x[0] == 'POST']) == 1:
                c.transport.deadline = 1
            return native_request(method, url, **kw)
        monkeypatch.setattr(c.transport, '_session', lambda: SimpleNamespace(request=request, auth=None))
    row, index, (status, evidence) = run(c)
    assert status == 'FAIL', row
    assert evidence['complete'] is False and evidence['coverage'] == 'observed_selected_build_entries_partial'
    assert evidence['entries'] == 1 and evidence['secret_leaks']
    assert old.TOKEN not in json.dumps([row, index, evidence, c.transport.evidence]) + repr(c.transport.cache)
    assert row[producer.MARKER]['reason'] != 'complete'
    assert all(r.closed for r in c._logging_test_responses if r not in pending)


def test_second_detector_failure_preserves_confirmed_positive(monkeypatch):
    scanning._RESULTS.clear()
    c, _, _ = sample(monkeypatch, rows=[secret_entry()])
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda payload, path, timeout: [(old.TOKEN, 'github-token', 1)])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: (_ for _ in ()).throw(RuntimeError('offline failure')))
    row, index, (status, evidence) = run(c)
    assert status == 'FAIL', row
    assert evidence['complete'] is False
    assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']} == {'kingfisher'}
    assert {e['engine']: e['status'] for e in evidence['engines']} == {'kingfisher': 'complete', 'trufflehog': 'unavailable'}
    assert old.TOKEN not in json.dumps([row, index, evidence, c.transport.evidence])


def test_foreign_second_page_discards_earlier_positive(monkeypatch):
    foreign = secret_entry({'project_id': 'foreign'})
    c, _, _ = sample(monkeypatch, pages=[{'entries': [secret_entry()], 'nextPageToken': 'next'}, {'entries': [foreign]}])
    row, index, (status, _) = run(c)
    assert status == 'UNKNOWN' and row[producer.MARKER]['complete'] is False
    assert not row[producer.MARKER].get('logging')


def test_clean_truncated_page_remains_unknown(monkeypatch):
    clean = secret_entry()
    clean['textPayload'] = 'normal build output\n'
    c, _, pending = sample(monkeypatch, pages=[{'entries': [clean], 'nextPageToken': 'next'}, {'entries': []}])
    pending[2] = old.Response(raw=b'{"entries":[]')
    pending[2].headers['Content-Length'] = str(len(pending[2].payload) + 4)
    row, index, (status, _) = run(c)
    assert status == 'UNKNOWN' and row[producer.MARKER]['complete'] is False


def test_partial_receipt_tamper_unknown(monkeypatch):
    c, _, _ = sample(monkeypatch, pages=[{'entries': [secret_entry()], 'nextPageToken': 'next'}, {'entries': []}], statuses={2: 403})
    row, index, (status, _) = run(c)
    assert status == 'FAIL'
    import copy
    for mutation in ('native', 'first_page', 'failed_page', 'leaks', 'window'):
        bad = copy.deepcopy(row)
        marker = bad[producer.MARKER]
        if mutation == 'native':
            marker['native_requests'] = []
        elif mutation == 'first_page':
            marker['read_receipts'][1]['resource_id'] = 'foreign'
        elif mutation == 'failed_page':
            marker['read_receipts'][-1]['method'] = 'GET'
        elif mutation == 'leaks':
            marker['logging']['leaks'] = []
        else:
            marker['logging']['window_start'] = '2026-01-01T00:00:00Z'
        index['collections'][producer.KIND][0]['items'] = [bad]
        assert consumer.evaluate(bad, index)[0] == 'UNKNOWN'


def test_later_detector_failure_keeps_earlier_dual_leak(monkeypatch):
    scanning._RESULTS.clear()
    pages = [{'entries': [secret_entry(), {**secret_entry(), 'textPayload': 'another entry\n'}]}]
    c, _, _ = sample(monkeypatch, pages=pages)
    counts = {'trufflehog': 0}
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda payload, path, timeout:
        [(old.TOKEN, 'github-token', 1)] if old.TOKEN.encode() in payload else [])
    def hog(payload, path, timeout):
        counts['trufflehog'] += 1
        if counts['trufflehog'] == 2:
            raise RuntimeError('offline failure')
        return [(old.TOKEN, 'Github', 1)]
    monkeypatch.setattr(scanning, '_scan_trufflehog', hog)
    row, index, (status, evidence) = run(c)
    assert status == 'FAIL' and evidence['complete'] is False
    assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert old.TOKEN not in json.dumps([row, index, evidence])


def test_partial_failed_receipt_reason_tamper_unknown(monkeypatch):
    c, _, _ = sample(monkeypatch, pages=[{'entries': [secret_entry()], 'nextPageToken': 'next'}, {'entries': []}], statuses={2: 403})
    row, index, (status, _) = run(c)
    assert status == 'FAIL'
    import copy
    for tweak in ('http_status', 'reason', 'missing'):
        bad = copy.deepcopy(row)
        marker = bad[producer.MARKER]
        if tweak == 'http_status':
            marker['read_receipts'][-1]['http_status'] = 500
        elif tweak == 'reason':
            marker['reason'] = marker['logging']['reason'] = 'detector_unavailable'
        else:
            marker['read_receipts'].pop()
            marker['source_requests'].pop()
        index['collections'][producer.KIND][0]['items'] = [bad]
        assert consumer.evaluate(bad, index)[0] == 'UNKNOWN'
