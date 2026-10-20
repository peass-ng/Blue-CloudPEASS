"""Native Composer and task partial-positive acceptance tests."""
import json
from copy import deepcopy
import pytest
import composer_task_positive_helper as r

@pytest.mark.parametrize('runner', [r.run_composer,
    lambda: r.run_task(r.task.source.TASK_KIND),
    lambda: r.run_task(r.task.source.ROUTINE_KIND)])
def test_incomplete_engine_keeps_bound_positive(runner):
    result = runner()
    assert result['complete'] is False
    assert result['leak_count'] == 1
    assert result['verdict'] == 'FAIL'
    assert not result['raw_secret_retained']


def test_composer_later_native_denial_preserves_earlier_positive():
    patch = pytest.MonkeyPatch()
    r.scan._RESULTS.clear()
    patch.setattr(r.scan, '_scan_kingfisher', r.found)
    patch.setattr(r.scan, '_scan_trufflehog', lambda *a, **k: [])
    payload = ('token=' + r.composer.TOKEN + '\n').encode()
    first = r.composer.metadata(payload)
    second = r.composer.metadata(b'other\n', name='dags/second.py')
    replies = [r.composer.Response({'items': [first, second]}),
        r.composer.Response(first),
        r.composer.Response(raw=payload, headers={'Content-Type': 'text/x-python', 'x-goog-generation': '12345'}),
        r.composer.Response({'error': 'denied'}, status=403)]
    try:
        c, _, responses, _ = r.composer.fixture(patch, payload=payload, replies=replies)
        row, ix, _ = r.composer.produce(c)
        m = row[r.composer.adapter.MARKER]
        verdict, evidence = r.composer.check.evaluate(row, ix)
        assert m['complete'] is False and m['reason'] == 'denied'
        assert len(m['leaks']) == 1 and len(m['files']) == 1
        assert verdict == 'FAIL' and len(evidence['secret_leaks']) == 1
        assert all(x.closed for x in replies)
        assert r.composer.TOKEN not in json.dumps([row, ix, c.transport.evidence, evidence])
        # Neither a foreign file identity nor an unsuccessful media receipt can
        # become the provenance of the retained positive.
        tampered = deepcopy(row)
        tampered[r.composer.adapter.MARKER]['files'] = ['gcs-selected-object:' + '0' * 64]
        assert r.composer.check.evaluate(tampered, ix)[0] == 'UNKNOWN'
        tampered = deepcopy(row)
        tampered[r.composer.adapter.MARKER]['read_receipts'][2]['status'] = 'unavailable'
        assert r.composer.check.evaluate(tampered, ix)[0] == 'UNKNOWN'
    finally:
        patch.undo()
        r.scan._RESULTS.clear()


def test_composer_later_generation_metadata_mismatch_excludes_that_file():
    patch = pytest.MonkeyPatch()
    r.scan._RESULTS.clear()
    patch.setattr(r.scan, '_scan_kingfisher', r.found)
    patch.setattr(r.scan, '_scan_trufflehog', lambda *a, **k: [])
    payload = ('token=' + r.composer.TOKEN + '\n').encode()
    first = r.composer.metadata(payload)
    second = r.composer.metadata(payload, name='dags/second.py')
    replies = [r.composer.Response({'items': [first, second]}),
        r.composer.Response(first),
        r.composer.Response(raw=payload, headers={'Content-Type': 'text/x-python', 'x-goog-generation': '12345'}),
        r.composer.Response({**second, 'size': '999'})]
    try:
        c, _, _, _ = r.composer.fixture(patch, payload=payload, replies=replies)
        row, ix, _ = r.composer.produce(c)
        m = row[r.composer.adapter.MARKER]
        verdict, evidence = r.composer.check.evaluate(row, ix)
        assert m['reason'] == 'metadata_changed'
        assert len(m['files']) == 1 and len(m['leaks']) == 1
        assert verdict == 'FAIL' and len(evidence['secret_leaks'][0]['locations']) == 1
        assert r.composer.TOKEN not in json.dumps([row, ix, evidence])
    finally:
        patch.undo()
        r.scan._RESULTS.clear()


def test_task_later_header_engine_failure_keeps_body_positive():
    patch = pytest.MonkeyPatch()
    r.scan._RESULTS.clear()
    patch.setattr(r.scan, '_scan_kingfisher', r.found)
    def second_engine(raw, path, timeout):
        if path.endswith('.headers'):
            raise RuntimeError('synthetic header engine failure')
        return []
    patch.setattr(r.scan, '_scan_trufflehog', second_engine)
    try:
        kind = r.task.source.TASK_KIND
        snapshot, trace = r.task.capture(patch, kind,
            data=r.task.native(kind, ('token=' + r.task.TOKEN + '\n').encode()), mocked=False)
        item, ix = r.task.index_of(snapshot, kind)
        m = item[r.task.source.MARKER]
        verdict, evidence = r.task.checks.evaluate(item, ix, kind=kind)
        assert m['complete'] is False and m['reason'] == 'detector_unavailable'
        assert [p['complete'] for p in m['parts']] == [True, False]
        assert verdict == 'FAIL' and len(evidence['secret_leaks']) == 1
        assert r.task.TOKEN not in json.dumps([snapshot, evidence])
        bad = deepcopy(item)
        bad[r.task.source.MARKER]['read_receipts'][0]['resource_id'] = 'foreign'
        assert r.task.checks.evaluate(bad, ix, kind=kind)[0] == 'UNKNOWN'
        bad = deepcopy(item)
        bad[r.task.source.MARKER]['leaks'][0]['locations'][0]['path'] = 'foreign'
        assert r.task.checks.evaluate(bad, ix, kind=kind)[0] == 'UNKNOWN'
    finally:
        patch.undo()
        r.scan._RESULTS.clear()

@pytest.mark.parametrize('kind', [r.task.source.TASK_KIND, r.task.source.ROUTINE_KIND])
def test_complete_clean_and_native_denial_remain_safe(kind):
    patch = pytest.MonkeyPatch()
    r.scan._RESULTS.clear()
    patch.setattr(r.scan, '_scan_kingfisher', lambda *a, **k: [])
    patch.setattr(r.scan, '_scan_trufflehog', lambda *a, **k: [])
    try:
        snapshot, _ = r.task.capture(patch, kind, data=r.task.native(kind), mocked=False)
        item, ix = r.task.index_of(snapshot, kind)
        assert r.task.checks.evaluate(item, ix, kind=kind)[0] == 'PASS'
        denied, _ = r.task.capture(patch, kind, response=r.task.Response({'error':'no'}, 403), mocked=False)
        item, ix = r.task.index_of(denied, kind)
        assert r.task.checks.evaluate(item, ix, kind=kind)[0] == 'UNKNOWN'
    finally:
        patch.undo()
        r.scan._RESULTS.clear()


def test_composer_complete_clean_and_native_denial_remain_safe():
    patch = pytest.MonkeyPatch()
    r.scan._RESULTS.clear()
    patch.setattr(r.scan, '_scan_kingfisher', lambda *a, **k: [])
    patch.setattr(r.scan, '_scan_trufflehog', lambda *a, **k: [])
    try:
        c, _, _, _ = r.composer.fixture(patch)
        row, ix, _ = r.composer.produce(c)
        assert r.composer.check.evaluate(row, ix)[0] == 'PASS'
        c, _, _, _ = r.composer.fixture(patch, replies=[r.composer.Response({}, status=403)])
        row, ix, _ = r.composer.produce(c)
        assert r.composer.check.evaluate(row, ix)[0] == 'UNKNOWN'
    finally:
        patch.undo()
        r.scan._RESULTS.clear()


def test_same_fingerprint_merges_across_two_bound_composer_files():
    patch = pytest.MonkeyPatch()
    r.scan._RESULTS.clear()
    patch.setattr(r.scan, '_scan_kingfisher', r.found)
    patch.setattr(r.scan, '_scan_trufflehog', lambda *a, **k: [])
    payload = ('token=' + r.composer.TOKEN + '\n').encode()
    first = r.composer.metadata(payload)
    second = r.composer.metadata(payload, name='dags/second.py')
    replies = [r.composer.Response({'items': [first, second]}),
        r.composer.Response(first),
        r.composer.Response(raw=payload, headers={'Content-Type': 'text/x-python', 'x-goog-generation': '12345'}),
        r.composer.Response(second),
        r.composer.Response(raw=payload, headers={'Content-Type': 'text/x-python', 'x-goog-generation': '12345'})]
    try:
        c, _, _, _ = r.composer.fixture(patch, payload=payload, replies=replies)
        row, ix, _ = r.composer.produce(c)
        verdict, evidence = r.composer.check.evaluate(row, ix)
        assert verdict == 'FAIL'
        assert len(evidence['secret_leaks']) == 1
        assert len(evidence['secret_leaks'][0]['locations']) == 2
        assert r.composer.TOKEN not in json.dumps([row, ix, evidence])
    finally:
        patch.undo()
        r.scan._RESULTS.clear()


@pytest.mark.parametrize('kind', [r.task.source.TASK_KIND, r.task.source.ROUTINE_KIND])
def test_incomplete_negative_stays_unknown(kind):
    patch = pytest.MonkeyPatch()
    r.scan._RESULTS.clear()
    patch.setattr(r.scan, '_scan_kingfisher', lambda *a, **k: [])
    patch.setattr(r.scan, '_scan_trufflehog', r.unavailable)
    try:
        snapshot, _ = r.task.capture(patch, kind, data=r.task.native(kind), mocked=False)
        item, ix = r.task.index_of(snapshot, kind)
        assert item[r.task.source.MARKER]['leaks'] == []
        assert r.task.checks.evaluate(item, ix, kind=kind)[0] == 'UNKNOWN'
    finally:
        patch.undo()
        r.scan._RESULTS.clear()


def test_incomplete_composer_negative_stays_unknown():
    patch = pytest.MonkeyPatch()
    r.scan._RESULTS.clear()
    patch.setattr(r.scan, '_scan_kingfisher', lambda *a, **k: [])
    patch.setattr(r.scan, '_scan_trufflehog', r.unavailable)
    try:
        c, _, _, _ = r.composer.fixture(patch)
        row, ix, _ = r.composer.produce(c)
        assert row[r.composer.adapter.MARKER]['leaks'] == []
        assert r.composer.check.evaluate(row, ix)[0] == 'UNKNOWN'
    finally:
        patch.undo()
        r.scan._RESULTS.clear()
