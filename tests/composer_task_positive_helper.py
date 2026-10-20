"""Real Composer and task modules with existing native fixture builders."""
import json
import pytest
from portable_fixture import load_fixture
from peaso import secret_scanning as scan

composer = load_fixture("test_gcp_composer_source_secret_review_20261019.py")
task = load_fixture("test_gcp_task_routine_secret_review_20261020.py")

# Kingfisher identifies a synthetic token; the second local engine fails. The
# shared scanner returns a redacted fingerprint even though complete is False.
def found(raw, path, timeout):
    return [(task.TOKEN, 'synthetic-github', 1)] if task.TOKEN.encode() in raw else []
def unavailable(raw, path, timeout):
    raise RuntimeError('synthetic offline engine unavailable')

def run_composer():
    patch = pytest.MonkeyPatch()
    scan._RESULTS.clear()
    patch.setattr(scan, '_scan_kingfisher', found)
    patch.setattr(scan, '_scan_trufflehog', unavailable)
    payload = ('token=' + composer.TOKEN + '\n').encode()
    try:
        c, calls, responses, pending = composer.fixture(patch, payload=payload)
        row, ix, env = composer.produce(c)
        marker = row[composer.adapter.MARKER]
        verdict, evidence = composer.check.evaluate(row, ix)
        output = {'kind': 'composer', 'complete': marker['complete'], 'reason': marker['reason'],
                  'leak_count': len(marker['leaks']), 'verdict': verdict,
                  'read_statuses': [r['status'] for r in marker['read_receipts']],
                  'native_request_count': len(marker['native_requests']),
                  'content_calls': len([x for x in calls if x[2].get('stream')]),
                  'responses_closed': all(r.closed for r in responses[-3:]),
                  'raw_secret_retained': composer.TOKEN in json.dumps([row, ix, c.transport.evidence, evidence])}
        assert output['content_calls'] == 3 and output['native_request_count'] == 3
        assert output['read_statuses'] == ['collected', 'collected', 'collected']
        assert output['responses_closed'] and not output['raw_secret_retained']
        return output
    finally:
        patch.undo()
        scan._RESULTS.clear()

def run_task(kind):
    patch = pytest.MonkeyPatch()
    scan._RESULTS.clear()
    patch.setattr(scan, '_scan_kingfisher', found)
    patch.setattr(scan, '_scan_trufflehog', unavailable)
    try:
        snapshot, trace = task.capture(patch, kind,
            data=task.native(kind, ('token=' + task.TOKEN + '\n').encode()), mocked=False)
        item, ix = task.index_of(snapshot, kind)
        marker = item[task.source.MARKER]
        verdict, evidence = task.checks.evaluate(item, ix, kind=kind)
        output = {'kind': kind, 'complete': marker['complete'], 'reason': marker['reason'],
                  'leak_count': len(marker['leaks']), 'verdict': verdict,
                  'part_completeness': [p['complete'] for p in marker['parts']],
                  'read_statuses': [r['status'] for r in marker['read_receipts']],
                  'native_request_count': len(marker['native_requests']),
                  'content_calls': len(trace.responses),
                  'responses_closed': all(r.closed for r in trace.responses),
                  'raw_secret_retained': task.TOKEN in json.dumps([snapshot, trace.c.transport.evidence, evidence])}
        assert output['content_calls'] == 1 and output['native_request_count'] == 1
        assert output['read_statuses'] == ['collected']
        assert output['responses_closed'] and not output['raw_secret_retained']
        return output
    finally:
        patch.undo()
        scan._RESULTS.clear()
