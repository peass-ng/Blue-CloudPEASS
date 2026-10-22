"""Offline full-page leak replay with real pinned engines and private evidence.

Pass an unmodified baseline module path. Prints only counts, hashes and timings;
synthetic token values and decrypted private source records stay in memory.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import time

from peaso import secret_scanning as scanning, secret_evidence as evidence
from peaso.collectors import aws_code_log_content_indicators as candidate


TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'


def cpu():
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return time.process_time() + children.ru_utime + children.ru_stime


def replay(module, events):
    calls = []
    original = scanning._run

    def counted(argv, *args):
        if 'filesystem' in argv:
            calls.append(1)
        return original(argv, *args)

    scanning._run = counted
    scanning._RESULTS.clear()
    cipher = evidence.EphemeralCipher()
    start, used = time.perf_counter(), cpu()
    try:
        with evidence.capture(cipher, tenant='offline', scan_id='a' * 32) as sink:
            with evidence.source_context(resource_id='owned-log', scope='us-east-1'):
                value = module.project_response({'events': events}, 'logs', 'filter_log_events',
                    {'logGroupName': 'owned-log', 'startTime': 100, 'endTime': 200, 'limit': 100},
                    region='us-east-1', request_context={'remaining_bytes': module.MAX_BYTES})
            records = [cipher.decrypt(sink.records[key]) for key in sorted(sink.records)]
            assert not sink.incomplete
        elapsed, used = time.perf_counter() - start, cpu() - used
    finally:
        scanning._run = original
    assert all(row['scanner_complete'] for row in value['value']['events'])
    positive = sum(bool(row['leaks']) for row in value['value']['events'])
    assert positive == 50 and records
    public = json.dumps(value, sort_keys=True, separators=(',', ':'))
    private = json.dumps(records, sort_keys=True, separators=(',', ':'))
    assert TOKEN not in public
    return dict(wall_seconds=elapsed, cpu_seconds=used, trufflehog_processes=len(calls),
                events=len(events), positive_events=positive,
                private_locations=sum(len(row['locations']) for row in records),
                public_sha256=hashlib.sha256(public.encode()).hexdigest(),
                private_sha256=hashlib.sha256(private.encode()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    args = parser.parse_args()
    name = 'peaso.collectors._log_page_before'
    spec = importlib.util.spec_from_file_location(name, args.baseline)
    before = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(before)
    events = [dict(timestamp=100+i, eventId=f'event-{i}', logStreamName='owned-stream',
                   message=f'event={i} token={TOKEN}' if i % 2 else f'clean event {i}')
              for i in range(100)]
    # Equal rule/version warmup; neither measured case uses a result cache.
    scanning._kingfisher()
    scanning._trufflehog()
    # The first projection lazily imports AWS collector registration. That
    # process startup cost must not be charged only to the baseline case.
    candidate.project_response({'events': []}, 'logs', 'filter_log_events',
        {'logGroupName': 'owned-log', 'startTime': 100, 'endTime': 200, 'limit': 100},
        region='us-east-1', request_context={'remaining_bytes': candidate.MAX_BYTES})
    results = dict(before=replay(before, events), after=replay(candidate, events))
    assert results['before']['public_sha256'] == results['after']['public_sha256']
    assert results['before']['private_sha256'] == results['after']['private_sha256']
    print(json.dumps(dict(cloud_calls=0, exact_public_private_parity=True, **results), indent=2))
