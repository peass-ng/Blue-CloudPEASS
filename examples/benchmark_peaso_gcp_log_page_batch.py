"""Offline GCP page replay: exact complete-page parity and bounded coverage.

Real pinned scanners run without cloud calls. Output is counts/timings/hashes;
synthetic values and private plaintext records remain only in process memory.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import time
from datetime import datetime, timedelta, timezone

from peaso import secret_scanning as scanning, secret_evidence as evidence
from peaso.collectors import gcp_log_secret_indicators as candidate


TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
SCOPE = 'projects/offline-project'


def cpu():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return time.process_time() + usage.ru_utime + usage.ru_stime


def replay(module, count, last):
    first = last - timedelta(minutes=30)
    rows = [dict(logName=SCOPE+'/logs/application', timestamp=last.isoformat(),
                 insertId=f'event-{i}', resource={'type': 'global',
                 'labels': {'project_id': 'offline-project'}},
                 textPayload=f'event={i} token={TOKEN}') for i in range(count)]
    starts = []
    original = scanning._run

    def run(argv, *args):
        if 'stdin' in argv or 'filesystem' in argv:
            starts.append(1)
        return original(argv, *args)

    scanning._run = run
    scanning._RESULTS.clear()
    cipher = evidence.EphemeralCipher()
    wall, used = time.perf_counter(), cpu()
    try:
        with evidence.capture(cipher, tenant='offline', scan_id='a'*32) as sink:
            result, cursor = module.project_page({'entries': rows}, scope=SCOPE,
                first=first, last=last, page_size=50, page_number=1,
                check_cancelled=lambda: None)
            records = {key: cipher.decrypt(value) for key, value in sink.records.items()}
            assert not sink.incomplete
        seconds, used = time.perf_counter()-wall, cpu()-used
    finally:
        scanning._run = original
    assert cursor is None and result['entries'] == count
    public = json.dumps(result, sort_keys=True, separators=(',', ':'))
    private = json.dumps(records, sort_keys=True, separators=(',', ':'))
    assert TOKEN not in public
    metrics = dict(wall_seconds=seconds, cpu_seconds=used, detector_processes=len(starts),
        entries=count, scanned=len(result['scans']),
        complete_scans=sum(row['complete'] for row in result['scans']), complete=result['complete'],
        private_locations=sum(len(row['locations']) for row in records.values()),
        public_sha256=hashlib.sha256(public.encode()).hexdigest(),
        private_records_sha256=hashlib.sha256(private.encode()).hexdigest())
    return metrics, result, records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('peaso.collectors._gcp_log_before', args.baseline)
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)
    scanning._kingfisher()
    scanning._trufflehog()
    output = []
    for count in (10, 50):
        captured_at = datetime.now(timezone.utc).replace(microsecond=0)
        before, native_before, private_before = replay(baseline, count, captured_at)
        after, native_after, private_after = replay(candidate, count, captured_at)
        assert after['complete'] and after['complete_scans'] == count
        # All previously captured private locations survive the larger page.
        for key, record in private_before.items():
            target = private_after[key]
            assert all(loc in target['locations'] for loc in record['locations'])
            assert all(item in target['detectors'] for item in record['detectors'])
        equal = before['complete']
        if equal:
            assert native_before == native_after and private_before == private_after
        output.append(dict(before=before, after=after,
            exact_complete_public_private_records_parity=equal,
            prior_private_locations_preserved=True))
    print(json.dumps(dict(cloud_calls=0, deadline_seconds=45, results=output), indent=2))
