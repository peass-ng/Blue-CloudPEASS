"""Synthetic leak postprocessing benchmark, with optional real offline detectors.

python -m examples.benchmark_peaso_leaks --real-detectors
"""
import argparse
import hashlib
import json
import time
from unittest.mock import patch

from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings


def _measure(function):
    times, digests = [], []
    for _ in range(3):
        started = time.perf_counter()
        output = function()
        times.append(round(time.perf_counter() - started, 6))
        digests.append(hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest())
    assert len(set(digests)) == 1
    return {'seconds': times, 'output_digest': digests[0]}


def benchmark(occurrences=1500, sources=500, real_detectors=False):
    if not 1 <= occurrences <= scanning.MAX_FINDINGS or sources < 1:
        raise ValueError('occurrences must fit the finding bound and sources must be positive')
    value = 'synthetic-value'
    payload = ((b'x' * 1024) + value.encode() + b'\n') * occurrences
    detector_output = json.dumps({'Raw': value, 'Verified': False, 'DetectorName': 'synthetic'}).encode()
    with patch.object(scanning, '_trufflehog', return_value='/synthetic/trufflehog'), \
            patch.object(scanning, '_run', return_value=detector_output):
        locations = _measure(lambda: scanning._scan_trufflehog(payload, 'synthetic.log', 15))
    leaks = [{'fingerprint': 'a' * 64,
              'detectors': [{'engine': 'kingfisher', 'rule': 'synthetic'}],
              'locations': [{'path': 'synthetic.log', 'line': i + 1}]}
             for i in range(occurrences)]
    merge = _measure(lambda: scanning.merge_leaks(leaks + leaks[::-1]))
    findings = [{'provider': 'aws', 'check_id': f'synthetic-{i % 3}', 'scope': 'synthetic',
                 'resource_id': f'synthetic-{i}', 'status': 'FAIL', 'frameworks': ['synthetic'],
                 'evidence': {'secret_leaks': [leaks[0]], 'complete': i != 0}}
                for i in range(sources)]
    grouping = _measure(lambda: deduplicate_secret_findings(findings))
    result = {'occurrences': occurrences, 'sources': sources, 'line_recovery': locations,
              'leak_merge': merge, 'finding_grouping': grouping, 'cloud_calls': 0,
              'limitations': 'Synthetic postprocessing timings exclude detector execution, collection and report rendering.'}
    if real_detectors:
        # Deliberately synthetic PAT; detectors run with credential verification disabled.
        token = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
        content = (f'token={token}\ncopy={token}\n').encode()

        def scan():
            scanning._RESULTS.clear()
            outcome = scanning.scan_content(content, 'synthetic.py')
            if not outcome['complete'] or not outcome['leaks']:
                raise RuntimeError('both pinned detectors must complete and detect the synthetic token')
            return outcome

        result['real_offline_detectors'] = _measure(scan)
        result['limitations'] += ' Real detector timings use a tiny synthetic file, clear the result cache, and include first-use initialization.'
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--occurrences', type=int, default=1500)
    parser.add_argument('--sources', type=int, default=500)
    parser.add_argument('--real-detectors', action='store_true')
    args = parser.parse_args()
    print(json.dumps(benchmark(args.occurrences, args.sources, args.real_detectors), indent=2))
