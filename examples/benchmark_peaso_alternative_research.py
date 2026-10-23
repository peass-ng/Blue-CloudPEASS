"""Offline observations for the alternative performance roadmap; no cloud calls.

Run with the repository's Python environment. These measure existing work and
adapter behavior, not an implemented optimization or a claimed speedup.
"""
from collections import Counter
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def artifact_reuse():
    from peaso.storage.artifacts import S3Artifacts
    from peaso.storage.report_reuse import ReusableReportArtifacts

    class Client:
        def __init__(self):
            self.writes = []

        def put_object(self, **arguments):
            self.writes.append(arguments)

    results = {}
    scan_id = 'a' * 32
    for batched in (False, True):
        client = Client()
        wrapper = ReusableReportArtifacts(S3Artifacts('offline', client), 'tenant', scan_id)
        references = []
        for _ in range(2):
            if batched:
                with wrapper.batch() as publisher:
                    references.append(publisher.put('tenant', scan_id, 'findings', {'items': []}))
            else:
                references.append(wrapper.put('tenant', scan_id, 'findings', {'items': []}))
        results['batched' if batched else 'direct'] = {
            'puts': len(client.writes), 'same_reference': references[0] == references[1],
            'reuse_entries': len(wrapper.entries),
        }
    return results


def audit_normalizers(count=200):
    from peaso.attack_detection.rules import Rule, detect_aws_events

    # Explicit synthetic rules avoid the default remote rule-pack loader.
    rules = (Rule('offline', 'Offline selector', 'low', '', '', 'aws',
                  {'event.source': 'not-the-input.amazonaws.com'}),)
    records = [{'eventSource': 'example.invalid', 'eventName': 'Ignore',
                'eventID': str(index)} for index in range(count)]
    start = time.process_time()
    result = detect_aws_events(records, rules)
    unprofiled_cpu = time.process_time() - start
    calls = Counter()

    def profile(frame, event, argument):
        if event == 'call':
            code = frame.f_code
            if code.co_name.startswith('normalize') and '/peaso/attack_detection/' in code.co_filename:
                calls[(code.co_filename, code.co_name)] += 1

    sys.setprofile(profile)
    try:
        profiled = detect_aws_events(records, rules)
    finally:
        sys.setprofile(None)
    assert profiled == result
    return {'events': count, 'rules': len(rules), 'detections': len(result),
            'unprofiled_cpu_seconds': unprofiled_cpu,
            'normalizer_calls': sum(calls.values()), 'distinct_normalizers': len(calls)}


if __name__ == '__main__':
    print(json.dumps({'artifact_reuse': artifact_reuse(),
                      'audit_normalizers': audit_normalizers()}, indent=2))
