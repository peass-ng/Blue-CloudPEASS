"""Compare complete historical object reads; no cloud calls or parser changes."""
import argparse
import gzip
import io
import json
from types import SimpleNamespace
from unittest.mock import patch

from peaso.attack_detection import history_s3
from examples.benchmark_peaso_alternative_optimizations import measure, original


class Objects:
    def __init__(self, raw):
        self.raw = raw

    def get_object(self, **request):
        return {'ETag': request.get('IfMatch', '"fixture"'), 'ContentLength': len(self.raw),
                'Body': io.BytesIO(self.raw)}


def qualification(previous):
    """Compare success payloads and exact stable failure codes, including tails."""
    row = {'eventID': 'one', 'recipientAccountId': '123456789012', 'awsRegion': 'us-east-1'}
    document = json.dumps({'Records': [row]})
    payloads = [document.encode(encoding) for encoding in ('utf-8', 'utf-16', 'utf-32')]
    payloads += [(document + ' ' * 1400000).encode(), b'not-json', b'\xff', b'[]',
        b'{"Records": []}', ('{"Records": null, "Records": [' + json.dumps(row) + ']}').encode(),
        json.dumps({'Records': [row, row]}).encode(),
        json.dumps({'Records': [row | {'recipientAccountId': '999999999999'}]}).encode()]
    count = 0
    for payload in payloads:
        single = gzip.compress(payload, mtime=0)
        middle = len(payload) // 2
        variants = [single, single + b'\0' * 10,
            gzip.compress(payload[:middle], mtime=0) + gzip.compress(payload[middle:], mtime=0),
            single[:-3], single + b'invalid gzip trailer',
            single[:-8] + bytes([single[-8] ^ 1]) + single[-7:],
            single[:-4] + b'\0' * 4, single[:-4] + b'\xff' * 4,
            single[:3] + b'\x02' + single[4:10] + b'\0\0' + single[10:],
            single[:3] + b'\x20' + single[4:],
            single[:10] + b'\xff' * 10 + single[20:],
            single + gzip.compress(b' ', mtime=0)[:-3]]
        for raw in variants:
            prefix = 'AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/18/'
            obj = history_s3.CloudTrailObject(prefix + 'one.json.gz', '"fixture"', len(raw))
            manifest = history_s3.DayManifest('logs', prefix, '123456789012', 'us-east-1',
                '2026-10-18', (obj,), 1, '2026-10-23T00:00:00Z')
            for limit in sorted({1, 100, max(1, len(payload) - 1), len(payload), len(payload) + 1,
                                 history_s3.MAX_EXPANDED_BYTES}):
                def capture(function):
                    try:
                        value = function(Objects(raw), manifest, obj, max_expanded=limit)
                        return 'success', value.sha256, json.dumps(value.records, sort_keys=True)
                    except history_s3.HistorySourceGap as error:
                        return 'gap', str(error)
                    except Exception as error:
                        return 'exception', type(error).__name__, str(error)
                assert capture(previous) == capture(history_s3.read_cloudtrail_object), (count, limit)
                count += 1
    return count


def preview(baseline):
    from peaso.server import attack_logs
    records = [{'eventID': str(index), 'recipientAccountId': '123456789012',
                'awsRegion': 'us-east-1'} for index in range(100)]
    raw = gzip.compress(json.dumps({'Records': records}).encode(), mtime=0)

    class Client(Objects):
        def list_objects_v2(self, **request):
            return {'Contents': [{'Key': 'one.json.gz', 'Size': len(raw)}]}

    session = SimpleNamespace(client=lambda *args, **kwargs: Client(raw))
    source = SimpleNamespace(kind='aws_cloudtrail_s3', region='us-east-1', role_arn=None,
        bucket='logs', prefix='AWSLogs/123456789012/CloudTrail/', day='2020-01-01')
    with patch.object(attack_logs, '_target_session', lambda *args: (session, '123456789012')):
        previous = original(baseline, 'peaso/server/attack_logs.py', 'analyze_aws_source',
            SimpleNamespace(**vars(attack_logs), gzip=gzip, io=io))
        before, old_stats = measure(lambda: previous({}, {}, source, rules=[]))
        after, new_stats = measure(lambda: attack_logs.analyze_aws_source({}, {}, source, rules=[]))
    assert before == after
    return {'baseline': old_stats, 'optimized': new_stats, 'equal_output': True}


def replay(baseline):
    previous = original(baseline, 'peaso/attack_detection/history_s3.py',
                        'read_cloudtrail_object', SimpleNamespace(**vars(history_s3), gzip=gzip, io=io))
    results = {}
    for name, count, repeats in [('10000-small-objects', 10, 10000),
                                 ('1000-medium-objects', 1000, 1000),
                                 ('10-large-objects', 20000, 10)]:
        records = [{'eventID': str(index), 'recipientAccountId': '123456789012',
                    'awsRegion': 'us-east-1', 'detail': 'synthetic ' * 30}
                   for index in range(count)]
        payload = json.dumps({'Records': records}).encode()
        raw = gzip.compress(payload, mtime=0)
        prefix = 'AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/18/'
        obj = history_s3.CloudTrailObject(prefix + 'one.json.gz', '"fixture"', len(raw))
        manifest = history_s3.DayManifest('logs', prefix, '123456789012', 'us-east-1',
            '2026-10-18', (obj,), 1, '2026-10-23T00:00:00Z')

        def run(function):
            for _ in range(repeats):
                result = function(Objects(raw), manifest, obj)
            return result

        before, old_stats = measure(lambda: run(previous))
        after, new_stats = measure(lambda: run(history_s3.read_cloudtrail_object))
        assert before == after
        results[name] = {'baseline': old_stats, 'optimized': new_stats,
                         'compressed_bytes_per_object': len(raw),
                         'expanded_bytes_per_object': len(payload), 'equal_output': True}
    results['interactive-preview'] = preview(baseline)
    return {'baseline_commit': baseline, 'method': 'Median of three full-read CPU/wall trials; '
            'separate tracemalloc peak; in-memory S3 transport; no cloud calls', 'results': results,
            'differential_acceptance_and_error_cases': qualification(previous)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default='3359a8fb')
    print(json.dumps(replay(parser.parse_args().baseline), indent=2))
