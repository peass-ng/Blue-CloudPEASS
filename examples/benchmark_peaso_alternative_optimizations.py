"""Offline before/after workflow replays; no remote services or model calls.

python -m examples.benchmark_peaso_alternative_optimizations --baseline 19cb2da9
The baseline is loaded from Git, without replacing admitted runtime helpers.
CPU/wall medians and traced Python allocation peaks are measured separately.
"""
import argparse
import ast
import gc
import io
import json
from pathlib import Path
import statistics
import subprocess
import tempfile
import threading
import time
import tracemalloc


def original(revision, path, name, module):
    source = subprocess.run(['git', 'show', f'{revision}:{path}'], check=True,
                            capture_output=True, text=True).stdout
    tree = ast.parse(source)
    node = next(node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name)
    namespace = dict(vars(module))
    exec(compile(ast.Module(body=[node], type_ignores=[]), f'<baseline {path}>', 'exec'), namespace)
    return namespace[name]


def measure(function):
    wall, cpu = [], []
    for _ in range(3):
        gc.collect()
        start, processor = time.perf_counter(), time.process_time()
        result = function()
        wall.append(time.perf_counter() - start)
        cpu.append(time.process_time() - processor)
    gc.collect()
    tracemalloc.start()
    function()
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return result, {'wall_seconds': statistics.median(wall), 'cpu_seconds': statistics.median(cpu),
                    'peak_python_bytes': peak}


def compare(before, after):
    old, old_stats = measure(before)
    new, new_stats = measure(after)
    assert old == new
    return {'baseline': old_stats, 'optimized': new_stats, 'equal_output': True}


def audit(revision):
    from peaso.attack_detection import rules
    old = original(revision, 'peaso/attack_detection/rules.py', 'detect_aws_events', rules)
    selected = [rules.Rule('offline', 'Offline', 'low', '', '', 'aws', {'event.source': 'other'})]
    events = [{'eventSource': 'example.invalid', 'eventName': 'Ignore', 'eventID': str(i)} for i in range(10000)]
    return compare(lambda: old(events, selected), lambda: rules.detect_aws_events(events, selected))


def private_indexes():
    from peaso.private_evidence_checkpoint import PrivateEvidenceCheckpoint
    from peaso.secret_evidence import Capture, EphemeralCipher
    cipher = EphemeralCipher()
    capture = Capture(cipher, 'offline', 'scan')
    for index in range(1000):
        capture.records[str(index)] = cipher.encrypt({'locations': [
            {'resource_id': f'resource-{index}', 'scope': 'scope', 'path': f'path-{ordinal}'} for ordinal in range(5)]})

    def replay(reuse):
        adapter = PrivateEvidenceCheckpoint() if reuse else None
        for _ in range(20):
            document = adapter.document(capture) if adapter else capture.document()
        return dict(document, index=cipher.decrypt(document['index']))

    return compare(lambda: replay(False), lambda: replay(True))


def manifests(revision):
    from peaso.storage import attack_history_ledger as ledger
    from peaso.attack_detection.history_s3 import CloudTrailObject, DayManifest
    old = original(revision, 'peaso/storage/attack_history_ledger.py', 'LocalAttackHistoryLedger', ledger)
    with tempfile.TemporaryDirectory() as directory:
        current = ledger.LocalAttackHistoryLedger(Path(directory))
        prefix = 'AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/18/'
        selected = DayManifest('bucket', prefix, '123456789012', 'us-east-1', '2026-10-18', tuple(
            CloudTrailObject(prefix + f'{i:06}.json.gz', 'etag', 100) for i in range(1000)), 1, '2026-10-18T00:00:00Z')
        pointer = current.put_manifest('tenant', 'job', selected)

        def replay(cls):
            reader = cls(Path(directory))
            for _ in range(40):
                manifest = reader.get_manifest('tenant', 'job', pointer.ref, pointer.sha256)
            return manifest

        return compare(lambda: replay(old), lambda: replay(ledger.LocalAttackHistoryLedger))


def access(revision):
    from peaso.ai import pipeline
    old = original(revision, 'peaso/ai/pipeline.py', 'review_credentials', pipeline)
    resources = [{'scope': 'scope', 'data': {f'field-{j}': f'value-{j}' for j in range(100)}} for _ in range(1000)]
    results = {}
    for provider in ('aws', 'gcp', 'azure', 'k8s'):
        entries = [{'provider': provider, 'account_id': '123456789012', 'cluster_id': f'cluster-{i}'} for i in range(12)]
        findings = [{'scope': 'scope', 'resource_id': 'arn:aws:lambda:us-east-1:123456789012:function:offline',
                     'evidence': {'cluster_id': 'cluster-1'}}]
        results[provider] = compare(lambda: old(entries, provider, findings, {'resources': resources}),
                                    lambda: pipeline.review_credentials(entries, provider, findings, {'resources': resources}))
    return results


def storage_reads(revision):
    from peaso.storage import dynamodb
    old = original(revision, 'peaso/storage/dynamodb.py', 'DynamoStore', dynamodb)

    class Client:
        def __init__(self):
            self.calls = 0
            self.rows = {}
            self.pages = []

        def get_item(self, TableName, Key, **kwargs):
            self.calls += 1
            return {'Item': self.rows[tuple(dynamodb.row(Key).values())]}

        def batch_get_item(self, RequestItems):
            self.calls += 1
            table, request = next(iter(RequestItems.items()))
            assert request['ConsistentRead'] is True
            return {'Responses': {table: [self.rows[tuple(dynamodb.row(key).values())] for key in request['Keys']]}}

        def query(self, **kwargs):
            self.calls += 1
            if 'IndexName' in kwargs:
                return {'Items': [{'PK': item['PK'], 'SK': item['SK']} for item in self.queued]}
            return {'Items': [dynamodb.attrs({'workspace_id': str(i)}) for i in range(5)]}

        def scan(self, **kwargs):
            self.calls += 1
            offset = int(kwargs.get('ExclusiveStartKey', {}).get('offset', 0))
            page = {'Items': self.pages[offset]}
            if offset + 1 < len(self.pages):
                page['LastEvaluatedKey'] = {'offset': offset + 1}
            return page

    client = Client()
    for i in range(5):
        for suffix, fields in [('meta/current', {'id': str(i), 'name': f'Workspace {i}', 'owner': 'user'}),
                               ('member/user', {'role': 'admin'})]:
            key = f'workspace/{i}', suffix
            client.rows[key] = dynamodb.attrs(dict(PK=key[0], SK=key[1], **fields))

    def workspaces(cls):
        client.calls = 0
        result = cls('table', client).workspaces('user')
        return result, client.calls

    old_output, before = measure(lambda: workspaces(old))
    new_output, after = measure(lambda: workspaces(dynamodb.DynamoStore))
    assert old_output[0] == new_output[0]
    workspace = {'baseline': before, 'optimized': after,
                 'requests': [old_output[1], new_output[1]], 'equal_output': True}
    client.rows = {}
    for i in range(20100):
        key = 'tenant/owner', f'job/{i}'
        client.rows[key] = dynamodb.attrs(dict(PK=key[0], SK=key[1], id=str(i), tenant='owner',
            kind='job', status='queued' if i < 100 else 'completed', created=i, queued_at=i))
    all_rows = list(client.rows.values())
    client.pages = [all_rows[offset:offset + 500] for offset in range(0, len(all_rows), 500)]
    client.queued = all_rows[:100]

    def queued(index):
        client.calls = 0
        result = dynamodb.DynamoStore('table', client, work_state_index=index).queued_jobs()
        return result, client.calls

    old_output, before = measure(lambda: queued(''))
    new_output, after = measure(lambda: queued('work-state'))
    assert old_output[0] == new_output[0]
    return {'workspaces': workspace, 'queue': {'baseline': before, 'optimized': after,
            'requests': [old_output[1], new_output[1]], 'equal_output': True}}


def publications(revision, compact=False):
    from examples.benchmark_peaso_publication import synthetic_report
    from examples.benchmark_peaso_publication_reuse import bundle_digest
    from peaso.storage import report_reuse
    from peaso.storage.artifacts import S3Artifacts
    from peaso.storage.reports import publish_report
    from peaso.checks.catalog import framework_catalog
    framework_catalog()
    old = original(revision, 'peaso/storage/report_reuse.py', 'ReusableReportArtifacts', report_reuse)
    if compact:
        from examples.benchmark_peaso_report_publication import fixture
        report, snapshot = fixture(2000, True)
    else:
        report, snapshot = synthetic_report(2000), None

    class Client:
        def __init__(self, root):
            self.root, self.lock, self.count = root, threading.Lock(), 0

        def put_object(self, **arguments):
            time.sleep(0.01)  # Declared synthetic transport latency, not AWS measurement.
            path = self.root / arguments['Key']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(arguments['Body'])
            with self.lock:
                self.count += 1

        def get_object(self, Bucket, Key):
            return {'Body': io.BytesIO((self.root / Key).read_bytes())}

    results = {}
    for name, cls in [('baseline', old), ('optimized', report_reuse.ReusableReportArtifacts)]:
        counts, hashes = [], []

        # Keep temporary objects alive through verification, but exclude that
        # verification from the timed allocation region.
        def trial():
            with tempfile.TemporaryDirectory() as directory:
                client = Client(Path(directory))
                backend = S3Artifacts('offline', client)
                writer = cls(backend, 'benchmark', 'f' * 32)
                gc.collect()
                start, cpu = time.perf_counter(), time.process_time()
                references = [publish_report(writer, 'benchmark', 'f' * 32,
                    dict(report, publication={'sequence': sequence}), snapshot) for sequence in range(2)]
                elapsed, processor = time.perf_counter() - start, time.process_time() - cpu
                counts.append(client.count)
                hashes.append([bundle_digest(backend, reference) for reference in references])
                return elapsed, processor

        times = [trial() for _ in range(3)]
        with tempfile.TemporaryDirectory() as directory:
            client = Client(Path(directory))
            writer = cls(S3Artifacts('offline', client), 'benchmark', 'f' * 32)
            gc.collect()
            tracemalloc.start()
            for sequence in range(2):
                publish_report(writer, 'benchmark', 'f' * 32, dict(report, publication={'sequence': sequence}), snapshot)
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
        results[name] = {'wall_seconds': statistics.median(item[0] for item in times),
                         'cpu_seconds': statistics.median(item[1] for item in times),
                         'peak_python_bytes': peak, 'puts': counts, 'bundle_hashes': hashes}
    assert results['baseline']['bundle_hashes'] == results['optimized']['bundle_hashes']
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default='19cb2da9')
    parser.add_argument('--sections', nargs='+', default=['audit', 'private', 'manifest', 'access', 'storage', 'publication'])
    parser.add_argument('--compact', action='store_true', help='Use native schema 1.1 inventory for publication')
    args = parser.parse_args()
    methods = {'audit': lambda: audit(args.baseline), 'private': private_indexes,
               'manifest': lambda: manifests(args.baseline), 'access': lambda: access(args.baseline),
               'storage': lambda: storage_reads(args.baseline), 'publication': lambda: publications(args.baseline, args.compact)}
    for section in args.sections:
        print(json.dumps({'section': section, 'results': methods[section]()}), flush=True)
