"""Full report publication replay with real retained native inventory.

Run both local durable storage and the normal S3 compression/encryption adapter
with a local object transport. No cloud request occurs. Compare every recursively
resolved bundle payload, including exact Markdown, after each publication.
Temporary private objects are deleted; output contains only counters and hashes.
"""
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import argparse

from peaso.engine import evaluate_snapshot
from peaso.storage.artifacts import FileArtifacts, S3Artifacts, check_reference
from peaso.storage.report_reuse import ReusableReportArtifacts
from peaso.storage.reports import publish_report
from peaso.worker import redact_report

TENANT, IDENT = 'benchmark', 'f'*32


class Files(FileArtifacts):
    def __init__(self, root):
        super().__init__(root)
        self.counts = Counter()
    def _write(self, tenant, ident, kind, value, **kwargs):
        self.counts['writes'] += 1
        self.counts['uncompressed_bytes'] += len(value.encode())
        return super()._write(tenant, ident, kind, value, **kwargs)


class Objects:
    """Private local object transport; real S3Artifacts codec runs above it."""
    def __init__(self, root):
        self.root = root
        self.counts = Counter()
    def put_object(self, **kwargs):
        body = kwargs['Body']
        self.counts['writes'] += 1
        self.counts['transferred_bytes'] += len(body)
        self.counts['uncompressed_bytes'] += int(kwargs.get('Metadata', {}).get('peaso-uncompressed-bytes', len(body)))
        path = self.root/kwargs['Key']
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(body)
    def get_object(self, **kwargs):
        return {'Body': io.BytesIO((self.root/kwargs['Key']).read_bytes())}


def bundle_digest(artifacts, reference):
    memo = {}
    def normalized(value):
        if isinstance(value, dict): return {key: normalized(child) for key, child in value.items()}
        if isinstance(value, list): return [normalized(child) for child in value]
        if isinstance(value, str):
            try: check_reference(TENANT, value)
            except ValueError: return value
            if value not in memo:
                if value.endswith('.md'):
                    memo[value] = hashlib.sha256(artifacts.get_text(TENANT, value).encode()).hexdigest()
                else:
                    memo[value] = hashlib.sha256(json.dumps(normalized(artifacts.get(TENANT, value)),
                        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            return {'resolved_payload_sha256': memo[value]}
        return value
    return normalized(reference)['resolved_payload_sha256']


def benchmark(snapshot, report, mode, reuse, publications):
    with tempfile.TemporaryDirectory(prefix='peaso-publish-reuse-private-') as directory:
        if mode == 'file':
            backend = Files(Path(directory)); counts = backend.counts
        else:
            objects = Objects(Path(directory)); backend = S3Artifacts('private-fixture', objects, kms_key='fixture-kms')
            counts = objects.counts
        artifacts = ReusableReportArtifacts(backend, TENANT, IDENT) if reuse else backend
        output, digests = [], []
        for sequence in range(1, publications+1):
            current = dict(report, publication={'state': 'partial', 'phase': 'collecting', 'sequence': sequence})
            before = Counter(counts)
            wall, cpu = time.perf_counter(), time.process_time()
            reference = publish_report(artifacts, TENANT, IDENT, current, snapshot)
            output.append({'wall_seconds': time.perf_counter()-wall, 'cpu_seconds': time.process_time()-cpu,
                **dict(Counter(counts)-before)})
            digests.append(bundle_digest(artifacts, reference))
        return {'backend': mode, 'reuse': reuse, 'publications': output, 'totals': dict(counts),
            'bundle_payload_sha256': digests, 'retained_cache_entries': len(artifacts.entries) if reuse else 0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--publications', type=int, default=2)
    args = parser.parse_args()
    raw = args.snapshot.read_bytes()
    snapshot = json.loads(raw)
    report = redact_report(evaluate_snapshot(snapshot, categories=['hardening'], include_not_applicable=False))
    results = []
    for mode in ('file', 's3-local-transport'):
        before = benchmark(snapshot, report, mode, False, args.publications)
        after = benchmark(snapshot, report, mode, True, args.publications)
        assert before['bundle_payload_sha256'] == after['bundle_payload_sha256']
        results.append({'before': before, 'after': after, 'all_bundle_payloads_equal': True})
    print(json.dumps({'snapshot_input_sha256': hashlib.sha256(raw).hexdigest(),
        'collections': len(snapshot['collections']), 'resources': sum(len(row['items']) for row in snapshot['collections']),
        'categories': ['hardening'], 'cloud_calls': 0, 'results': results}, indent=2))
