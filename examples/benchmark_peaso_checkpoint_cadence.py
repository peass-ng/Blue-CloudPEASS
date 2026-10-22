"""Replay durable checkpoint updates against retained inventory, without cloud I/O.

Use --baseline and --candidate to compare collector implementations. The full
native evaluator, public redaction, local durable writes and report publication
run normally. Output contains counts, timings and hashes only. Temporary private
artifacts are deleted. This profiles replay after restore, not cloud latency.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time

from peaso import engine
from peaso.auth.secrets import redact
from peaso.snapshot import make_snapshot
from peaso.storage.artifacts import FileArtifacts
from peaso.storage.reports import publish_report
from peaso.worker import redact_report


class TimedLock:
    def __init__(self):
        self.lock = threading.RLock()
        self.depth = 0
        self.total = self.maximum = 0.0
    def __enter__(self):
        self.lock.acquire()
        if self.depth == 0:
            self.start = time.perf_counter()
        self.depth += 1
        return self
    def __exit__(self, *args):
        self.depth -= 1
        if self.depth == 0:
            elapsed = time.perf_counter() - self.start
            self.total += elapsed
            self.maximum = max(self.maximum, elapsed)
        self.lock.release()


def replay(module_path, snapshot, batches, categories):
    spec = importlib.util.spec_from_file_location('peaso._checkpoint_benchmark', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original_make = module.make_snapshot
    module.make_snapshot = lambda *args, **kwargs: original_make(
        *args, created_at=snapshot['created_at'], **kwargs)
    class ManualSession(module.CheckpointSession):
        def _background(self): pass
    metrics = {'raw_batches': 0, 'reports': 0, 'artifact_bytes': 0,
               'artifact_writes': 0, 'redaction_calls': 0, 'evaluation_wall': 0.0,
               'evaluation_cpu': 0.0, 'publication_wall': 0.0}
    final = None
    class Artifacts(FileArtifacts):
        def _write(self, tenant, ident, kind, value, **kwargs):
            metrics['artifact_bytes'] += len(value.encode())
            metrics['artifact_writes'] += 1
            return super()._write(tenant, ident, kind, value, **kwargs)
    original_evaluate = engine.evaluate_snapshot
    def evaluate(*args, **kwargs):
        wall, cpu = time.perf_counter(), time.process_time()
        try:
            return original_evaluate(*args, **kwargs)
        finally:
            metrics['evaluation_wall'] += time.perf_counter() - wall
            metrics['evaluation_cpu'] += time.process_time() - cpu
    def public(raw):
        metrics['redaction_calls'] += 1
        return module.seal(redact(raw))
    with tempfile.TemporaryDirectory(prefix='peaso-cadence-private-') as folder:
        artifacts = Artifacts(Path(folder))
        def checkpoint(raw, report, sequence):
            nonlocal final
            began = time.perf_counter()
            artifacts.put('benchmark', 'a'*32, 'snapshot', raw)
            if report is None:
                metrics['raw_batches'] += 1
            else:
                metrics['reports'] += 1
                safe = redact_report(report)
                final = hashlib.sha256(json.dumps(safe, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest()
                publish_report(artifacts, 'benchmark', 'a'*32, safe, raw)
            metrics['publication_wall'] += time.perf_counter() - began
        request = {'connector': {'provider': snapshot['provider'], 'scopes': snapshot['scopes']},
                   'categories': categories}
        session = ManualSession(request, checkpoint, public, batch_interval=100)
        rows = snapshot['collections']
        restored = make_snapshot(snapshot['provider'], snapshot['scopes'], rows,
            metadata={'incremental': {'sequence': len(rows),
                'batch_revisions': list(range(1, len(rows)+1))}})
        session.restore([restored], len(rows))
        session.lock = TimedLock()
        engine.evaluate_snapshot = evaluate
        began, cpu = time.perf_counter(), time.process_time()
        try:
            for batch in range(batches):
                for offset in range(64):
                    row = copy.deepcopy(rows[(batch*64+offset) % len(rows)])
                    row['benchmark_revision'] = batch*64+offset+1
                    session.on_collection(row)
                session._maybe_publish()
            session.flush()
        finally:
            session.close()
            engine.evaluate_snapshot = original_evaluate
        metrics.update(wall_seconds=time.perf_counter()-began, cpu_seconds=time.process_time()-cpu,
            collector_lock_total_seconds=session.lock.total,
            collector_lock_max_seconds=session.lock.maximum, final_report_sha256=final,
            final_sequence=session.sequence, collection_count=len(rows),
            resources=sum(len(row['items']) for row in rows))
    return metrics


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--batches', type=int, default=4)
    parser.add_argument('--categories', nargs='+', default=['hardening'])
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text())
    before = replay(args.baseline, snapshot, args.batches, args.categories)
    after = replay(args.candidate, snapshot, args.batches, args.categories)
    assert before['final_report_sha256'] == after['final_report_sha256']
    assert before['raw_batches'] == after['raw_batches'] == args.batches
    print(json.dumps({'before': before, 'after': after, 'final_report_equal': True,
                      'cloud_requests': 0, 'categories': args.categories}, indent=2))
