"""Compare same-scan checkpoint publication against an explicit predecessor.

No cloud calls. Both variants use the current complete publisher and S3 codec;
only the scan-local reuse wrapper differs. Uploads go to temporary local files,
so allocation measurements do not count an artificial in-memory object archive.
"""
import argparse
from collections import Counter
import copy
import gc
import importlib.util
import json
from pathlib import Path
import resource
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc

from examples.benchmark_peaso_publication_reuse import Objects, bundle_digest
from examples.benchmark_peaso_report_publication import fixture
from peaso.snapshot import digest
from peaso.storage.artifacts import S3Artifacts
from peaso.storage.report_reuse import ReusableReportArtifacts
from peaso.storage.reports import publish_report

TENANT, JOB = 'benchmark', 'f' * 32


class Transport(Objects):
    def __init__(self, root, latency):
        super().__init__(root)
        self.latency, self.lock = latency, threading.Lock()
        self.active = self.peak = 0

    def put_object(self, **request):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            if self.latency:
                time.sleep(self.latency)
            with self.lock:
                super().put_object(**request)
        finally:
            with self.lock:
                self.active -= 1


def predecessor(path):
    spec = importlib.util.spec_from_file_location('peaso.storage._reuse_predecessor', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ReusableReportArtifacts


def replay(wrapper, report, snapshot, latency, memory=False):
    # Repeated checkpoint, then a real evidence change. Inputs are prepared
    # before timing; the same wrappers live for this one scan only.
    reports = []
    for sequence in range(1, 4):
        current = copy.deepcopy(report)
        current['publication'] = {'state': 'partial', 'phase': 'collecting', 'sequence': sequence}
        if sequence == 3:
            current['findings'][0]['evidence']['recorded_value'] = 'changed in checkpoint 3'
        reports.append(current)
    before = [digest(row) for row in reports], digest(snapshot)
    with tempfile.TemporaryDirectory(prefix='peaso-scan-cache-') as directory:
        client = Transport(Path(directory), latency)
        backend = S3Artifacts('private-fixture', client, kms_key='fixture-key')
        cached = wrapper(backend, TENANT, JOB)
        rows, fingerprints = [], []
        for current in reports:
            gc.collect()
            counters = Counter(client.counts)
            collections = [generation['collections'] for generation in gc.get_stats()]
            if memory:
                tracemalloc.start()
            usage = resource.getrusage(resource.RUSAGE_SELF)
            wall, cpu = time.perf_counter(), time.process_time()
            reference = publish_report(cached, TENANT, JOB, current, snapshot)
            row = {'cpu_seconds': time.process_time() - cpu,
                   'wall_seconds': time.perf_counter() - wall,
                   **dict(Counter(client.counts) - counters)}
            row['gc_collections'] = [generation['collections'] - before
                                     for generation, before in zip(gc.get_stats(), collections)]
            after = resource.getrusage(resource.RUSAGE_SELF)
            row.update(user_seconds=after.ru_utime - usage.ru_utime,
                       system_seconds=after.ru_stime - usage.ru_stime,
                       minor_faults=after.ru_minflt - usage.ru_minflt,
                       major_faults=after.ru_majflt - usage.ru_majflt)
            if memory:
                row['peak_allocated_bytes'] = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
            rows.append(row)
            # Resolve every child artifact, full JSON and exact Markdown after
            # timing and tracing. Duplicate reference counts may legitimately differ.
            fingerprints.append(bundle_digest(backend, reference))
        assert ([digest(row) for row in reports], digest(snapshot)) == before
        return {'checkpoints': rows, 'bundle_digests': fingerprints,
                'total_writes': client.counts['writes'],
                'total_transferred_bytes': client.counts['transferred_bytes'],
                'retained_cache_entries': len(cached.entries), 'peak_uploads': client.peak}


def compare(baseline, count, latency, compact, memory, repeats=4):
    from peaso.checks.catalog import framework_catalog
    framework_catalog()  # Ordinary scan evaluation has already initialized this.
    report, snapshot = fixture(count, compact)
    variants = [('baseline', predecessor(baseline)), ('candidate', ReusableReportArtifacts)]
    samples = {name: [] for name, _ in variants}
    for iteration in range(repeats):
        order = variants if iteration % 2 == 0 else variants[::-1]
        for name, wrapper in order:
            samples[name].append(replay(wrapper, report, snapshot, latency))
            print(name, 'run', len(samples[name]), 'checkpoint writes',
                  [row.get('writes', 0) for row in samples[name][-1]['checkpoints']],
                  file=sys.stderr, flush=True)
    fingerprints = [sample['bundle_digests'] for rows in samples.values() for sample in rows]
    assert all(value == fingerprints[0] for value in fingerprints)
    output = {'findings': count, 'compact': compact, 'simulated_put_latency_ms': latency * 1000,
              'repeats_per_variant': repeats,
              'cloud_calls': 0, 'all_resolved_bundle_payloads_equal': True,
              'input_unchanged': True, 'samples': samples, 'medians': {}}
    for name, wrapper in variants:
        output['medians'][name] = [
            {key: statistics.median(sample['checkpoints'][i].get(key, 0) for sample in samples[name])
             for key in ('cpu_seconds', 'wall_seconds', 'writes', 'transferred_bytes')}
            for i in range(3)]
        if memory:
            traced = replay(wrapper, report, snapshot, latency, memory=True)
            assert traced['bundle_digests'] == fingerprints[0]
            output['medians'][name + '_peak_allocated_bytes'] = [
                row['peak_allocated_bytes'] for row in traced['checkpoints']]
    output['limitations'] = ('Synthetic complete report checkpoints; simulated S3 latency and temporary file '
        'transport. Catalog initialization, fixture construction, parity resolution and cleanup are outside '
        'timing. Interleaved runs per variant; separate tracemalloc run is not process RSS. '
        'Includes all sanitization, grouping, Markdown, native expansion, serialization and compression. '
        'Does not measure whole-scan speed or live cloud performance.')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--findings', type=int, default=10000)
    parser.add_argument('--latency-ms', type=float, default=20)
    parser.add_argument('--compact', action='store_true')
    parser.add_argument('--memory', action='store_true')
    parser.add_argument('--repeats', type=int, default=4)
    args = parser.parse_args()
    if args.findings < 1 or args.latency_ms < 0 or args.repeats < 2:
        parser.error('positive findings, nonnegative latency and at least two repeats required')
    print(json.dumps(compare(args.baseline, args.findings, args.latency_ms / 1000,
                             args.compact, args.memory, args.repeats), indent=2))
