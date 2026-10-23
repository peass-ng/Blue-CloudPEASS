"""Full native report publication with one shared inventory inside each call."""
import argparse
import gc
import json
from pathlib import Path
import tempfile
import statistics
import time
import tracemalloc

from examples.benchmark_peaso_alternative_optimizations import original
from examples.benchmark_peaso_publication_reuse import bundle_digest, Objects


def compare(baseline, count, fields):
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot, digest
    from peaso.storage import reports
    from peaso.storage.artifacts import FileArtifacts, S3Artifacts
    from peaso.worker import redact_report

    scope = '123456789012/us-east-1'
    snapshot = make_snapshot('aws', [scope], [{'type': 'bucket', 'scope': scope,
        'status': 'collected', 'items': [{'Name': f'synthetic-bucket-{index}',
            'recorded_configuration': {f'field-{key}': {'value': index + key, 'tags': ['synthetic', 'λ']}
                                       for key in range(fields)}} for index in range(count)]}],
        created_at='2026-01-01T00:00:00+00:00')
    report = redact_report(evaluate_snapshot(snapshot, checks=['aws.s3.default_encryption'],
        categories=['hardening'], include_not_applicable=False))
    prior = original(baseline, 'peaso/storage/reports.py', '_publish_report', reports)
    prior.__globals__['resource_chunks'] = original(baseline, 'peaso/storage/reports.py', 'resource_chunks', reports)
    unchanged = digest(snapshot), digest(report)
    results = {}
    with tempfile.TemporaryDirectory() as directory:
        for mode in ('file', 's3-local-transport'):
            values = {name: {'trials': [], 'bundle_hashes': []} for name in ('baseline', 'optimized')}
            variants = [('baseline', prior), ('optimized', reports._publish_report)]

            def run(function, name, trial):
                path = Path(directory) / mode / name / str(trial)
                backend = FileArtifacts(path) if mode == 'file' else S3Artifacts('private', Objects(path), kms_key='fixture')
                gc.collect()
                started, cpu = time.perf_counter(), time.process_time()
                if trial == 'memory':
                    tracemalloc.start()
                try:
                    if mode == 'file':
                        reference = function(backend, 'benchmark', 'f' * 32, report, snapshot)
                    else:
                        with backend.batch() as writer:
                            reference = function(writer, 'benchmark', 'f' * 32, report, snapshot)
                    stats = {'wall_seconds': time.perf_counter() - started,
                             'cpu_seconds': time.process_time() - cpu}
                    if trial == 'memory':
                        values[name]['peak_python_bytes'] = tracemalloc.get_traced_memory()[1]
                    else:
                        values[name]['trials'].append(stats)
                finally:
                    if trial == 'memory':
                        tracemalloc.stop()
                values[name]['bundle_hashes'].append(bundle_digest(backend, reference))

            for trial in range(3):
                for name, function in variants if trial % 2 == 0 else variants[::-1]:
                    run(function, name, trial)
            for name, function in variants:
                run(function, name, 'memory')
                values[name].update({key: statistics.median(item[key] for item in values[name]['trials'])
                                     for key in ('wall_seconds', 'cpu_seconds')})
            assert len(set(values['baseline']['bundle_hashes'] + values['optimized']['bundle_hashes'])) == 1
            results[mode] = dict(values, equal_complete_bundle=True)
    assert unchanged == (digest(snapshot), digest(report))
    return {'baseline_commit': baseline, 'resources': count, 'fields_per_native_resource': fields,
        'method': 'Three alternating full-publication CPU/wall trials, separate tracemalloc peak; real file and S3 codecs '
                  'with local transport; actual native evaluator warmed before timing; no cloud calls',
        'input_unchanged': True, 'results': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default='6b997cdc')
    parser.add_argument('--resources', type=int, default=2000)
    parser.add_argument('--fields', type=int, default=40)
    args = parser.parse_args()
    print(json.dumps(compare(args.baseline, args.resources, args.fields), indent=2))
