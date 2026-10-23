"""Complete per-finding AI fingerprint preparation; exact baseline byte contract."""
import argparse
import gc
import json
import statistics
import time
import tracemalloc

from peaso.ai import pipeline
from examples.benchmark_peaso_alternative_optimizations import original


def measured_pair(previous, current):
    expected = previous()
    assert current() == expected
    results = {key: {'trials': []} for key in ('baseline', 'optimized')}
    functions = [('baseline', previous), ('optimized', current)]
    for trial in range(3):
        for name, function in functions if trial % 2 == 0 else functions[::-1]:
            gc.collect()
            started, cpu = time.perf_counter(), time.process_time()
            actual = function()
            results[name]['trials'].append({'wall_seconds': time.perf_counter() - started,
                                            'cpu_seconds': time.process_time() - cpu})
            assert actual == expected
    for name, function in functions:
        gc.collect()
        tracemalloc.start()
        try:
            actual = function()
            results[name]['peak_python_bytes'] = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert actual == expected
        results[name].update({key: statistics.median(row[key] for row in results[name]['trials'])
                              for key in ('wall_seconds', 'cpu_seconds')})
    return dict(results, equal_complete_fingerprints=True)


def compare(baseline, count, fields):
    previous = original(baseline, 'peaso/ai/pipeline.py', 'review_fingerprints', pipeline)
    for name in ('review_context', 'findings_document', 'review_credentials'):
        previous.__globals__[name] = original(baseline, 'peaso/ai/pipeline.py', name, pipeline)
    results = {}
    for provider in ('aws', 'gcp', 'azure', 'k8s'):
        scope = {'aws': '123456789012/us-east-1', 'gcp': 'projects/synthetic',
                 'azure': 'subscriptions/synthetic', 'k8s': 'namespace-a'}[provider]
        inventory = {f'r{index}': {'id': f'r{index}', 'scope': scope,
            'data': {'recorded_labels': [f'native-{number}' for number in range(fields)]}}
            for index in range(10)}
        findings = [{'id': f'f{index}', 'resource_id': f'r{index % 10}', 'scope': scope,
            'provider': provider, 'status': 'UNKNOWN',
            'evidence': {'values': [f'value-{number}' for number in range(fields)], 'cluster_id': 'cluster-a'}}
            for index in range(count)]
        report = {'provider': provider, 'snapshot_id': 'checkpoint', 'created_at': 'time'}
        entry = {'provider': provider, 'target_scopes': [scope], 'account_id': '123456789012',
                 'cluster_id': 'cluster-a', 'captured_at': 100, 'expires_at': 200}
        for access in ('none', 'matching', 'other-provider'):
            entries = [] if access == 'none' else [entry if access == 'matching' else dict(entry, provider='other')]
            arguments = report, inventory, findings
            results[provider + '/' + access] = measured_pair(
                lambda: previous(*arguments, identity={'owner': 'synthetic'}, entries=entries),
                lambda: pipeline.review_fingerprints(*arguments, identity={'owner': 'synthetic'}, entries=entries))
    return {'baseline_commit': baseline, 'findings_per_case': count, 'fields_per_finding_and_resource': fields,
        'method': 'Warm both variants, then median of three alternating full fingerprint-workflow CPU/wall trials; '
                  'separate tracemalloc peak; '
                  'all four providers and three access-context states; no model or cloud calls', 'results': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default='5af7c210')
    parser.add_argument('--findings', type=int, default=1000)
    parser.add_argument('--fields', type=int, default=200)
    args = parser.parse_args()
    print(json.dumps(compare(args.baseline, args.findings, args.fields), indent=2))
