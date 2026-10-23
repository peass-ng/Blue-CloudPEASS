"""Complete IAM stage replay against an explicit predecessor policy parser.

No cloud calls. Fixture preparation, fingerprints and cold native initialization
are outside timing; independent runs keep no cache across scans.
"""
import argparse
import gc
import importlib.util
import json
from pathlib import Path
import statistics
import time
import tracemalloc
from unittest.mock import patch
from urllib.parse import quote

from examples.benchmark_peaso_decoded_policies import synthetic_snapshot
from examples.benchmark_peaso_iam_action_profiles import run_stage
from peaso.analysis import iam
from peaso.snapshot import digest, resources, seal, validate


def predecessor(path):
    spec = importlib.util.spec_from_file_location('peaso.analysis._predecessor_policy_views', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._resource_policy_documents


def fixture(count, mode):
    source = synthetic_snapshot(count, 'dict', 20)
    source = json.loads(json.dumps(source))
    for collection in source['collections']:
        shared = collection['items'][0]['RolePolicyList'][0]['PolicyDocument']
        for i, role in enumerate(collection['items']):
            if mode == 'shared':
                role['RolePolicyList'][0]['PolicyDocument'] = shared
            for row, field in [(role, 'AssumeRolePolicyDocument'),
                               *((item, 'PolicyDocument') for item in role['RolePolicyList'])]:
                if mode == 'unique':
                    row[field]['Id'] = 'unique-policy-' + str(i)
                if mode != 'dict':
                    text = json.dumps(row[field], ensure_ascii=False)
                    row[field] = quote(text) if mode == 'percent' else text
    return validate(seal(source))


def compare(baseline, count, mode, repeats, memory):
    snapshot = fixture(count, mode)
    inventory, before = resources(snapshot), digest(snapshot)
    candidate = iam._resource_policy_documents
    variants = [('baseline', predecessor(baseline)), ('candidate', candidate)]
    results = {name: {'samples': [], 'fingerprints': []} for name, _ in variants}
    # Initialize normal native metadata once, as the worker does before analysis.
    run_stage(snapshot, inventory)
    for iteration in range(repeats):
        for name, parser in variants if iteration % 2 == 0 else variants[::-1]:
            with patch.object(iam, '_resource_policy_documents', parser):
                gc.collect()
                start, cpu = time.perf_counter(), time.process_time()
                output = run_stage(snapshot, inventory)
                results[name]['samples'].append({'cpu_seconds': time.process_time() - cpu,
                                                'wall_seconds': time.perf_counter() - start})
                results[name]['fingerprints'].append(digest(output))
                counts = {key: len(output[key]) for key in ('findings', 'principals')}
                counts.update(nodes=len(output['graph']['nodes']), edges=len(output['graph']['edges']))
                del output
    if memory:
        for name, parser in variants:
            with patch.object(iam, '_resource_policy_documents', parser):
                gc.collect()
                tracemalloc.start()
                output = run_stage(snapshot, inventory)
                results[name]['peak_allocated_bytes'] = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
                assert digest(output) == results[name]['fingerprints'][0]
                del output
    fingerprints = [fp for row in results.values() for fp in row.pop('fingerprints')]
    assert len(set(fingerprints)) == 1 and digest(snapshot) == before
    for row in results.values():
        row['median_cpu_seconds'] = statistics.median(s['cpu_seconds'] for s in row['samples'])
        row['median_wall_seconds'] = statistics.median(s['wall_seconds'] for s in row['samples'])
    return {'resources': len(inventory), 'mode': mode, 'repeats': repeats, 'results': results, **counts,
            'identical_complete_output': True, 'input_unchanged': True, 'output_sha256': fingerprints[0],
            'cloud_calls': 0, 'limits': 'Synthetic complete IAM findings, graph and principal projection; '
                'includes context creation, all parsing and cleanup. Excludes collection, native checks, '
                'privilege techniques, other analyses and report rendering. Tracemalloc peaks are not RSS.'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--resources', type=int, default=600)
    p.add_argument('--mode', choices=['json', 'percent', 'shared', 'unique', 'dict'], default='percent')
    p.add_argument('--repeats', type=int, default=4)
    p.add_argument('--memory', action='store_true')
    args = p.parse_args()
    print(json.dumps(compare(args.baseline, args.resources, args.mode, args.repeats, args.memory), indent=2))
