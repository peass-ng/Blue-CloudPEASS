"""Complete network findings, topology, annotation and identity correlation.

python -m examples.benchmark_peaso_network_workflows --scenario gcp --size 1000 --memory
The reference repeats predecessor native traversals and uses its exact topology
builder. All previously shipped workload/selector indexes remain enabled.
"""
import argparse
from contextlib import contextmanager, ExitStack
import gc
import json
import statistics
import sys
import time
import tracemalloc
from unittest.mock import patch

from examples.benchmark_peaso_cloud_workloads import synthetic_snapshot as cloud_snapshot
from examples.benchmark_peaso_gcp_lb_workloads import run_stage, synthetic_snapshot as lb_snapshot
from examples.benchmark_peaso_k8s_workloads import synthetic_snapshot as k8s_snapshot
from examples.benchmark_peaso_network import synthetic_snapshot as native_snapshot
from examples.benchmark_peaso_network_facts import RepeatedNetworkFacts
from examples.benchmark_peaso_network_node_ids import fingerprint, synthetic_snapshot as topology_snapshot
from examples.reference_peaso_network_node_ids import original_builder
from peaso.analysis import common, network, network_facts, network_observations
from peaso.snapshot import digest, resources


@contextmanager
def implementation(baseline):
    with ExitStack() as stack:
        if baseline:
            stack.enter_context(patch.object(network, 'build_network', original_builder()))
            stack.enter_context(patch.object(network_facts, 'NetworkFacts', RepeatedNetworkFacts))
            stack.enter_context(patch.object(network_observations, '_field_traits', lambda key: None))
        yield


def fixture(scenario, size):
    if scenario in {'aws', 'azure'}:
        return cloud_snapshot(scenario, size)
    if scenario == 'gcp':
        return lb_snapshot(size)
    if scenario == 'k8s':
        return k8s_snapshot(size, 'shared')
    if scenario == 'gcp_native':
        return native_snapshot('gcp', workloads=size, selectors=size, subnets=10)
    if scenario == 'topology':
        return topology_snapshot(size)
    raise ValueError('supported scenario required')


def compare(scenario='gcp', size=1000, *, memory=False):
    snapshot = fixture(scenario, size)
    inventory, before = resources(snapshot), digest(snapshot)
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': [], 'node_id_hashes': []}
        for name in ('baseline', 'optimized')}
    for iteration in range(3):
        for name in ('baseline', 'optimized') if iteration % 2 == 0 else ('optimized', 'baseline'):
            with implementation(name == 'baseline'):
                common._node_id.cache_clear()
                gc.collect()
                started, cpu = time.perf_counter(), time.process_time()
                output = run_stage(snapshot, inventory)
                results[name]['seconds'].append(time.perf_counter() - started)
                results[name]['cpu_seconds'].append(time.process_time() - cpu)
                results[name]['node_id_hashes'].append(common._node_id.cache_info().misses)
                results[name]['digests'].append(fingerprint(output))
                counts = {'findings': len(output['findings']), 'nodes': len(output['graph']['nodes']),
                    'edges': len(output['graph']['edges']), 'principals': len(output['principals'])}
                if scenario == 'topology':
                    assert counts == {'findings': 0, 'nodes': size * 2, 'edges': size, 'principals': 0}
                else:
                    assert counts['findings'] > 0 and counts['nodes'] > 0 and counts['principals'] > 0
                print(scenario, name, iteration + 1, 'seconds', round(results[name]['seconds'][-1], 3),
                    'cpu', round(results[name]['cpu_seconds'][-1], 3), file=sys.stderr, flush=True)
                del output
    if memory:
        for name in ('baseline', 'optimized'):
            with implementation(name == 'baseline'):
                common._node_id.cache_clear()
                gc.collect()
                tracemalloc.start()
                output = run_stage(snapshot, inventory)
                results[name]['peak_allocated_bytes'] = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
                assert fingerprint(output) == results[name]['digests'][0]
                del output
    for result in results.values():
        fingerprints = result.pop('digests')
        assert len(set(fingerprints)) == 1
        result['output_digest'] = fingerprints[0]
    assert results['baseline']['output_digest'] == results['optimized']['output_digest']
    assert digest(snapshot) == before
    return {**results, 'scenario': scenario, 'size': size, 'resources': len(inventory), **counts,
        'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
            statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
            statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete offline network findings, topology, annotation and principal '
            'correlation. Excludes collection, native checks, other analysis families and report rendering. '
            'Separate allocation peaks are traced Python allocations, not RSS.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=('aws', 'azure', 'gcp', 'k8s', 'gcp_native', 'topology'), default='gcp')
    parser.add_argument('--size', type=int, default=1000)
    parser.add_argument('--memory', action='store_true')
    args = parser.parse_args()
    print(json.dumps(compare(args.scenario, args.size, memory=args.memory), indent=2))
