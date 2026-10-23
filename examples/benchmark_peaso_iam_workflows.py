"""Complete IAM review, graph and principal stages with predecessor algorithms.

python -m examples.benchmark_peaso_iam_workflows --scenario encoded --size 500 --memory
Every reference runs the full stage; only pure reuse/prepared-ID helpers differ.
"""
import argparse
from contextlib import contextmanager, ExitStack
import gc
import json
import statistics
import time
import tracemalloc
from unittest.mock import patch

from examples.benchmark_peaso_decoded_policies import literal_documents, synthetic_snapshot as encoded_snapshot
from examples.benchmark_peaso_iam_action_profiles import synthetic_snapshot as role_snapshot, run_stage
from examples.benchmark_peaso_trust_domains import literal_normalized, synthetic_snapshot as domain_snapshot
from examples.benchmark_peaso_trust_policy_reuse import literal_document
from examples.reference_peaso_iam_node_ids import original_builder
from peaso import principal_exposure
from peaso.analysis import iam, trust
from peaso.snapshot import resources, digest


@contextmanager
def implementation(baseline):
    with ExitStack() as stack:
        if baseline:
            for owner, name, value in ((iam, '_permission_profile', iam._permission_profile_uncached),
                    (iam, '_resource_policy_documents', literal_documents),
                    (iam, 'assume_role_document', literal_document),
                    (principal_exposure, 'assume_role_document', literal_document),
                    (trust, 'normalized_domains', literal_normalized),
                    (iam, 'build_iam', original_builder())):
                stack.enter_context(patch.object(owner, name, value))
        yield


def compare(scenario='encoded', size=500, *, memory=False):
    if size < 1:
        raise ValueError('positive inventory size required')
    if scenario == 'encoded':
        snapshot = encoded_snapshot(size, 'percent', 20)
    elif scenario in ('aws','azure'):
        snapshot = role_snapshot(scenario, size, 24)
    elif scenario in ('gcp','k8s'):
        snapshot = domain_snapshot(scenario, size, 256)
    else:
        raise ValueError('supported scenario required')
    inventory, before = resources(snapshot), digest(snapshot)
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name in ('baseline','optimized')}
    for iteration in range(3):
        for name in ('baseline','optimized') if iteration % 2 == 0 else ('optimized','baseline'):
            with implementation(name == 'baseline'):
                gc.collect()
                start, cpu = time.perf_counter(), time.process_time()
                output = run_stage(snapshot, inventory)
                results[name]['seconds'].append(time.perf_counter()-start)
                results[name]['cpu_seconds'].append(time.process_time()-cpu)
                results[name]['digests'].append(digest(output))
                counts = {'findings':len(output['findings']),'nodes':len(output['graph']['nodes']),
                    'edges':len(output['graph']['edges']),'principals':len(output['principals'])}
                del output
    if memory:
        for name in ('baseline','optimized'):
            with implementation(name == 'baseline'):
                gc.collect()
                tracemalloc.start()
                output = run_stage(snapshot, inventory)
                results[name]['peak_allocated_bytes'] = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
                assert digest(output) == results[name]['digests'][0]
                del output
    for result in results.values():
        fingerprints=result.pop('digests')
        assert len(set(fingerprints))==1
        result['output_digest']=fingerprints[0]
    assert results['baseline']['output_digest']==results['optimized']['output_digest']
    assert digest(snapshot)==before
    return {**results,'scenario':scenario,'resources':len(inventory),**counts,'identical_output':True,
        'input_unchanged':True,
        'speedup':round(statistics.median(results['baseline']['seconds'])/statistics.median(results['optimized']['seconds']),2),
        'cpu_speedup':round(statistics.median(results['baseline']['cpu_seconds'])/statistics.median(results['optimized']['cpu_seconds']),2),
        'limitations':'Synthetic complete offline IAM review, graph and principal stage. Timing excludes snapshot setup, '
            'collection, native checks, other analyses and rendering. Optional traced allocations cover one complete '
            'stage, not process RSS. Reference algorithms disable only the new reuse and prepared identities.'}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario',choices=('encoded','aws','azure','gcp','k8s'),default='encoded')
    parser.add_argument('--size',type=int,default=500)
    parser.add_argument('--memory',action='store_true')
    args=parser.parse_args()
    print(json.dumps(compare(args.scenario,args.size,memory=args.memory),indent=2))
