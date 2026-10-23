"""Complete identity and workload projection stages with original join loops.

python -m examples.benchmark_peaso_principal_workflows --scenario aws --size 1000 --memory
References retain current-main GCP workload indexes and restore only new joins.
"""
import argparse
from contextlib import contextmanager,ExitStack
import gc
import json
import statistics
import time
import tracemalloc
from unittest.mock import patch

from examples.benchmark_peaso_alb_workloads import synthetic_snapshot as alb_snapshot
from examples.benchmark_peaso_azure_federation import synthetic_snapshot as federation_snapshot, run_stage as federation_stage, LinearFederation
from examples.benchmark_peaso_cloud_workloads import synthetic_snapshot as cloud_snapshot
from examples.benchmark_peaso_gcp_lb_workloads import synthetic_snapshot as gcp_network_snapshot, run_stage as gcp_network_stage
from examples.benchmark_peaso_iam_action_profiles import run_stage
from examples.benchmark_peaso_k8s_impersonation import synthetic_snapshot as impersonation_snapshot, LinearAccounts
from examples.benchmark_peaso_k8s_workloads import synthetic_snapshot as k8s_snapshot, LinearK8sWorkloads
from examples.benchmark_peaso_principal_joins import synthetic_snapshot as scope_snapshot
from examples.benchmark_peaso_trust_domains import gcp_snapshot as shared_snapshot
from examples.reference_peaso_ordered_matches import OriginalOrderedMatchIndex
from peaso.analysis import azure_federation_index,cloud_workload_index,evidence_accumulator,k8s_impersonation_index,k8s_workload_index
from peaso.snapshot import resources,digest

IndexedCloudWorkloads=cloud_workload_index.CloudWorkloadIndex


class FormerCloudWorkloads:
    """Existing GCP workload joins stay indexed; new joins use original rows."""
    def __init__(self,by_type):
        self.by_type=by_type
        self.existing=IndexedCloudWorkloads(by_type)

    def candidates(self,kind,field,values,**options):
        if field in {'gcp_backend_path','gcp_running_instance_path'}:
            return self.existing.candidates(kind,field,values,**options)
        return self.by_type[kind]


class LiteralEvidence:
    def append(self,rows,item,kind):
        if item not in rows:
            rows.append(item)


@contextmanager
def implementation(baseline):
    with ExitStack() as stack:
        if baseline:
            for owner,name,value in ((cloud_workload_index,'CloudWorkloadIndex',FormerCloudWorkloads),
                    (cloud_workload_index,'OrderedMatchIndex',OriginalOrderedMatchIndex),
                    (k8s_workload_index,'K8sWorkloadIndex',LinearK8sWorkloads),
                    (k8s_impersonation_index,'K8sImpersonationIndex',LinearAccounts),
                    (azure_federation_index,'AzureFederationIndex',LinearFederation),
                    (evidence_accumulator,'EvidenceAccumulator',LiteralEvidence)):
                stack.enter_context(patch.object(owner,name,value))
        yield


def fixture(scenario,size):
    if scenario in {'aws','azure'}:
        return cloud_snapshot(scenario,size),run_stage
    if scenario=='alb':
        return alb_snapshot(size),run_stage
    if scenario=='k8s':
        return k8s_snapshot(size),run_stage
    if scenario=='gcp_existing':
        return gcp_network_snapshot(size),gcp_network_stage
    if scenario=='gcp_scope':
        return scope_snapshot('gcp',size),run_stage
    if scenario=='azure_federation':
        return federation_snapshot(size),federation_stage
    if scenario=='k8s_impersonation':
        return impersonation_snapshot(size,'shared'),run_stage
    if scenario=='shared_evidence':
        return shared_snapshot(size,64),run_stage
    raise ValueError('supported scenario required')


def compare(scenario='aws',size=1000,*,memory=False):
    snapshot,stage=fixture(scenario,size)
    inventory,before=resources(snapshot),digest(snapshot)
    results={name:{'seconds':[],'cpu_seconds':[],'digests':[]} for name in ('baseline','optimized')}
    for iteration in range(3):
        for name in ('baseline','optimized') if iteration%2==0 else ('optimized','baseline'):
            with implementation(name=='baseline'):
                gc.collect()
                start,cpu=time.perf_counter(),time.process_time()
                output=stage(snapshot,inventory)
                results[name]['seconds'].append(time.perf_counter()-start)
                results[name]['cpu_seconds'].append(time.process_time()-cpu)
                results[name]['digests'].append(digest(output))
                counts={'findings':len(output['findings']),'nodes':len(output['graph']['nodes']),
                    'edges':len(output['graph']['edges']),'principals':len(output['principals']),
                    'signals':sum(len(card['exposures']) for card in output['principals'].values()),
                    'grant_reviews':sum(len(card['grant_reviews']) for card in output['principals'].values())}
                assert counts['principals']>0
                assert (counts['grant_reviews'] if scenario=='shared_evidence' else counts['signals'])>=size
                del output
    if memory:
        for name in ('baseline','optimized'):
            with implementation(name=='baseline'):
                gc.collect()
                tracemalloc.start()
                output=stage(snapshot,inventory)
                results[name]['peak_allocated_bytes']=tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
                assert digest(output)==results[name]['digests'][0]
                del output
    for result in results.values():
        fingerprints=result.pop('digests')
        assert len(set(fingerprints))==1
        result['output_digest']=fingerprints[0]
    assert results['baseline']['output_digest']==results['optimized']['output_digest']
    assert digest(snapshot)==before
    return {**results,'scenario':scenario,'size':size,'resources':len(inventory),**counts,
        'identical_output':True,'input_unchanged':True,
        'speedup':round(statistics.median(results['baseline']['seconds'])/statistics.median(results['optimized']['seconds']),2),
        'cpu_speedup':round(statistics.median(results['baseline']['cpu_seconds'])/statistics.median(results['optimized']['cpu_seconds']),2),
        'limitations':'Complete synthetic offline IAM review, IAM graph and principal/workload projection. '
            'Azure federation also includes federation findings. Reference restores original new-join loops, '
            'evidence membership and posting storage while retaining prior IAM reuse and existing GCP joins. '
            'Collection, native checks, other analyses and rendering are excluded. Optional peaks are traced stage allocations, not process RSS.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario',choices=('aws','azure','alb','k8s','gcp_scope','gcp_existing','azure_federation','k8s_impersonation','shared_evidence'),default='aws')
    parser.add_argument('--size',type=int,default=1000)
    parser.add_argument('--memory',action='store_true')
    args=parser.parse_args()
    print(json.dumps(compare(args.scenario,args.size,memory=args.memory),indent=2))
