"""Fresh-process offline analysis tasks, including their import costs.

python -m examples.benchmark_peaso_analysis_startup --reference-root /path/to/predecessor
The reference must be an unchanged checkout containing the same workflow fixture.
"""
import argparse
import json
from pathlib import Path
import statistics
import subprocess
import sys

CHILD = r'''
import os,sys,json,time,resource
sys.path.insert(0,os.getcwd())
start,cpu=time.perf_counter(),time.process_time()
import peaso.analysis as analysis
output={}
if sys.argv[1]=='workflows':
    from examples.benchmark_peaso_stable_ids import workload
    from peaso.snapshot import resources,digest
    for stage in ('iam','network'):
        snapshot,run=workload(stage,int(sys.argv[2]))
        before=digest(snapshot)
        value=run(snapshot,resources(snapshot))
        assert digest(snapshot)==before
        output[stage]={'digest':digest(value),'findings':len(value['findings']),
            'nodes':len(value['graph']['nodes']),'edges':len(value['graph']['edges']),
            'principals':len(value['principals'])}
result={'seconds':time.perf_counter()-start,'cpu_seconds':time.process_time()-cpu,
    'peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024),
    'output':output,'native_registry_loaded':'peaso.checks' in sys.modules,
    'analysis_catalog_loaded':'peaso.analysis.catalog' in sys.modules,
    'public_exports':analysis.__all__}
print(json.dumps(result))
'''


def compare(reference_root, *, task='workflows', size=32, repeats=1):
    current = Path(__file__).resolve().parents[1]
    roots = {'baseline': Path(reference_root).resolve(), 'optimized': current}
    if roots['baseline'] == current or size < 1 or repeats < 1:
        raise ValueError('separate reference checkout and positive sizes required')
    results = {name: [] for name in roots}
    for iteration in range(repeats):
        for name in ('baseline','optimized') if iteration % 2 == 0 else ('optimized','baseline'):
            result = subprocess.run([sys.executable, '-c', CHILD, task, str(size)], cwd=roots[name],
                capture_output=True, text=True, check=True)
            results[name].append(json.loads(result.stdout))
    expected = results['baseline'][0]
    for runs in results.values():
        for result in runs:
            assert result['output'] == expected['output']
            assert result['public_exports'] == expected['public_exports']
    return {**results,'task':task,'size':size,'identical_output':True,
        'cpu_speedup':round(statistics.median(row['cpu_seconds'] for row in results['baseline']) /
                            statistics.median(row['cpu_seconds'] for row in results['optimized']),2),
        'limitations':'Fresh-process offline IAM/network tasks include fixture construction, imports and projections. '
            'Native execution, cloud collection and hosted scan scheduling are excluded. RSS is the process high-water mark. '
            'A native scan that needs the catalog still initializes and validates that catalog.'}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-root',required=True)
    parser.add_argument('--task',choices=('import','workflows'),default='workflows')
    parser.add_argument('--size',type=int,default=32)
    parser.add_argument('--repeats',type=int,default=1)
    args=parser.parse_args()
    print(json.dumps(compare(args.reference_root,task=args.task,size=args.size,repeats=args.repeats),indent=2))
