"""Group remaining native evidence work and run isolated wave tests concurrently.

No cloud operations. Each subprocess owns its pytest registry; receipts bind
the exact tested source bytes and retain failures rather than counting them as
completed checks. Default operation writes a plan only.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source_hashes():
    return {str(path.relative_to(ROOT)):digest(path) for parent in ('peaso','scripts')
            for path in sorted((ROOT/parent).rglob('*')) if path.is_file() and path.suffix in ('.py','.json','.yaml')}

def batches():
    from peaso.collectors.bulk_evidence import coverage
    contract = json.loads((ROOT/'peaso/checks/bulk_pending.json').read_text())
    unavailable = {p:set(row['unavailable_projections']) for p,row in coverage().items()}
    groups = {}
    for ident,row in contract['checks'].items():
        missing = tuple(sorted(set([row['kind'], *row['dependencies']]) & unavailable[row['provider']]))
        if not missing:
            continue
        key=(row['provider'],missing)
        group=groups.setdefault(key, {'provider':key[0], 'missing_native_projections':list(missing), 'checks':[], 'modules':set()})
        group['checks'].append(ident);group['modules'].add(row['source_module'])
    result=[]
    for group in groups.values():
        group['checks'].sort();group['modules']=sorted(group['modules'])
        group['check_count']=len(group['checks'])
        result.append(group)
    return sorted(result,key=lambda group:(-group['check_count'],group['provider'],group['missing_native_projections']))

def run_test(path, output, timeout):
    started=time.time(); before=digest(path)
    log=output/(path.stem+'.log')
    with log.open('w') as stream:
        try:
            job=subprocess.run([sys.executable,'-m','pytest','-q',str(path)], cwd=ROOT, stdout=stream,stderr=subprocess.STDOUT, timeout=timeout)
            code=job.returncode
        except subprocess.TimeoutExpired:
            code=124
    after=digest(path)
    return {'test':str(path.relative_to(ROOT)), 'sha256':before, 'unchanged_during_test':before==after,
            'returncode':code, 'passed':code==0 and before==after, 'seconds':round(time.time()-started,3),
            'log':str(log.resolve())}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--test',action='append',default=[],help='Exact test path; one independent pytest subprocess per file')
    parser.add_argument('--workers',type=int,choices=range(1,5),default=4)
    parser.add_argument('--timeout',type=int,default=600)
    args=parser.parse_args()
    if args.timeout<=0:parser.error('timeout must be positive')
    paths=[]
    for item in args.test:
        path=(ROOT/item).resolve()
        if path.parent != ROOT/'tests' or not path.name.startswith('test_') or path.suffix!='.py' or not path.is_file():
            parser.error('test must name an existing file directly inside tests/')
        if path not in paths:paths.append(path)
    args.output.mkdir(parents=True,exist_ok=True)
    # Bind the product source independently of individual test results.
    sources=source_hashes()
    plan=batches()
    receipt={'pending_checks':sum(row['check_count'] for row in plan), 'dependency_batches':plan,
             'source_sha256':sources, 'workers':args.workers, 'cloud_resources_created':0}
    (args.output/'plan.json').write_text(json.dumps(receipt,indent=2)+'\n')
    # The parent owns omitted regression inputs for the entire worker group.
    # Otherwise individual pytest sessions can race to create them, or remove
    # inputs while a sibling process still needs them.
    from tests.release_test_inputs import restore_missing_inputs
    restored = restore_missing_inputs(ROOT) if paths else []
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results=list(pool.map(lambda path:run_test(path,args.output,args.timeout),paths))
    finally:
        for path in restored:
            path.unlink(missing_ok=True)
    after=source_hashes()
    changed=sorted(name for name in sources.keys() | after.keys() if sources.get(name)!=after.get(name))
    receipt.update(tests=results,source_changed_during_tests=changed,
                   all_selected_tests_passed=bool(results) and not changed and all(row['passed'] for row in results))
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'pending_checks':receipt['pending_checks'],'dependency_batches':len(plan),
                      'tests':results,'source_changed_during_tests':changed}))
    return int(bool(changed) or any(not row['passed'] for row in results))

if __name__=='__main__':raise SystemExit(main())
