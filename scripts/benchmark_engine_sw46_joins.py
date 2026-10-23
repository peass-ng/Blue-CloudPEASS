"""Fresh-process complete registered engine replay for a strict SW46 successor.

Only check_meta.*.clarity_evaluation_contract may be normalized for comparison,
which records the intentionally changed native source. All verdict/evidence,
resource, coverage, metadata and list order bytes must otherwise be identical.
"""
import argparse
import gc
import hashlib
import json
import marshal
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time
import types


def child(root, scopes_count, variant):
    from peaso import engine
    from peaso.checks import CHECKS
    from peaso.snapshot import digest, make_snapshot
    assert Path(engine.__file__).resolve().is_relative_to(root.resolve())
    module = sys.modules['peaso.checks._bulk_pending_compliance_new_sw46']
    path = Path(module.__file__)
    assert path.resolve().is_relative_to(root.resolve())
    compiled = compile(path.read_text(), str(path), 'exec', dont_inherit=True)
    definitions = {code.co_name: code for code in compiled.co_consts if isinstance(code, types.CodeType)}
    for name in ('_items', '_resource'):
        assert marshal.dumps(getattr(module, name).__code__) == marshal.dumps(definitions[name]), name
    check = next(c for c in CHECKS if c.id == 'aws_ec2_instance_time_offset_monitored')
    callback, seen = check.evaluate, set()
    while callback is not None and id(callback) not in seen:
        seen.add(id(callback))
        if callback.__globals__ is module.__dict__:
            break
        callback = getattr(callback, '__wrapped__', None)
    assert callback is not None and callback.__globals__ is module.__dict__
    collections, scopes = [], []
    for number in range(scopes_count):
        scope = f'{111111111111 + number}/us-east-1'
        scopes.append(scope)
        for kind, service, rows in [
            ('instance', 'ec2', [{'InstanceId': f'i-{i:016x}', 'State': {'Name': 'running'},
                'MetadataOptions': {'HttpEndpoint': 'enabled', 'HttpTokens': 'required' if i % 2 else 'optional'}} for i in range(100)]),
            ('bucket', 's3', [{'Name': f'synthetic-{number}-{i}'} for i in range(10)]),
            ('security_group', 'ec2', [{'GroupId': f'sg-{i:016x}', 'VpcId': 'vpc-synthetic', 'IpPermissions': []} for i in range(10)])]:
            collections.append({'type': kind, 'scope': scope, 'service': service, 'status': 'collected', 'items': rows})
    snapshot = make_snapshot('aws', scopes, collections, created_at='2026-10-22T00:00:00+00:00', metadata={'synthetic': True})
    before = digest(snapshot)
    categories = ['hardening', 'encryption', 'identity', 'logging', 'monitoring', 'backup']
    report = engine.evaluate_snapshot(snapshot, categories=categories)
    del report
    gc.collect()
    cpu, wall = time.process_time(), time.perf_counter()
    report = engine.evaluate_snapshot(snapshot, categories=categories)
    cpu, wall = time.process_time() - cpu, time.perf_counter() - wall
    raw = json.dumps(report, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
    raw_hash = hashlib.sha256(raw).hexdigest()
    values, normalized_count = set(), 0
    for fields in report.get('check_meta', {}).values():
        if 'clarity_evaluation_contract' in fields:
            values.add(fields['clarity_evaluation_contract'])
            fields['clarity_evaluation_contract'] = 'SOURCE_CONTRACT_ONLY_NORMALIZED'
            normalized_count += 1
    normalized = json.dumps(report, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
    assert digest(snapshot) == before
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {'variant': variant, 'synthetic_only': True, 'cloud_calls': 0,
        'normal_native_admission': True, 'module_namespace': module.__name__, 'registered_callback_namespace_verified': True,
        'helper_code_matches_actual_source': True, 'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'engine_sha256': hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest(),
        'resources': report['stats']['resource_count'], 'findings': report['stats']['finding_count'], 'scopes': scopes_count,
        'categories': categories, 'by_status': report['stats']['by_status'], 'input_unchanged': True,
        'raw_report_sha256': raw_hash, 'normalized_report_sha256': hashlib.sha256(normalized).hexdigest(),
        'normalized_field': 'check_meta.*.clarity_evaluation_contract', 'normalized_field_count': normalized_count,
        'source_contract_values': sorted(values), 'cpu_seconds': cpu, 'wall_seconds': wall,
        'whole_process_peak_rss_bytes': peak if sys.platform == 'darwin' else peak * 1024,
        'python': platform.python_version(), 'platform': platform.platform()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-root', type=Path)
    parser.add_argument('--candidate-root', type=Path)
    parser.add_argument('--scopes', type=int, default=100)
    parser.add_argument('--samples', type=int, default=2)
    parser.add_argument('--child-root', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--variant', choices=['baseline', 'candidate'], help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.scopes < 1 or args.samples < 1:
        parser.error('positive scopes/samples required')
    if args.child_root:
        print(json.dumps(child(args.child_root, args.scopes, args.variant)), flush=True)
        return
    if not args.baseline_root or not args.candidate_root:
        parser.error('--baseline-root and --candidate-root required')
    roots = {'baseline': args.baseline_root.resolve(), 'candidate': args.candidate_root.resolve()}
    rows = []
    for cycle in range(args.samples):
        for name in (('baseline', 'candidate') if cycle % 2 == 0 else ('candidate', 'baseline')):
            env = dict(os.environ, PYTHONPATH=str(roots[name]))
            result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--child-root', str(roots[name]),
                '--variant', name, '--scopes', str(args.scopes)], cwd=roots[name], env=env, capture_output=True, text=True, check=True)
            rows.append(json.loads(result.stdout))
    assert len({row['normalized_report_sha256'] for row in rows}) == 1
    assert len({(row['resources'], row['findings'], row['normalized_field_count']) for row in rows}) == 1
    print(json.dumps({'whole_normalized_report_bytes_equal': True, 'measurements': rows,
        'limitations': 'Synthetic complete registered native evaluation, no cloud collection, graph categories or publication. Only the stated source-contract field is normalized. Each RSS value belongs to a fresh full process including native startup and serialization.'}, indent=2), flush=True)


if __name__ == '__main__':
    main()
