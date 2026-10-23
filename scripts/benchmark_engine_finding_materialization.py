"""Compare complete registered engine evaluations and exact serialized reports.

Synthetic offline input; native admission and predicates run normally. Supply a
reviewed predecessor engine.py. No collector or cloud calls are made. Timed
samples exclude registry setup, fixture construction, serialization and GC.
Use --variant in separate fresh processes for whole-process peak RSS readings.
"""
import argparse
import gc
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import resource
import sys
import time
from peaso import engine
from peaso.snapshot import digest, make_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--scopes', type=int, default=100)
    parser.add_argument('--variant', choices=['baseline', 'candidate'])
    args = parser.parse_args()
    if args.scopes < 1:
        parser.error('positive scope count required')
    setup = time.process_time()
    module_name = 'peaso._finding_materialization_predecessor'
    spec = importlib.util.spec_from_file_location(module_name, args.baseline)
    baseline = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = baseline
    spec.loader.exec_module(baseline)
    # Normal native admission executes before timed samples for both variants.
    engine._registry()
    collections, scopes = [], []
    for number in range(args.scopes):
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
    setup_cpu = time.process_time() - setup
    categories = ['hardening', 'encryption', 'identity', 'logging', 'monitoring', 'backup']
    modules = {'baseline': baseline, 'candidate': engine}
    results = {'baseline': [], 'candidate': []}
    reference = None
    output_hash = None
    if args.variant is None:
        reference = baseline.evaluate_snapshot(snapshot, categories=categories)
        reference = json.dumps(reference, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
        order = ['candidate', 'baseline', 'baseline', 'candidate']
    else:
        order = [args.variant]
    for name in order:
        gc.collect()
        cpu, wall = time.process_time(), time.perf_counter()
        report = modules[name].evaluate_snapshot(snapshot, categories=categories)
        sample = {'cpu_seconds': time.process_time() - cpu, 'wall_seconds': time.perf_counter() - wall}
        results[name].append(sample)
        raw = json.dumps(report, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
        if reference is not None:
            assert raw == reference
        output_hash = hashlib.sha256(raw).hexdigest()
        stats = report['stats']
        del report, raw
    assert digest(snapshot) == before
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rss_bytes = peak if sys.platform == 'darwin' else peak * 1024
    print(json.dumps({'synthetic_only': True, 'cloud_calls': 0, 'normal_native_admission': True,
        'candidate_module': str(Path(engine.__file__).resolve()),
        'candidate_engine_sha256': hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest(),
        'baseline_engine_sha256': hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
        'python': platform.python_version(), 'platform': platform.platform(),
        'resources': stats['resource_count'], 'findings': stats['finding_count'], 'scopes': args.scopes,
        'categories': categories, 'input_unchanged': True, 'report_sha256': output_hash,
        'all_report_bytes_equal': reference is not None, 'variant': args.variant,
        'setup_cpu_seconds': setup_cpu, 'whole_process_peak_rss_bytes': rss_bytes,
        'measurements': results,
        'limitations': 'Synthetic complete native evaluation; excludes cloud collection, graph categories and report publication. Shared-host wall time varies. Peak RSS belongs to this whole process, not each timed sample.'}, indent=2), flush=True)


if __name__ == '__main__':
    main()
