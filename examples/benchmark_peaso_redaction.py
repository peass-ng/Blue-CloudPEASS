"""Complete retained-inventory redaction; outputs only timing/count/hash metadata."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import time


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def measure(redact, snapshot, values):
    wall, cpu = time.perf_counter(), time.process_time()
    public = redact(snapshot, values)
    return {'wall_seconds': time.perf_counter()-wall, 'cpu_seconds': time.process_time()-cpu,
        'public_sha256': hashlib.sha256(json.dumps(public, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    args = parser.parse_args()
    baseline = load(args.baseline, 'redaction_baseline')
    candidate = load(args.candidate, 'redaction_candidate')
    raw = args.snapshot.read_bytes(); snapshot = json.loads(raw)
    results = []
    for count in (0, 1, 100, 1000):
        values = ['synthetic-redaction-value-'+str(i)+'-do-not-persist' for i in range(count)]
        before = measure(baseline.redact, snapshot, values)
        after = measure(candidate.redact, snapshot, values)
        assert before['public_sha256'] == after['public_sha256']
        results.append({'values': count, 'before': before, 'after': after})
    print(json.dumps({'snapshot_input_sha256': hashlib.sha256(raw).hexdigest(),
        'collections': len(snapshot['collections']), 'resources': sum(len(c['items']) for c in snapshot['collections']),
        'results': results, 'cloud_calls': 0}, indent=2))
