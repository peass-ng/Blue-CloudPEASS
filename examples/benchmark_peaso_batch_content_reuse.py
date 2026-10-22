"""Real pinned dual-engine batch replay with exact public/private parity.

Duplicate and unique payload fixtures keep the same original source count and
paths. Only counts, timings and hashes leave the process; no token/plaintext
private evidence is printed. Uses volatile tmpfs, no cloud calls or verification.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import sys
import time

from peaso import secret_scanning as scanning, secret_evidence as evidence

TOKEN = 'ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'


def load(path):
    spec = importlib.util.spec_from_file_location('peaso.secret_scanning_batch', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def cpu():
    used = resource.getrusage(resource.RUSAGE_CHILDREN)
    return time.process_time()+used.ru_utime+used.ru_stime


def replay(module, items):
    scanning.prepared_content_batch = module.prepared_content_batch
    scanning._prepared_trufflehog_output = module.prepared_output
    original = scanning._run
    staged = []

    def run(argv, *args):
        if 'filesystem' in argv:
            paths = [Path(arg) for arg in argv if arg.startswith('/dev/shm/peaso-scan-')]
            staged.append(dict(files=len(paths), bytes=sum(path.stat().st_size for path in paths)))
        return original(argv, *args)

    scanning._run = run
    scanning._RESULTS.clear()
    cipher = evidence.EphemeralCipher()
    wall, used = time.perf_counter(), cpu()
    try:
        with evidence.capture(cipher, tenant='offline', scan_id='a'*32) as sink:
            with module.prepared_content_batch(items, timeout=60):
                results = []
                for index, (payload, path) in enumerate(items):
                    with evidence.source_context(resource_id=f'asset/{index}',
                        scope='fixture', path=path, location_kind='file'):
                        results.append(scanning.scan_content(payload, path))
            records = {key: cipher.decrypt(value) for key, value in sink.records.items()}
            document = sink.document()
            index = cipher.decrypt(document['index'])
            assert not sink.incomplete
        elapsed, used = time.perf_counter()-wall, cpu()-used
    finally:
        scanning._run = original
    assert all(row['complete'] and row['leaks'] for row in results)
    locations = sum(len(record['locations']) for record in records.values())
    assert locations == len(items)
    assert {loc['path'] for record in records.values() for loc in record['locations']} == {
        path for _, path in items}
    public = json.dumps(results, sort_keys=True)
    assert TOKEN not in public
    private = json.dumps(dict(records=records, index=index), sort_keys=True)
    return dict(wall_seconds=elapsed, cpu_seconds=used, staged=staged,
        original_sources=len(items), private_locations=locations,
        public_sha256=hashlib.sha256(public.encode()).hexdigest(),
        private_records_index_sha256=hashlib.sha256(private.encode()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--items', type=int, default=128)
    parser.add_argument('--kib', type=int, default=256)
    args = parser.parse_args()
    assert 1 <= args.rounds <= 5
    assert 2 <= args.items <= 128 and 1 <= args.kib <= 512
    assert args.items*args.kib <= 64*1024
    before, after = load(args.baseline), load(args.candidate)
    scanning._kingfisher()
    scanning._trufflehog()
    output = []
    for unique in (False, True):
        items = []
        for index in range(args.items):
            prefix = (f'source={index if unique else 0}\ntoken={TOKEN}\n').encode()
            filler = b'# ordinary fixture text\n'
            payload = prefix+(filler*((args.kib*1024-len(prefix))//len(filler)+1))
            items.append((payload[:args.kib*1024], f'original/{index}.txt'))
        for round_number in range(args.rounds):
            if round_number % 2:
                new, old = replay(after, items), replay(before, items)
            else:
                old, new = replay(before, items), replay(after, items)
            assert old['public_sha256'] == new['public_sha256']
            assert old['private_records_index_sha256'] == new['private_records_index_sha256']
            output.append(dict(unique_payloads=unique, round=round_number,
                before=old, after=new, exact_parity=True))
    print(json.dumps(dict(cloud_calls=0, results=output), indent=2))
