"""Actual local polling reads; fixture setup excluded, no cloud calls."""
import json
from pathlib import Path
import statistics
import tempfile
import time
import tracemalloc
from peaso.storage import SQLiteStore


def main():
    with tempfile.TemporaryDirectory() as root:
        store = SQLiteStore(Path(root))
        connector = store.add_connector('fixture', {'provider': 'aws'}, 'encrypted-fixture')
        job = store.enqueue('fixture', {'connector_id': connector['id']})
        with store.connect() as db:
            db.execute('UPDATE jobs SET data=?, connector=? WHERE id=?',
                       ('x' * 128_000, 'y' * 128_000, job['id']))
        expected = store.job('fixture', job['id'])['status']
        results = {}
        methods = {'full': store.job, 'control': store.job_control}
        times, walls = {name: [] for name in methods}, {name: [] for name in methods}
        for name in ['full', 'control', 'control', 'full'] * 2:
            cpu, wall = time.process_time(), time.perf_counter()
            for _ in range(300):
                assert methods[name]('fixture', job['id'])['status'] == expected
            times[name].append(time.process_time() - cpu)
            walls[name].append(time.perf_counter() - wall)
        for name, read in methods.items():
            tracemalloc.start()
            for _ in range(10):
                read('fixture', job['id'])
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            results[name] = {'cpu_seconds': statistics.median(times[name]),
                'wall_seconds': statistics.median(walls[name]), 'peak_allocated_bytes': peak}
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
