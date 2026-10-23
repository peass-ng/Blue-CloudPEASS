"""Complete HTTP graph-query parity against an explicit predecessor app source."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
import tracemalloc
from fastapi.testclient import TestClient
from peaso.auth import Identity
from peaso.server.config import Settings
from examples.benchmark_peaso_privesc_pages import fixture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--rows', type=int, default=50000)
    args = parser.parse_args()
    scan = '1' * 32
    graph = fixture(args.rows)
    class Users:
        def authenticate(self, header):
            return Identity('alice')
    class Store:
        def job(self, tenant, ident):
            assert tenant == 'alice' and ident == scan
            return {'id': ident, 'status': 'completed', 'report': 'manifest'}
        def public_job(self, row):
            return {'runtime': {}}
    class Artifacts:
        def get(self, tenant, reference):
            assert tenant == 'alice'
            if reference == 'graph':
                return copy.deepcopy(graph)
            assert reference == 'manifest'
            return {'bundle_version': 1, 'summary': {'provider': 'aws'}, 'graphs': {'privesc': 'graph'}, 'finding_chunks': []}
    clients, roots, output, expected = {}, [], {}, {}
    try:
        for name, path in [('baseline', args.baseline), ('candidate', Path(__file__).resolve().parents[1] / 'peaso/server/app.py')]:
            module_name = 'peaso.server._page_benchmark_' + name
            spec = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            root = tempfile.TemporaryDirectory()
            roots.append(root)
            settings = Settings(state_dir=Path(root.name) / 'state', identity_dir=Path(root.name) / 'identity')
            client = TestClient(module.create_app(settings, store=Store(), authenticator=Users(), artifacts=Artifacts()), base_url="http://127.0.0.1:8000")
            clients[name] = client
            for route in ['admins', 'broad']:
                response = client.get(f'/api/scans/{scan}/privesc/{route}?limit=100', headers={'Authorization': 'Bearer alice'})
                assert response.status_code == 200, response.text
                if name == 'baseline':
                    expected[route] = response.content
                else:
                    assert response.content == expected[route]
        for route in expected:
            output[route] = {}
            cpu, wall = {k: [] for k in clients}, {k: [] for k in clients}
            def request(name):
                response = clients[name].get(f'/api/scans/{scan}/privesc/{route}?limit=100', headers={'Authorization': 'Bearer alice'})
                assert response.status_code == 200 and response.content == expected[route]
            for name in ['baseline', 'candidate', 'candidate', 'baseline'] * 2:
                started_cpu, started_wall = time.process_time(), time.perf_counter()
                request(name)
                cpu[name].append(time.process_time() - started_cpu)
                wall[name].append(time.perf_counter() - started_wall)
            for name in clients:
                tracemalloc.start()
                request(name)
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                output[route][name] = {'cpu_seconds': statistics.median(cpu[name]), 'wall_seconds': statistics.median(wall[name]), 'peak_allocated_bytes': peak}
        print(json.dumps(output, indent=2))
    finally:
        for client in clients.values():
            client.close()
        for root in roots:
            root.cleanup()


if __name__ == '__main__':
    main()
