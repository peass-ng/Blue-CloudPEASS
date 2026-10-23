"""Offline SDK, connection-pool, download and history workflow comparisons."""
import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import statistics
import tempfile
import threading
import time

from examples.benchmark_peaso_alternative_optimizations import measure, original


def sdk_workspaces(revision):
    import boto3
    import moto
    from peaso.storage import dynamodb
    old = original(revision, 'peaso/storage/dynamodb.py', 'DynamoStore', dynamodb)
    with moto.mock_aws():
        client = boto3.client('dynamodb', region_name='us-east-1')
        client.create_table(TableName='offline', BillingMode='PAY_PER_REQUEST',
            KeySchema=[{'AttributeName': 'PK', 'KeyType': 'HASH'}, {'AttributeName': 'SK', 'KeyType': 'RANGE'}],
            AttributeDefinitions=[{'AttributeName': name, 'AttributeType': 'S'} for name in ('PK', 'SK')])
        store = dynamodb.DynamoStore('offline', client)
        for index in range(5):
            store.create_workspace('owner', f'Workspace {index}', f'workspace-{index}', 'owner@example.invalid')
        counts = []
        active = [0]
        client.meta.events.register('before-call.dynamodb', lambda **_: active.__setitem__(0, active[0] + 1))

        def replay(cls):
            active[0] = 0
            value = cls('offline', client).workspaces('owner')
            counts.append(active[0])
            return value

        before, old_stats = measure(lambda: replay(old))
        old_count = counts[-1]
        after, new_stats = measure(lambda: replay(dynamodb.DynamoStore))
        assert before == after
        return {'baseline': old_stats, 'optimized': new_stats,
                'requests': [old_count, counts[-1]], 'equal_output': True,
                'transport': 'real botocore pipeline with in-process moto service'}


def connection_pool():
    import requests
    connections = [0]

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def setup(self):
            super().setup()
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connections[0] += 1
            time.sleep(0.01)  # Declared setup latency; this is not a TLS benchmark.

        def log_message(self, *args):
            pass

        def do_GET(self):
            body = b'{"entries":[]}'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}/'
    counts = []

    def replay(reuse):
        before = connections[0]
        with requests.Session() as session:
            for _ in range(20):
                with (session.get(url, timeout=5) if reuse else requests.get(url, timeout=5)) as response:
                    value = response.json()
        counts.append(connections[0] - before)
        return value

    try:
        before, old_stats = measure(lambda: replay(False))
        old_count = counts[-1]
        after, new_stats = measure(lambda: replay(True))
        assert before == after
        return {'baseline': old_stats, 'optimized': new_stats,
                'connections': [old_count, counts[-1]], 'equal_output': True,
                'transport': 'loopback HTTP/1.1, 20 reads, 10 ms synthetic connection setup'}
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def local_downloads(revision):
    from fastapi import HTTPException
    from fastapi.testclient import TestClient
    from peaso.auth import Identity
    from peaso.server import app as application
    from peaso.server.config import Settings
    from peaso.storage import FileArtifacts, SQLiteStore
    from examples.benchmark_peaso_publication import synthetic_report
    old = original(revision, 'peaso/server/app.py', 'create_app', application)

    class Authentication:
        def authenticate(self, authorization):
            if authorization != 'Bearer offline':
                raise HTTPException(401)
            return Identity('offline')

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        store, artifacts = SQLiteStore(root / 'state'), FileArtifacts(root / 'artifacts')
        connector = store.add_connector('offline', {'provider': 'gcp', 'name': 'Offline'}, 'sealed')
        job = store.enqueue('offline', {'connector_id': connector['id']})
        report = synthetic_report(10000)
        reference = artifacts.put('offline', job['id'], 'report', report)
        with store.transaction() as db:
            db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?", (reference, job['id']))
        settings = Settings(state_dir=root / 'settings', identity_dir=root / 'identity')
        results, outputs = {}, []
        for name, factory in [('baseline', old), ('optimized', application.create_app)]:
            app = factory(settings, store=store, artifacts=artifacts, authenticator=Authentication())
            with TestClient(app, base_url='http://127.0.0.1:8000', headers={'Authorization': 'Bearer offline'}) as client:
                path = f"/api/scans/{job['id']}/report?aggregation=check"
                assert client.get(path).status_code == 200  # Warm only the immutable grouped reference.

                def download():
                    response = client.get(path)
                    assert response.status_code == 200
                    assert 'attachment;' in response.headers['content-disposition']
                    return response.content

                body, results[name] = measure(download)
                outputs.append(json.loads(body))
        assert outputs[0] == outputs[1]
        return dict(results, equal_output=True, workload='10,000 findings; legacy local grouped download; warm group reference')


def history_commit(revision):
    from peaso.storage import attack_history_sqlite as storage
    from peaso.storage import attack_history_ledger as ledger
    from tests.test_attack_history_ledger import history_job, fixed_manifest, finding
    from peaso.auth.secrets import CredentialCipher
    import hashlib
    old_store = original(revision, 'peaso/storage/attack_history_sqlite.py', 'SQLiteAttackHistoryStore', storage)
    old_ledger = original(revision, 'peaso/storage/attack_history_ledger.py', 'LocalAttackHistoryLedger', ledger)
    results, outputs = {}, []
    for name, cls, reader in [('baseline', old_store, old_ledger), ('optimized', storage.SQLiteAttackHistoryStore, ledger.LocalAttackHistoryLedger)]:
        lock_wall, lock_cpu = [], []

        def replay():
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                db = cls(root, CredentialCipher(root / 'identity'))
                db.ledger = reader(root / 'attack_history_ledger')
                job = history_job(db)
                generation = db.claim_job('tenant-a', job, 'worker-a', lease_seconds=3600, now=1792454399)
                manifest = fixed_manifest(listed='2026-10-19T00:00:00+00:00')
                db.register_cloudtrail_first_manifest('tenant-a', job, 'worker-a', generation, 'main', manifest, now=1792454400)
                hashes = [(f'event-{i}', hashlib.sha256(str(i).encode()).hexdigest()) for i in range(1000)]
                chunks = db.ledger.put_finding_chunks('tenant-a', job, (finding(i) for i in range(1000)))
                checkpoint = db.ledger.put_object_checkpoint('tenant-a', job, 'main', manifest.objects[0], 'c' * 64, hashes, chunks)
                transaction = db._transaction

                @contextmanager
                def timed_transaction():
                    with transaction() as connection:
                        start, cpu = time.perf_counter(), time.process_time()
                        yield connection
                        lock_wall.append(time.perf_counter() - start)
                        lock_cpu.append(time.process_time() - cpu)

                db._transaction = timed_transaction
                db.commit_cloudtrail_object('tenant-a', job, 'worker-a', generation, 'main', manifest.objects[0],
                                           'c' * 64, hashes, checkpoint, now=1792454401)
                with db._connect() as connection:
                    return tuple(connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0] for table in
                                 ('attack_cloudtrail_objects', 'attack_cloudtrail_events', 'attack_cloudtrail_chunks'))

        output, stats = measure(replay)
        outputs.append(output)
        results[name] = dict(stats, writer_body_wall_seconds=statistics.median(lock_wall[:3]),
                            writer_body_cpu_seconds=statistics.median(lock_cpu[:3]))
    assert outputs[0] == outputs[1] == (1, 1000, 1)
    return dict(results, equal_counts=True, workload='stage and commit one 1,000-finding CloudTrail object, FULL SQLite durability')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default='19cb2da9')
    parser.add_argument('--sections', nargs='+', default=['sdk-workspaces', 'connections', 'downloads', 'history'])
    args = parser.parse_args()
    methods = {'sdk-workspaces': lambda: sdk_workspaces(args.baseline), 'connections': connection_pool,
               'downloads': lambda: local_downloads(args.baseline), 'history': lambda: history_commit(args.baseline)}
    for section in args.sections:
        print(json.dumps({'section': section, 'results': methods[section]()}), flush=True)
