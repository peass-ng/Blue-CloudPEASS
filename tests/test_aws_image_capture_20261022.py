"""Offline concurrent ECR payload reuse, authorization boundaries and cleanup."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import threading
from types import SimpleNamespace

import pytest

from peaso.collectors import aws_image_capture_20261022 as capture
from peaso.collectors import aws_image_vulnerability_native_20261021 as native
from peaso.collectors import aws_workload_image_secret_native_20261021 as workload
from peaso.collectors import aws_package_content_indicators as package
from tests.test_aws_package_content_review_20261019 import (
    sdk, ACCOUNT, REGION, SECRET, index, FUNCTIONS)
from tests.test_aws_image_vulnerability_runtime_20261021 import scan_runner


def fixture(monkeypatch):
    requests, session, item, ops, calls, downloads, payloads = sdk(
        monkeypatch, 'ecr_repository')
    client = session.client
    def native_client(service, **kwargs):
        wrapped = client(service, **kwargs)
        class Client:
            def close(self):
                pass
            def __getattr__(self, operation):
                def invoke(**args):
                    result = getattr(wrapped, operation)(**args)
                    result['ResponseMetadata'] = {'HTTPStatusCode': 200, 'RequestId': 'synthetic-request'}
                    return result
                return invoke
            def can_paginate(self, operation):
                return False
        return Client()
    session.client = native_client
    digest = ops['batch_get_image']['images'][0]['imageId']['imageDigest']
    target = {'scope': ACCOUNT + '/' + REGION,
              'repository_name': 'example', 'image_digest': digest}
    # The existing content parser still runs; detector processes stay offline.
    from peaso import secret_scanning
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', lambda *args: [])
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', lambda *args: [])
    return requests, session, item, ops, calls, downloads, payloads, target


@pytest.mark.parametrize('order', ['concurrent', 'secret_first', 'cve_first'])
def test_exact_image_payload_once_and_scanner_parity(monkeypatch, order):
    requests, session, item, ops, calls, downloads, payloads, target = fixture(monkeypatch)
    def secret():
        return package.enrich('ecr_repository', requests, session, REGION, [item])[0]
    def cve():
        return native.collect_native(requests, session, ACCOUNT, REGION, [target],
                                     enabled=True, runner=scan_runner())
    if order == 'concurrent':
        # Force both independent scanners to reach the same config capture
        # before either can fetch it; this exercises actual single-flight.
        descriptor = package._json(ops['batch_get_image']['images'][0]['imageManifest'])['config']
        config_barrier = threading.Barrier(2)
        original = capture._Capture.blob
        def synchronized(self, *args, **kwargs):
            if args[6] == descriptor['digest']:
                config_barrier.wait(timeout=5)
            return original(self, *args, **kwargs)
        monkeypatch.setattr(capture._Capture, 'blob', synchronized)
    with capture.capture_scope(requests) as store:
        root = store.root
        if order == 'concurrent':
            barrier = threading.Barrier(2)
            def run(fn):
                barrier.wait(timeout=5)
                return fn()
            with ThreadPoolExecutor(2) as pool:
                sf, cf = pool.submit(run, secret), pool.submit(run, cve)
                secrets, cves = sf.result(timeout=30), cf.result(timeout=30)
        elif order == 'secret_first':
            secrets, cves = secret(), cve()
        else:
            cves, secrets = cve(), secret()
        assert root.stat().st_mode & 0o077 == 0
        assert len(list(root.iterdir())) == 2
        assert all(p.stat().st_mode & 0o077 == 0 for p in root.iterdir())
        assert Counter(url for url, _ in downloads) == Counter({url: 1 for url in payloads})
        manifest = package._json(ops['batch_get_image']['images'][0]['imageManifest'])
        assert Counter(args['layerDigest'] for _, op, args in calls
                       if op == 'get_download_url_for_layer') == Counter(
                           d['digest'] for d in [manifest['config'], *manifest['layers']])
        assert sum(op == 'batch_get_image' for _, op, _ in calls) >= 4
        assert FUNCTIONS['ecr_repository'](secrets, index('ecr_repository', secrets))[0] == 'FAIL'
        assert secrets['PackageContentSource']['PackageSecretIndicators']['NativeResponseComplete']
        assert cves['complete'] and cves['status'] == 'FAIL'
        safe = json.dumps([secrets, cves, [f.result() for f in requests._cache.values()]], default=str)
        assert SECRET not in safe and 'NEVERCACHEME' not in safe and str(root) not in safe
    assert not root.exists() and not hasattr(requests, '_ecr_image_capture')


@pytest.mark.parametrize('profile', ['lambda', 'ecs', 'batch'])
def test_repository_workload_and_cve_share_bytes_with_fresh_workload_binding(monkeypatch, profile):
    requests, session, item, ops, calls, downloads, payloads, target = fixture(monkeypatch)
    reference = (f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/example@'
                 + target['image_digest'])
    selected = dict(target)
    if profile == 'lambda':
        arn = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:fixture'
        selected = {'scope': target['scope'], 'function_arn': arn}
        operation = 'get_function'
        ops[operation] = {'Configuration': {'FunctionArn': arn, 'PackageType': 'Image',
            'Version': '$LATEST', 'RevisionId': 'synthetic'},
            'Code': {'ResolvedImageUri': reference}}
    elif profile == 'ecs':
        arn = f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/fixture:1'
        selected.update(task_definition_arn=arn, container_name='worker')
        operation = 'describe_task_definition'
        ops[operation] = {'taskDefinition': {'taskDefinitionArn': arn,
            'family': 'fixture', 'revision': 1, 'status': 'ACTIVE',
            'containerDefinitions': [{'name': 'worker', 'image': reference}]}}
    else:
        arn = f'arn:aws:batch:{REGION}:{ACCOUNT}:job-definition/fixture:1'
        selected.update(job_definition_arn=arn, batch_profile='container')
        operation = 'describe_job_definitions'
        ops[operation] = {'jobDefinitions': [{'jobDefinitionArn': arn,
            'jobDefinitionName': 'fixture', 'revision': 1, 'status': 'ACTIVE',
            'type': 'container', 'containerProperties': {'image': reference}}]}
    barrier = threading.Barrier(3)
    def run(fn):
        barrier.wait(timeout=5)
        return fn()
    with capture.capture_scope(requests) as store, ThreadPoolExecutor(3) as pool:
        repo = pool.submit(run, lambda: package.enrich(
            'ecr_repository', requests, session, REGION, [item])[0])
        secret = pool.submit(run, lambda: workload.collect_scope(
            requests, session, ACCOUNT, REGION, [selected], named=[workload.CHECK]))
        cve = pool.submit(run, lambda: native.collect_native(
            requests, session, ACCOUNT, REGION, [selected], enabled=True, runner=scan_runner()))
        assert repo.result(timeout=30)['PackageContentSource']['PackageSecretIndicators']['NativeResponseComplete']
        rows = secret.result(timeout=30)
        assert rows[0]['complete'] and rows[0]['binding_before'] == rows[0]['binding_after']
        assert cve.result(timeout=30)['complete']
        assert Counter(url for url, _ in downloads) == Counter({url: 1 for url in payloads})
        assert sum(op == operation for _, op, _ in calls) >= 5
    assert not store.root.exists()


def test_index_child_platform_config_and_both_scanners_use_one_capture(monkeypatch):
    from peaso import container_image_archive_20261020 as archive
    from peaso import oci_index_20261021 as oci
    requests, session, item, ops, calls, downloads, payloads, target = fixture(monkeypatch)
    leaf = ops['batch_get_image']
    child_raw = leaf['images'][0]['imageManifest'].encode()
    parent_raw = json.dumps({'schemaVersion': 2, 'mediaType': oci.OCI_INDEX,
        'manifests': [{'mediaType': package.OCI, 'digest': target['image_digest'],
            'size': len(child_raw), 'platform': {'os': 'linux', 'architecture': 'amd64'}}]}).encode()
    parent_digest = archive.sha(parent_raw)
    parent = {'images': [{'registryId': ACCOUNT, 'repositoryName': 'example',
        'imageId': {'imageDigest': parent_digest}, 'imageManifest': parent_raw.decode(),
        'imageManifestMediaType': oci.OCI_INDEX}], 'failures': []}
    ops['batch_get_image'] = lambda **args: (parent if
        args['imageIds'][0]['imageDigest'] == parent_digest else leaf)
    ops['describe_images']['imageDetails'][0]['imageDigest'] = parent_digest
    target['image_digest'] = parent_digest
    with capture.capture_scope(requests) as store, ThreadPoolExecutor(2) as pool:
        secret = pool.submit(package.enrich, 'ecr_repository', requests, session, REGION, [item])
        cve = pool.submit(native.collect_native, requests, session, ACCOUNT, REGION,
                          [target], enabled=True, runner=scan_runner())
        marker = secret.result(timeout=30)[0]['PackageContentSource']['PackageSecretIndicators']
        result = cve.result(timeout=30)
        assert marker['NativeResponseComplete'] and marker['IndexGraph']['complete']
        assert result['complete'] and result['status'] == 'FAIL'
        assert result['rows'][0]['index_graph']['complete']
        assert Counter(url for url, _ in downloads) == Counter({url: 1 for url in payloads})
    assert not store.root.exists()


def test_pinned_workload_session_shares_original_authority(monkeypatch):
    requests = SimpleNamespace(_lock=threading.RLock(), check_deadline=lambda: None)
    session = object()
    params = (requests, session, ACCOUNT, REGION, 'example', 'image', 'blob', 3)
    def load(path):
        path.write_bytes(b'abc')
        return path
    with capture.capture_scope(requests):
        first = capture.shared_blob(*params, load, None)
        pinned = workload._PinnedSession(session, object())
        assert capture.shared_blob(requests, pinned, *params[2:], load, None) == first

