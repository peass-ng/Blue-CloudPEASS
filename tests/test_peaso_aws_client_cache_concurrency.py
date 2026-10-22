"""SDK creation must not serialize unrelated native reads or response caching."""
from concurrent.futures import ThreadPoolExecutor
import threading
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("boto3")
from peaso.collectors.aws import Requests


class Session:
    def __init__(self, create=None):
        self.calls = []
        self.create = create

    def client(self, service, **kwargs):
        self.calls.append((service, kwargs))
        if self.create:
            return self.create(service, kwargs)
        return SimpleNamespace(service=service, **kwargs)


def test_cold_client_does_not_block_warm_client_or_request_budget_lock():
    started, release = threading.Event(), threading.Event()

    def create(service, kwargs):
        if service == "ec2":
            started.set()
            assert release.wait(5)
        return SimpleNamespace(service=service, **kwargs)

    requests, session = Requests({}), Session(create)
    warm = requests.client(session, "iam", "us-east-1")

    def bookkeeping():
        with requests._lock:
            return requests.calls

    with ThreadPoolExecutor(max_workers=3) as pool:
        cold = pool.submit(requests.client, session, "ec2", "eu-west-1")
        try:
            assert started.wait(5)
            assert pool.submit(requests.client, session, "iam", "us-east-1").result(timeout=1) is warm
            assert pool.submit(bookkeeping).result(timeout=1) == 0
        finally:
            release.set()
        cold.result(timeout=5)


def test_same_session_creates_each_key_once_and_serializes_sdk_state():
    active = peak = 0
    lock = threading.Lock()

    def create(service, kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(.01)
            return SimpleNamespace(service=service, **kwargs)
        finally:
            with lock:
                active -= 1

    requests, session = Requests({}), Session(create)
    services = ["ec2", "iam", "s3"] * 4
    with ThreadPoolExecutor(max_workers=12) as pool:
        clients = list(pool.map(lambda service: requests.client(session, service, "us-east-1"), services))
    assert len(session.calls) == 3
    assert peak == 1
    for service in set(services):
        assert len({id(client) for client in clients if client.service == service}) == 1


def test_independent_sessions_create_clients_concurrently():
    barrier = threading.Barrier(2)

    def create(service, kwargs):
        barrier.wait(timeout=5)
        return object()

    requests = Requests({})
    sessions = [Session(create), Session(create)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        clients = list(pool.map(lambda session: requests.client(session, "iam", "us-east-1"), sessions))
    assert clients[0] is not clients[1]
    assert [len(session.calls) for session in sessions] == [1, 1]


def test_failed_creation_can_retry_without_poisoning_other_clients():
    attempts = 0

    def create(service, kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("synthetic SDK construction failure")
        return object()

    requests, session = Requests({}), Session(create)
    with pytest.raises(RuntimeError, match="synthetic SDK"):
        requests.client(session, "iam", "us-east-1")
    client = requests.client(session, "iam", "us-east-1")
    assert requests.client(session, "iam", "us-east-1") is client
    assert attempts == 2


@pytest.mark.parametrize("profile", [None, "aws-lambda-environment-content-v1", "aws-selected-configuration-content-v1"])
def test_profile_region_and_session_isolation_preserves_transport_config(profile):
    requests = Requests({"service_concurrency": 3, "connect_timeout": 8, "read_timeout": 25})
    session, other = Session(), Session()
    client = requests.client(session, "lambda", "us-east-1", _metadata_profile=profile)
    assert requests.client(session, "lambda", "us-east-1", _metadata_profile=profile) is client
    assert requests.client(other, "lambda", "us-east-1", _metadata_profile=profile) is not client
    assert requests.client(session, "lambda", "eu-west-1", _metadata_profile=profile) is not client
    if profile:
        assert requests.client(session, "lambda", "us-east-1") is not client
    config = client.config
    assert config.max_pool_connections == 3
    assert config.retries == {"total_max_attempts": 1, "mode": "standard"}
    assert (config.connect_timeout, config.read_timeout) == ((3, 5) if profile else (8, 25))
    if profile == "aws-selected-configuration-content-v1":
        assert config.ignore_configured_endpoint_urls is True
        assert config.use_fips_endpoint is False
        assert config.use_dualstack_endpoint is False


def test_s3_bootstrap_profile_is_separate_from_normal_sts_client():
    requests, session = Requests({}), Session()
    normal = requests.client(session, "sts", "us-east-1")
    requests.content_secret_scans = True
    requests.content_secret_scan_kinds = {"s3_selected_source_content"}
    bootstrap = requests.client(session, "sts", "us-east-1")
    assert bootstrap is not normal
    assert requests.client(session, "sts", "us-east-1") is bootstrap
    assert (bootstrap.config.connect_timeout, bootstrap.config.read_timeout) == (3, 5)
    assert bootstrap.config.ignore_configured_endpoint_urls is True
