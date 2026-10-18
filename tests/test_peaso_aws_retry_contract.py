"""Offline fake-client contracts; no boto session or cloud call is created."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import format_datetime

import pytest


from peaso.collectors import aws


class ProviderError(Exception):
    def __init__(self, code, *, header=None, status=429):
        super().__init__(code)
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status,
            "HTTPHeaders": {"rEtRy-AfTeR": header} if header is not None else {}}}


class FakeClient:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = 0

    def get_account_summary(self):
        self.calls += 1
        result = next(self.results)
        if isinstance(result, Exception):
            raise result
        return result


def reader(monkeypatch, results, *, attempts=2, sleep=None, deadline=None):
    client = FakeClient(results)
    monkeypatch.setattr(aws.Requests, "client", lambda self, session, service, region: client)
    options = {"retry_attempts": attempts}
    if deadline is not None:
        options["deadline_seconds"] = deadline
    waits = []
    requests = aws.Requests(options, sleep=sleep or waits.append)
    return requests, object(), client, waits


def call(requests, session):
    return requests.call(session, "iam", "us-east-1", "get_account_summary")


@pytest.mark.parametrize("header,minimum", [
    ("7", 7.0),
    ("date", 20.0),
    ("invalid", 0.2),
    (None, 0.2),
])
def test_retry_after_seconds_date_and_jitter_fallback(monkeypatch, header, minimum):
    wall = 1_700_000_000.0
    monkeypatch.setattr(aws.time, "time", lambda: wall)
    if header == "date":
        header = format_datetime(datetime.fromtimestamp(wall + 20, timezone.utc), usegmt=True)
    requests, session, client, waits = reader(monkeypatch,
        [ProviderError("Throttling", header=header), {"SummaryMap": {"Users": 1}}])
    assert call(requests, session)["SummaryMap"]["Users"] == 1
    assert client.calls == 2 and waits == [minimum]


def test_retry_after_over_60_seconds_is_honored_by_default(monkeypatch):
    requests, session, client, waits = reader(monkeypatch,
        [ProviderError("Throttling", header="70"), {"SummaryMap": {"Users": 4}}])
    assert call(requests, session) == {"SummaryMap": {"Users": 4}}
    assert client.calls == 2 and waits == [70.0]


def test_explicit_deadline_rejects_provider_wait_before_next_api_call(monkeypatch):
    requests, session, client, waits = reader(monkeypatch,
        [ProviderError("Throttling", header="7")], deadline=5)
    with pytest.raises(aws.ReadFailure) as caught:
        call(requests, session)
    assert caught.value.code == "retry_wait_exceeds_deadline"
    assert client.calls == 1 and waits == []


def test_call_budget_stops_retry_after_wait(monkeypatch):
    requests, session, client, waits = reader(monkeypatch,
        [ProviderError("Throttling", header="2")])
    requests.max_calls = 1
    with pytest.raises(aws.ReadFailure) as caught:
        call(requests, session)
    assert caught.value.code == "call_limit"
    assert client.calls == 1 and waits == [2.0]


def test_cancellation_during_default_wait_stops_retry(monkeypatch):
    cancelled = threading.Event()
    requests, session, client, _ = reader(monkeypatch,
        [ProviderError("Throttling", header="70")], sleep=time.sleep)
    requests.cancel_event = cancelled
    def cancel_wait(delay):
        assert delay == 70.0
        cancelled.set()
        return True
    monkeypatch.setattr(cancelled, "wait", cancel_wait)
    with pytest.raises(aws.ReadFailure) as caught:
        call(requests, session)
    assert caught.value.code == "collection_cancelled"
    assert client.calls == 1


def test_exhausted_throttle_gets_one_later_recovery_and_success_is_cached(monkeypatch):
    requests, session, client, _ = reader(monkeypatch,
        [ProviderError("Throttling"), {"SummaryMap": {"Users": 2}}], attempts=1)
    with pytest.raises(aws.ReadFailure) as caught:
        call(requests, session)
    assert caught.value.code == "Throttling"
    assert call(requests, session) == {"SummaryMap": {"Users": 2}}
    assert call(requests, session) == {"SummaryMap": {"Users": 2}}
    assert client.calls == 2 and requests.cache_hits == 1


def test_second_transient_failure_remains_cached_to_bound_recovery(monkeypatch):
    requests, session, client, _ = reader(monkeypatch,
        [ProviderError("Throttling"), ProviderError("Throttling")], attempts=1)
    for _ in range(3):
        with pytest.raises(aws.ReadFailure):
            call(requests, session)
    assert client.calls == 2


def test_stable_denial_is_cached(monkeypatch):
    requests, session, client, _ = reader(monkeypatch,
        [ProviderError("AccessDenied", status=403)], attempts=1)
    for _ in range(2):
        with pytest.raises(aws.ReadFailure) as caught:
            call(requests, session)
        assert caught.value.status == "denied"
    assert client.calls == 1


def test_inflight_waiters_keep_same_failed_future_then_later_call_recovers(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def first():
        entered.set()
        assert release.wait(2)
        raise ProviderError("Throttling")
    class BlockingClient:
        calls = 0
        def get_account_summary(self):
            self.calls += 1
            if self.calls == 1:
                return first()
            return {"SummaryMap": {"Users": 3}}
    client = BlockingClient()
    monkeypatch.setattr(aws.Requests, "client", lambda self, session, service, region: client)
    requests, session = aws.Requests({"retry_attempts": 1}), object()
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(call, requests, session) for _ in range(4)]
        assert entered.wait(2)
        until = time.monotonic() + 2
        while requests.cache_hits < 3 and time.monotonic() < until:
            time.sleep(0.001)
        assert requests.cache_hits == 3
        release.set()
        for future in futures:
            with pytest.raises(aws.ReadFailure) as caught:
                future.result()
            assert caught.value.code == "Throttling"
    assert client.calls == 1
    assert call(requests, session) == {"SummaryMap": {"Users": 3}}
    assert client.calls == 2
