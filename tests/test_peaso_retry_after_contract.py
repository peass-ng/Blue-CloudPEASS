"""Offline fake-clock contracts for provider-request Retry-After minima."""
from __future__ import annotations

import random
from datetime import datetime, timezone
from email.utils import format_datetime
from types import SimpleNamespace

import pytest

from peaso.collectors import azure, gcp


class Clock:
    def __init__(self):
        self.wall = 1_700_000_000.0
        self.mono = 100.0
        self.sleeps = []

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.wall += seconds
        self.mono += seconds


class Response:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}

    def json(self):
        return {"error": {"details": [{"reason": "RATE_LIMIT_EXCEEDED"}]}} if self.status_code == 429 else {"items": []}


class Throttled(Exception):
    status_code = 429

    def __init__(self, headers):
        self.headers = headers


def gcp_reader(monkeypatch, clock, header, *, deadline_seconds=None):
    monkeypatch.setattr(gcp.time, "time", clock.time)
    monkeypatch.setattr(gcp.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(random, "random", lambda: 0.0)  # minimum jitter
    options = {"retries": 1}
    if deadline_seconds is not None:
        options["deadline_seconds"] = deadline_seconds
    reader = gcp.Transport(SimpleNamespace(headers=lambda: {}, close=lambda: None), options, sleep=clock.sleep)
    calls = []
    responses = [Response(429, {"Retry-After": header} if header is not None else {}), Response(200)]

    def request(*args, **kwargs):
        calls.append(1)
        return responses[min(len(calls) - 1, 1)]

    monkeypatch.setattr(reader, "_session", lambda: SimpleNamespace(request=request))
    return reader, calls


@pytest.mark.parametrize("header,expected", [
    ("7", 7.0),
    ("date", 20.0),
    (None, 0.5),
    ("not-a-date", 0.5),
])
def test_gcp_retry_after_minimum_and_fallback(monkeypatch, header, expected):
    clock = Clock()
    if header == "date":
        header = format_datetime(datetime.fromtimestamp(clock.wall + 20, timezone.utc), usegmt=True)
    reader, calls = gcp_reader(monkeypatch, clock, header)
    result, _ = reader.request("GET", "https://compute.googleapis.com/compute/v1/projects/p/global/networks")
    assert result == {"items": []}
    assert calls == [1, 1]
    assert clock.sleeps == [expected]
    assert reader.calls == 2


@pytest.mark.parametrize("header,deadline,code", [
    ("70", None, "retry_after_exceeds_budget"),
    ("7", 5, "retry_wait_exceeds_deadline"),
])
def test_gcp_oversized_or_expired_wait_is_incomplete_without_retry(monkeypatch, header, deadline, code):
    clock = Clock()
    reader, calls = gcp_reader(monkeypatch, clock, header, deadline_seconds=deadline)
    with pytest.raises(gcp.ReadError) as caught:
        reader.request("GET", "https://compute.googleapis.com/compute/v1/projects/p/global/networks")
    assert caught.value.status == "unavailable" and caught.value.error["code"] == code
    assert calls == [1] and clock.sleeps == [] and reader.calls == 1


def azure_reader(monkeypatch, clock, header, *, deadline_seconds=None):
    monkeypatch.setattr(azure.time, "time", clock.time)
    monkeypatch.setattr(azure.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(azure.time, "sleep", clock.sleep)
    options = {"retries": 0}
    if deadline_seconds is not None:
        options["collection_deadline_seconds"] = deadline_seconds
    reader = azure._Reader(options)
    calls = []

    def operation():
        calls.append(1)
        if len(calls) == 1:
            raise Throttled({"Retry-After": header} if header is not None else {})
        return {"items": []}

    return reader, calls, operation


@pytest.mark.parametrize("header,expected", [
    ("7", 7.0),
    ("date", 20.0),
    (None, 2.0),
    ("not-a-date", 2.0),
])
def test_azure_retry_after_minimum_and_fallback(monkeypatch, header, expected):
    clock = Clock()
    if header == "date":
        header = format_datetime(datetime.fromtimestamp(clock.wall + 20, timezone.utc), usegmt=True)
    reader, calls, operation = azure_reader(monkeypatch, clock, header)
    assert reader.call(operation) == {"items": []}
    assert calls == [1, 1] and clock.sleeps == [expected] and reader.budget.calls == 2


@pytest.mark.parametrize("header,deadline,code", [
    ("45", None, "retry_after_exceeds_budget"),
    ("7", 5, "deadline_exceeded"),
])
def test_azure_oversized_or_expired_wait_stops_without_early_retry(monkeypatch, header, deadline, code):
    clock = Clock()
    reader, calls, operation = azure_reader(monkeypatch, clock, header, deadline_seconds=deadline)
    with pytest.raises(azure.AzureReadError) as caught:
        reader.call(operation)
    assert caught.value.code == code
    assert calls == [1] and clock.sleeps == [] and reader.budget.calls == 1
