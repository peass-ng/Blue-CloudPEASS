"""Cached read failures remain inert across repeated and concurrent consumers."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import pytest
from peaso.collectors import aws


@pytest.mark.parametrize('profile', [None, 'securityhub-findings-metadata-v1'])
def test_cached_failure_is_never_raised_on_repeated_hits(monkeypatch, profile):
    class Client:
        calls = 0
        def get_findings(self, **kwargs):
            self.calls += 1
            return None
    client, session = Client(), object()
    reader = aws.Requests({'retry_attempts': 1})
    monkeypatch.setattr(reader, 'client', lambda *args: client)
    for _ in range(3):
        with pytest.raises(aws.ReadFailure) as caught:
            reader.call(session, 'securityhub', 'us-east-1', 'get_findings',
                        _metadata_profile=profile)
        cached = next(iter(reader._cache.values())).exception()
        assert caught.value is not cached
        assert (caught.value.status, caught.value.code) == (cached.status, cached.code)
        assert cached.__traceback__ is cached.__context__ is cached.__cause__ is None
    assert client.calls == 1 and reader.cache_hits == 2


def test_pending_failed_read_shares_one_call_and_inert_exception(monkeypatch):
    entered, release, waiting = Event(), Event(), Event()
    class Client:
        calls = 0
        def get_findings(self, **kwargs):
            self.calls += 1
            entered.set()
            assert release.wait(5)
            return None
    client, session = Client(), object()
    reader = aws.Requests({'retry_attempts': 1})
    monkeypatch.setattr(reader, 'client', lambda *args: client)
    def call():
        try:
            reader.call(session, 'securityhub', 'us-east-1', 'get_findings',
                        _metadata_profile='securityhub-findings-metadata-v1')
        except aws.ReadFailure as exc:
            return exc
        pytest.fail('malformed response accepted')
    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(call)
        assert entered.wait(5)
        future = next(iter(reader._cache.values()))
        # Observe either the pre-fix result wait or the fixed exception wait.
        method = 'exception' if 'exception' in aws.Requests.call.__code__.co_names else 'result'
        original = getattr(future, method)
        def observed_wait(*args, **kwargs):
            waiting.set()
            return original(*args, **kwargs)
        monkeypatch.setattr(future, method, observed_wait)
        waiter = pool.submit(call)
        try:
            assert waiting.wait(5)
        finally:
            release.set()
        first, second = owner.result(5), waiter.result(5)
    cached = future.exception()
    assert first is not cached and second is not cached and first is not second
    assert cached.__traceback__ is cached.__context__ is cached.__cause__ is None
    assert client.calls == 1 and reader.cache_hits == 1
