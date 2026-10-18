"""Regression tests for GCP coalesced request cancellation."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp

URL = 'https://compute.googleapis.com/compute/v1/projects/p-one/global/networks'


class Response:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self.data = {'items': [{'name': 'network-a'}]} if data is None else data

    def json(self):
        return self.data


class BlockedSession:
    def __init__(self, response=None):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0
        self.response = response or Response()
        self.lock = threading.Lock()

    def request(self, *args, **kwargs):
        with self.lock:
            self.calls += 1
        self.entered.set()
        if not self.release.wait(3):
            raise RuntimeError('fixture owner was not released')
        return self.response


def transport(session, **options):
    credential = SimpleNamespace(headers=lambda: {'Authorization': 'Bearer fixture-token'}, close=lambda: None)
    out = gcp.Transport(credential, options)
    out._session = lambda: session
    return out


def start(name, fn):
    done = threading.Event()
    state = {}
    def run():
        try:
            state['value'] = fn()
        except Exception as exc:
            state['error'] = exc
        finally:
            done.set()
    thread = threading.Thread(name=name, target=run, daemon=True)
    thread.start()
    return thread, done, state


def test_cancelled_follower_exits_before_owner_and_other_follower_gets_one_response():
    session = BlockedSession()
    cancel = threading.Event()
    seen = {name: threading.Event() for name in ('cancelled', 'remaining')}
    counts = {}
    def check():
        name = threading.current_thread().name
        counts[name] = counts.get(name, 0) + 1
        if name in seen and counts[name] >= 2:
            seen[name].set()
        return name == 'cancelled' and cancel.is_set()
    tr = transport(session, _cancel_check=check, retries=0)
    owner, owner_done, owner_state = start('owner', lambda: tr.request('GET', URL))
    assert session.entered.wait(1)
    canceled, canceled_done, canceled_state = start('cancelled', lambda: tr.request('GET', URL))
    remaining, remaining_done, remaining_state = start('remaining', lambda: tr.request('GET', URL))
    try:
        assert seen['cancelled'].wait(1) and seen['remaining'].wait(1)
        at = time.monotonic()
        cancel.set()
        assert canceled_done.wait(0.35), 'follower remained blocked on owner event'
        assert time.monotonic() - at < 0.35
        err = canceled_state.get('error')
        assert isinstance(err, gcp.ReadError) and err.error['code'] == 'cancelled'
        assert not owner_done.is_set() and not remaining_done.is_set()
        assert session.calls == tr.calls == 1 and len(tr.evidence) == 0
    finally:
        session.release.set()
        for thread in (owner, canceled, remaining):
            thread.join(1)
    assert owner_done.is_set() and remaining_done.is_set()
    assert 'error' not in owner_state and 'error' not in remaining_state
    first, rid = owner_state['value']
    second, follower_rid = remaining_state['value']
    assert rid == follower_rid == tr.evidence[0]['id'] == 'request-1'
    first['changed'] = True
    assert 'changed' not in second
    assert tr.request('GET', URL)[1] == rid and session.calls == 1


@pytest.mark.parametrize('deadline_kind', ['absolute', 'duration'])
def test_waiting_follower_deadline_exits_before_owner_releases(deadline_kind):
    session = BlockedSession()
    options = {'retries': 0}
    if deadline_kind == 'absolute':
        options['deadline'] = time.time() + 0.35
    else:
        options['deadline_seconds'] = 1
    tr = transport(session, **options)
    owner, owner_done, owner_state = start('owner', lambda: tr.request('GET', URL))
    assert session.entered.wait(1)
    if deadline_kind == 'duration':
        tr.started = time.monotonic() - 0.7
    follower, follower_done, follower_state = start('follower', lambda: tr.request('GET', URL))
    try:
        assert follower_done.wait(0.8), 'follower ignored execution deadline'
        err = follower_state.get('error')
        assert isinstance(err, gcp.ReadError) and err.error['code'] == 'execution_deadline'
        assert not owner_done.is_set() and session.calls == tr.calls == 1
    finally:
        session.release.set()
        owner.join(1)
        follower.join(1)
    assert owner_done.is_set() and 'error' not in owner_state
    assert tr.evidence[0]['id'] == owner_state['value'][1] == 'request-1'
    assert session.calls == 1


def test_default_cache_permanent_error_and_read_only_guards_remain_unchanged():
    denied = BlockedSession(Response(403, {'error': {'message': 'private', 'details': []}}))
    denied.release.set()
    tr = transport(denied, retries=0)
    for _ in range(2):
        with pytest.raises(gcp.ReadError) as exc:
            tr.request('GET', URL)
        assert exc.value.status == 'denied' and exc.value.request_id == 'request-1'
    assert denied.calls == tr.calls == len(tr.evidence) == 1
    for url, code in (
        ('https://attacker.example/x', 'unsafe_api_endpoint'),
        ('https://compute.googleapis.com/x?access_token=secret', 'unsafe_api_endpoint'),
        ('https://secretmanager.googleapis.com/v1/projects/p/secrets/s/versions/latest:access', 'sensitive_value_read_prohibited'),
    ):
        with pytest.raises(gcp.ReadError) as exc:
            tr.request('GET', url)
        assert exc.value.error['code'] == code
    with pytest.raises(gcp.ReadError) as exc:
        tr.request('POST', URL)
    assert exc.value.error['code'] == 'cloud_mutation_prohibited'
    assert denied.calls == 1
    success = BlockedSession(Response(200, {'items': [{'name': 'network-a', 'accessToken': 'secret'}]}))
    success.release.set()
    default = transport(success)
    assert default.max_calls is None and default.deadline_seconds is None and default.deadline is None
    first, rid = default.request('GET', URL)
    second, second_id = default.request('GET', URL)
    assert first == second == {'items': [{'name': 'network-a'}]}
    assert rid == second_id == 'request-1' and success.calls == 1
    first['changed'] = True
    assert 'changed' not in second


def test_cancel_event_interrupts_follower_without_owner_retry():
    session = BlockedSession()
    cancel = threading.Event()
    waiting = threading.Event()
    class ObservedCancelEvent:
        checks = 0
        def is_set(self):
            if threading.current_thread().name == 'follower':
                self.checks += 1
                if self.checks >= 2:
                    waiting.set()
            return cancel.is_set()
    tr = transport(session, cancel_event=ObservedCancelEvent(), retries=0)
    owner, owner_done, owner_state = start('owner', lambda: tr.request('GET', URL))
    assert session.entered.wait(1)
    follower, follower_done, follower_state = start('follower', lambda: tr.request('GET', URL))
    try:
        assert waiting.wait(1), 'follower did not reach owner event wait'
        cancel.set()
        assert follower_done.wait(0.35)
        err = follower_state.get('error')
        assert isinstance(err, gcp.ReadError) and err.error['code'] == 'cancelled'
        assert not owner_done.is_set() and session.calls == tr.calls == 1
        assert tr.evidence == []
    finally:
        session.release.set()
        owner.join(1)
        follower.join(1)
    assert owner_done.is_set() and owner_state['value'][1] == 'request-1'
    assert session.calls == len(tr.evidence) == 1
