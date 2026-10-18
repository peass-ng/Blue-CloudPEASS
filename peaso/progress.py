"""Transient, thread-safe progress events; never part of a snapshot/report.

Provider schedulers receive options['_progress_callback'] at runtime and call
emit_progress(callback, phase='collecting', provider=..., scope=...,
              completed=..., total=None, resources=..., dynamic_total=True).
Only settled inventory/check counts are logged, never API arguments or facts.
"""
from __future__ import annotations
from contextvars import ContextVar
import re
import sys
import threading
import time
import unicodedata

_callback = ContextVar("peaso_progress_callback", default=None)
PHASES = frozenset({"starting", "discovering", "collecting", "evaluating", "completed", "error"})
PROVIDERS = frozenset({"aws", "gcp", "azure", "k8s"})


def current_callback():
    return _callback.get()


def _scope(value):
    if not isinstance(value, str):
        return ""
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    value = "".join(char for char in value if unicodedata.category(char) not in {"Cc", "Cf", "Cs"})
    if re.search(r"(?i)(?:https?://|bearer\s|ya29\.|-----BEGIN|AKIA[A-Z0-9]{16})", value):
        return "[redacted]"
    value = re.sub(r"(?i)\b[\w-]*(?:token|secret|password|credentials?|authorization|api[_-]?key|secret[_-]?access[_-]?key)\s*[:=]\s*\S+", "[redacted]", value)
    return value[:120]


def _number(value):
    return value if type(value) is int and value >= 0 else None


def sanitize_event(event):
    """Explicit scalar whitelist: callbacks never receive credentials/fact blobs."""
    if not isinstance(event, dict):
        return {}
    cleaned = {}
    if isinstance(event.get("phase"), str) and event["phase"] in PHASES:
        cleaned["phase"] = event["phase"]
    if isinstance(event.get("provider"), str) and event["provider"] in PROVIDERS:
        cleaned["provider"] = event["provider"]
    if "scope" in event:
        cleaned["scope"] = _scope(event["scope"])
    for field in ("completed", "total", "resources"):
        if field in event:
            cleaned[field] = _number(event[field])
    if type(event.get("dynamic_total")) is bool:
        cleaned["dynamic_total"] = event["dynamic_total"]
    if cleaned.get("dynamic_total") is True:
        cleaned["total"] = None
    return cleaned


def emit_progress(callback=None, **event):
    callback = current_callback() if callback is None else callback
    if not callable(callback):
        return False
    try:
        callback(sanitize_event(event))
        return True
    except Exception:
        # Optional diagnostics must not abort collection or change coverage.
        return False


class ProgressReporter:
    """Rate-limited stderr output plus heartbeat during a blocked provider read."""
    def __init__(self, *, quiet=False, provider=None, stream=None, interval=2.0, heartbeat=15.0, clock=time.monotonic):
        self.quiet = quiet
        self.stream = sys.stderr if stream is None else stream
        self.interval = max(0.01, interval)
        self.heartbeat = max(0.01, heartbeat)
        self.clock = clock
        self.started = clock()
        self.phase_started = self.started
        self.last_written = float("-inf")
        self.state = {"phase": "starting", "provider": provider if provider in PROVIDERS else "", "scope": "",
                      "completed": 0, "total": None, "resources": 0, "dynamic_total": True}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.token = None

    def __enter__(self):
        self.token = _callback.set(None if self.quiet else self)
        if not self.quiet:
            with self.lock:
                self._write(force=True)
            self.thread = threading.Thread(target=self._heartbeat, name="peaso-progress", daemon=True)
            self.thread.start()
        return self

    def __exit__(self, kind, value, traceback):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=min(self.heartbeat, 0.5))
        if not self.quiet:
            with self.lock:
                self.state["phase"] = "error" if kind else "completed"
                self._write(force=True)
        if self.token is not None:
            _callback.reset(self.token)

    def __call__(self, event):
        if self.quiet:
            return
        event = sanitize_event(event)
        with self.lock:
            changed = event.get("phase", self.state["phase"]) != self.state["phase"]
            if changed:
                self.phase_started = self.clock()
                self.state.update(completed=0, total=None, dynamic_total=True)
            else:
                # Concurrent provider workers can deliver older settlement
                # events after newer ones. Keep cumulative counts monotonic.
                for field in ("completed", "resources"):
                    if isinstance(event.get(field), int):
                        event[field] = max(event[field], self.state.get(field) or 0)
            self.state.update(event)
            if self.state.get("total") is not None and (self.state.get("completed") or 0) > self.state["total"]:
                self.state.update(total=None, dynamic_total=True)
            self._write(force=changed or self.state["phase"] in {"completed", "error"})

    def _heartbeat(self):
        while not self.stop.wait(self.heartbeat):
            with self.lock:
                self._write(force=True)

    def _write(self, force=False):
        now = self.clock()
        if not force and now - self.last_written < self.interval:
            return
        self.last_written = now
        state = self.state
        completed = state.get("completed") or 0
        total = state.get("total")
        count = f"{completed}/{total}" if total is not None else f"{completed}/unknown"
        eta = "unknown"
        if not state.get("dynamic_total", True) and total is not None and 0 < completed <= total:
            eta = f"{max(0, (now - self.phase_started) * (total - completed) / completed):.0f}s estimated"
        provider = state["provider"] or "unknown"
        scope = state["scope"] or "unknown"
        try:
            self.stream.write(f"peaso progress: {state['phase']} provider={provider} scope={scope} settled={count} resources={state.get('resources') or 0} elapsed={now - self.started:.1f}s ETA={eta}\n")
            self.stream.flush()
        except (OSError, ValueError):
            pass
