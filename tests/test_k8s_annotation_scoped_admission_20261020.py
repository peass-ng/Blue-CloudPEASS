"""Shared-source ancestor admission allows unrelated edits, keeps exact guards."""
import inspect
from pathlib import Path
import socket

import pytest
from peaso import engine
import peaso.checks as registry
from peaso.collectors import k8s
from peaso.checks import k8s_annotation_native_admission_20261020 as guard
from peaso.checks import k8s_annotation_indicators_review_20261020 as candidate


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**k):pytest.fail('live network/DNS/auth forbidden')
    for n in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in ('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,n,blocked)


@pytest.mark.parametrize('function',[engine.plan_collection,registry.register,k8s._native,k8s._pages,k8s._sanitize,k8s.collect])
@pytest.mark.parametrize('addition',[
    '\n\ndef unrelated_approved_helper():\n    raise RuntimeError("DO_NOT_EXECUTE")\n',
    '\nfrom . import unrelated_new_review_helper\nraise RuntimeError("DO_NOT_EXECUTE")\n'])
def test_unrelated_shared_source_addition_and_registry_import_allowed(monkeypatch,function,addition):
    path=Path(inspect.getsourcefile(function));before=guard._function(function);original=Path.read_bytes
    def changed(p):return original(p)+addition.encode()if p.resolve()==path.resolve()else original(p)
    monkeypatch.setattr(Path,'read_bytes',changed)
    assert guard._function(function)==before
    guard.install()


@pytest.mark.parametrize('function',[engine.plan_collection,registry.register,k8s._native,k8s._pages,k8s._sanitize,k8s.collect])
def test_changed_reviewed_function_source_ancestor_rejected(monkeypatch,function):
    path=Path(inspect.getsourcefile(function));original=Path.read_bytes
    source=inspect.getsource(function);changed=source.replace('\n','\n    # unreviewed owned-body delta\n',1)
    def altered(p):return original(p).replace(source.encode(),changed.encode(),1)if p.resolve()==path.resolve()else original(p)
    monkeypatch.setattr(Path,'read_bytes',altered)
    with pytest.raises(RuntimeError,match='source ancestor'):guard._function(function)


def test_changed_nested_safe_wrapper_source_rejected(monkeypatch):
    path=Path(registry.__file__);original=Path.read_bytes
    def changed(p):
        raw=original(p)
        return raw.replace(b'status, evidence = checked(item, index)',b'status, evidence = ("PASS", {})',1)if p.resolve()==path.resolve()else raw
    monkeypatch.setattr(Path,'read_bytes',changed)
    safe=next(c for c in registry.CHECKS if c.id==guard.IDS[0]).evaluate
    with pytest.raises(RuntimeError,match='source ancestor'):guard._function(safe)


def test_referenced_module_import_compiler_binding_is_guarded(monkeypatch):
    path=Path(k8s.__file__);original=Path.read_bytes
    def changed(p):
        raw=original(p)
        return raw.replace(b'\nimport re\n',b'\nimport re as unreviewed_re\n',1)if p.resolve()==path.resolve()else raw
    monkeypatch.setattr(Path,'read_bytes',changed)
    with pytest.raises(RuntimeError,match='future imports'):guard._function(k8s._sanitize)


def test_dedicated_producer_remains_whole_source_guarded(monkeypatch):
    path=Path(candidate.__file__);original=Path.read_bytes
    monkeypatch.setattr(Path,'read_bytes',lambda p:original(p)+b'\n# changed dedicated module'if p.resolve()==path.resolve()else original(p))
    with pytest.raises(RuntimeError,match='source bytes'):guard._function(candidate.evaluate)


@pytest.mark.parametrize('addition',['\nre = object()\n','\ndef re(): pass\n','\ndel re\n','\nre.sub = lambda *args: ""\n'])
def test_reviewed_imported_module_cannot_be_rebound_outside_function(monkeypatch,addition):
    path=Path(k8s.__file__);original=Path.read_bytes
    monkeypatch.setattr(Path,'read_bytes',lambda p:original(p)+addition.encode()if p.resolve()==path.resolve()else original(p))
    with pytest.raises(RuntimeError,match='binding rebound'):guard._function(k8s._sanitize)
