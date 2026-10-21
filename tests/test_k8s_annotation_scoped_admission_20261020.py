"""Shared-source ancestor admission allows unrelated edits, keeps exact guards."""
import hashlib
import inspect
from pathlib import Path
import socket

import pytest
from peaso import engine
import peaso.checks as registry
from peaso.collectors import k8s
from peaso.checks import k8s_annotation_native_admission_20261020 as guard
from peaso.checks import k8s_annotation_indicators_review_20261020 as candidate
from peaso import private_secret_source_epoch_20261021 as source_epoch


ROOT = Path(__file__).resolve().parents[1]
K8S_RELATIVE = 'peaso/collectors/k8s.py'
K8S_BEFORE_SHA = '86eca83f116bc8fe4a2b28d5ced1ae6612507c5cc3f53968fe6ec28df14a15f1'


def historical_k8s_bytes():
    current = (ROOT / K8S_RELATIVE).read_bytes()
    before = source_epoch.predecessor_bytes(K8S_RELATIVE, current, K8S_BEFORE_SHA, ROOT)
    assert hashlib.sha256(before).hexdigest() == K8S_BEFORE_SHA
    return before


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**k):pytest.fail('live network/DNS/auth forbidden')
    for n in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in ('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,n,blocked)


@pytest.mark.parametrize('function',[engine.plan_collection,registry.register,k8s._native,k8s._pages,k8s._sanitize,k8s.collect])
@pytest.mark.parametrize('addition',[
    '\n\ndef unrelated_approved_helper():\n    raise RuntimeError("DO_NOT_EXECUTE")\n',
    '\nfrom . import unrelated_new_review_helper\nraise RuntimeError("DO_NOT_EXECUTE")\n'])
def test_unrelated_shared_source_addition_preserves_historical_scoped_view(function,addition):
    path=Path(inspect.getsourcefile(function));relative=str(path.relative_to(ROOT))
    source=historical_k8s_bytes() if relative==K8S_RELATIVE else path.read_bytes()
    expected=guard._source_receipt()['compiled_sources'][relative]
    assert guard._verified_source(relative,source+addition.encode(),expected)==guard._verified_source(relative,source,expected)


def test_current_k8s_source_rejects_the_historical_unrelated_addition():
    current=(ROOT/K8S_RELATIVE).read_bytes()
    with pytest.raises(source_epoch.AdmissionError):
        source_epoch.predecessor_bytes(K8S_RELATIVE,current+b'\n# unreviewed current addition\n',K8S_BEFORE_SHA,ROOT)


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


def test_referenced_module_import_compiler_binding_is_guarded():
    raw=historical_k8s_bytes().replace(b'\nimport re\n',b'\nimport re as unreviewed_re\n',1)
    expected=guard._source_receipt()['compiled_sources'][K8S_RELATIVE]
    with pytest.raises(RuntimeError,match='future imports'):
        guard._verified_source(K8S_RELATIVE,raw,expected)


def test_dedicated_producer_remains_whole_source_guarded(monkeypatch):
    path=Path(candidate.__file__);original=Path.read_bytes
    monkeypatch.setattr(Path,'read_bytes',lambda p:original(p)+b'\n# changed dedicated module'if p.resolve()==path.resolve()else original(p))
    with pytest.raises(RuntimeError,match='source bytes'):guard._function(candidate.evaluate)


@pytest.mark.parametrize('addition',['\nre = object()\n','\ndef re(): pass\n','\ndel re\n','\nre.sub = lambda *args: ""\n'])
def test_reviewed_imported_module_cannot_be_rebound_outside_function(addition):
    raw=historical_k8s_bytes()+addition.encode()
    expected=guard._source_receipt()['compiled_sources'][K8S_RELATIVE]
    with pytest.raises(RuntimeError,match='binding rebound'):
        guard._verified_source(K8S_RELATIVE,raw,expected)
