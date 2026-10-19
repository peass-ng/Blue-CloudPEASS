"""Duplicate registration remains a fresh ordered, short-circuit scan."""
from dataclasses import replace
from types import SimpleNamespace
import pytest
import peaso.checks as registry


def decorate(check_id):
    return registry.register(check_id,'aws','hardening','bucket','title','medium','CM-6','review')


def evaluator(item,index):return 'PASS',{}


def test_scan_reads_current_checks_at_decoration_and_retains_duplicate_error(monkeypatch):
    original=registry.CHECKS[0];current=[]
    monkeypatch.setattr(registry,'CHECKS',current)
    monkeypatch.setattr(registry,'CHECK_ALIASES',{})
    callback=decorate('new-id')
    current.append(replace(original,id='new-id'))
    with pytest.raises(ValueError,match='^duplicate check id: new-id$'):callback(evaluator)
    current.clear()
    assert callback(evaluator) is evaluator
    assert len(current)==1 and current[0].id=='new-id'
    assert current[0].evaluate({}, {})==('PASS',{})


def test_alias_conflicts_keep_exact_error_without_registering(monkeypatch):
    current=[];aliases={'retired':'survivor'}
    monkeypatch.setattr(registry,'CHECKS',current)
    monkeypatch.setattr(registry,'CHECK_ALIASES',aliases)
    with pytest.raises(ValueError,match='^duplicate check id: retired$'):decorate('retired')(evaluator)
    assert current==[] and aliases=={'retired':'survivor'}


def test_duplicate_short_circuits_before_later_bad_entry_and_alias_lookup(monkeypatch):
    class BadLater:
        @property
        def id(self):raise AssertionError('later entry must not be read')
    class BadAliases(dict):
        def __contains__(self,key):raise AssertionError('aliases must not be read')
    monkeypatch.setattr(registry,'CHECKS',[SimpleNamespace(id='duplicate'),BadLater()])
    monkeypatch.setattr(registry,'CHECK_ALIASES',BadAliases())
    with pytest.raises(ValueError,match='^duplicate check id: duplicate$'):decorate('duplicate')(evaluator)


def test_comparison_direction_truthiness_and_access_order_are_preserved(monkeypatch):
    calls=[]
    class RecordedID:
        def __init__(self,value):self.value=value
        def __eq__(self,other):
            calls.append((self.value,other))
            return self.value==other
    monkeypatch.setattr(registry,'CHECKS',[SimpleNamespace(id=RecordedID('first')),SimpleNamespace(id=RecordedID('target')),SimpleNamespace(id=RecordedID('later'))])
    monkeypatch.setattr(registry,'CHECK_ALIASES',{})
    with pytest.raises(ValueError,match='^duplicate check id: target$'):decorate('target')(evaluator)
    assert calls==[('first','target'),('target','target')]
