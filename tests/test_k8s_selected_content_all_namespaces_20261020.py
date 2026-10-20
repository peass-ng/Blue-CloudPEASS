"""Overall wildcard scope never expands explicit named content selections."""
import pytest
from tests.test_k8s_controller_literal_secret_review_20261020 import (
    offline, capture, target, native, route, NATIVE, source, NS)

@pytest.mark.parametrize('kind',NATIVE)
@pytest.mark.parametrize('leak',[False,True])
def test_exact_named_target_with_overall_all_namespace_scope(monkeypatch,kind,leak):
    t=target(kind)
    snapshot,result,trace=capture(monkeypatch,[t],documents={route(t):native(t,leak)},
        req_change=lambda request:request['connector'].update(scopes=['*']))
    assert {f['status']for f in result['findings']}==({'FAIL'}if leak else{'PASS'})
    assert len(trace.calls)==2
    assert all(c['scope']=='*'for c in snapshot['collections']if c['type']==source.KIND)

@pytest.mark.parametrize('scopes,namespace',[( ['*',NS],NS),(['*'],'*'),(['*'],'../other'),([NS],'other')])
def test_wildcard_target_and_mixed_or_foreign_namespace_rejected(scopes,namespace):
    with pytest.raises(source.Incomplete):
        source.selected_targets({source.OPTION:[target('Deployment',namespace=namespace)]},scopes)

@pytest.mark.parametrize('kind',NATIVE)
def test_all_namespace_scope_does_not_accept_wrong_returned_namespace(monkeypatch,kind):
    t=target(kind);document=native(t);document['metadata']['namespace']='foreign'
    _,result,trace=capture(monkeypatch,[t],documents={route(t):document},
        req_change=lambda request:request['connector'].update(scopes=['*']))
    assert {f['status']for f in result['findings']}=={'UNKNOWN'}
    assert len(trace.calls)==1 and not trace.scans
