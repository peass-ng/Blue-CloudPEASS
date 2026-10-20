"""Installed exact-file CSR consent and native collector-to-engine contract."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso import engine, collectors
from peaso.collectors import gcp
from peaso.collectors import gcp_sourcerepo_secret_indicators as source
from peaso.checks import gcp_sourcerepo_secret_review_20261019 as check
from peaso.server.validation import validate_connector
from tests.test_gcp_sourcerepo_secret_review_20261019 import fixture, make_pack, SCOPE, REPO, PATH, TOKEN


def target():
    _, commit=make_pack()
    return {'repository':REPO,'commit':commit,'paths':[PATH]}


def installed(monkeypatch,payload=b'selected clean content\n',*,enabled=True,kinds=None,mock_engines=True):
    options={'content_secret_scans':enabled,'_content_secret_scan_kinds':[source.KIND] if kinds is None else kinds}
    parent,calls,_,pending,_,_,_=fixture(monkeypatch,payload,options=options,mock_engines=mock_engines)
    collector=gcp.GCPCollector({'provider':'gcp','scopes':[SCOPE],'options':parent.options},
        requirements=[source.KIND,'project'],transport=parent.transport)
    return collector.collect(),calls,pending


def test_installed_selected_commit_and_files_are_native_and_read_only(monkeypatch):
    captured,calls,pending=installed(monkeypatch)
    findings=engine.evaluate_snapshot(captured,checks=[check.CHECK_ID])['findings']
    assert len(findings)==1 and findings[0]['status']=='PASS',findings
    evidence=findings[0]['evidence']
    assert evidence['coverage']=='selected_files_at_advertised_commit_only'
    assert evidence['commit']==target()['commit'] and len(evidence['files'])==1
    assert captured['metadata']['source_repository_file_authorized'] is True
    assert not pending
    streamed=[(m,u) for m,u,k in calls if k.get('stream')]
    assert len(streamed)==3 and streamed[-1]==('POST','https://source.developers.google.com/p/review/r/example/git-upload-pack')
    assert [m for m,_ in streamed]==['GET','GET','POST']


def test_installed_both_real_detectors_produce_one_hidden_leak(monkeypatch):
    captured,_,_=installed(monkeypatch,('token='+TOKEN+'\n').encode(),mock_engines=False)
    findings=engine.evaluate_snapshot(captured,checks=[check.CHECK_ID])['findings']
    assert len(findings)==1 and findings[0]['status']=='FAIL',findings
    leak,=findings[0]['evidence']['secret_leaks']
    assert {r['engine'] for r in leak['detectors']}=={'kingfisher','trufflehog'}
    assert TOKEN not in repr(captured)+repr(findings)


@pytest.mark.parametrize('enabled,kinds',[(False,[source.KIND]),(True,[])])
def test_disabled_or_unselected_has_no_repository_content_reads(monkeypatch,enabled,kinds):
    captured,calls,pending=installed(monkeypatch,enabled=enabled,kinds=kinds)
    assert not any(k.get('stream') for _,_,k in calls) and pending
    finding,=engine.evaluate_snapshot(captured,checks=[check.CHECK_ID])['findings']
    assert finding['status']=='UNKNOWN'


def test_public_exact_check_alone_authorizes_this_content_kind(monkeypatch):
    from peaso.snapshot import make_snapshot
    calls=[]
    def collect(connector,requirements):
        calls.append((deepcopy(connector),set(requirements)))
        return make_snapshot('gcp',[SCOPE],[])
    monkeypatch.setattr(collectors,'collect_live',collect)
    connector={'provider':'gcp','scopes':[SCOPE],'options':{'content_secret_scans':True,
        'selected_source_repository_files':[target()]}}
    engine.collect_snapshot({'connector':connector,'checks':[check.CHECK_ID]})
    actual,requirements=calls.pop()
    assert actual['options']['_content_secret_scan_kinds']==[source.KIND]
    assert {source.KIND,'project'}<=requirements and 'bucket' not in requirements
    for selection in ({},{'categories':['hardening']},{'frameworks':['HackTricks Cloud Best Practices']}):
        engine.collect_snapshot({'connector':connector,**selection})
        actual,_=calls.pop()
        assert source.KIND not in actual['options']['_content_secret_scan_kinds']


def test_public_selector_rejection_precedes_credentials(monkeypatch):
    settings=SimpleNamespace(auth_mode='local')
    good=target()
    validate_connector('gcp',{}, {'selected_source_repository_files':[good]},settings,scopes=[SCOPE])
    for selection in (None,[],[good,good],[{**good,'commit':'main'}],[{**good,'repository':'projects/foreign/repos/example'}]):
        with pytest.raises(HTTPException):
            validate_connector('gcp',{}, {'selected_source_repository_files':selection},settings,scopes=[SCOPE])
        with pytest.raises(ValueError):
            gcp.GCPCollector({'provider':'gcp','scopes':[SCOPE],'options':{
                'selected_source_repository_files':selection}},requirements=[source.KIND])
