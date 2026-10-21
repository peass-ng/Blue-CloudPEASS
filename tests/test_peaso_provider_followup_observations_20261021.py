import importlib.util
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).parent if (Path(__file__).parent/'peaso').is_dir() else Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('followup',ROOT/'peaso/provider_followup_observations_20261021.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def finding(cid,status,evidence):
    return {'check_id':cid,'provider':'gcp' if cid==module.GCP else 'azure','status':status,'evidence':evidence}


@pytest.mark.parametrize('status',['PASS','FAIL','UNKNOWN','DENIED'])
def test_runtime_status_specific_brief(status):
    value=module.evidence_summary(finding(module.RUNTIME,status,{'runtime':'PYTHON|3.10'}))
    assert value and len(value.split('. '))<=3
    if status=='PASS':assert 'not deprecated' in value
    if status=='FAIL':assert 'deprecated or past' in value
    if status in ('UNKNOWN','DENIED'):assert 'could not be matched' in value


def test_storage_retention_unlocked_is_not_locked_claim():
    evidence={'observed_default_policies':[{'container_id':'/containers/one','state':'Unlocked',
         'retention_days':30,'new_writes_inherit':True}], 'containers_without_effective_default_retention':[]}
    text=module.evidence_summary(finding(module.STORAGE,'PASS',evidence))
    assert text=='New writes inherit a positive default retention period in all 1 observed Blob containers. At least one default policy is unlocked and can still be changed.'
    evidence['containers_without_effective_default_retention']=['/containers/one']
    assert module.evidence_summary(finding(module.STORAGE,'PASS',evidence)) is None


def test_storage_failure_names_only_affected_container():
    rows=[{'container_id':'/containers/one','state':'Absent','retention_days':0,'new_writes_inherit':False},
          {'container_id':'/containers/two','state':'Locked','retention_days':30,'new_writes_inherit':True}]
    value=module.evidence_summary(finding(module.STORAGE,'FAIL',{
         'observed_default_policies':rows,'containers_without_effective_default_retention':['/containers/one']}))
    assert '/containers/one' in value and '/containers/two' not in value


@pytest.mark.parametrize('status,coverage,rows,expected',[
 ('PASS','COMPLETE',[],True),('PASS','UNKNOWN',[],False),('FAIL','COMPLETE',[],False),
 ('UNKNOWN','UNKNOWN',[],True),('DENIED','UNKNOWN',[],True),
])
def test_vulnerability_completion_semantics(status,coverage,rows,expected):
    assert bool(module.evidence_summary(finding(module.GCP,status,{
        'coverage_status':coverage,'vulnerabilities':rows}))) is expected


def test_positive_survives_partial_without_claiming_running_image():
    rows=[{'severity':'CRITICAL','vulnerability_id':'CVE-2026-12345','package':'sample-lib','version':'1.2.3'}]
    value=module.evidence_summary(finding(module.GCP,'FAIL',{'coverage_status':'UNKNOWN','vulnerabilities':rows}))
    assert 'CVE-2026-12345 (sample-lib 1.2.3)' in value
    assert value.endswith('Image coverage is incomplete.') and 'running' not in value


def test_many_packages_have_bounded_human_summary():
    row={'severity':'HIGH','vulnerability_id':'CVE-2026-12345','package':'sample-lib','version':'1.2.3'}
    value=module.evidence_summary(finding(module.GCP,'FAIL',{'coverage_status':'COMPLETE','vulnerabilities':[row]*1000}))
    assert 'and 992 more' in value and len(value)<800


@pytest.mark.parametrize('bad',[
 {'provider':'aws','check_id':module.GCP,'status':'PASS','evidence':{}},
 {'provider':'gcp','check_id':'unrelated','status':'PASS','evidence':{}},
 {'provider':'azure','check_id':module.RUNTIME,'status':'PASS','evidence':{'runtime':'injected\nvalue'}},
 {'provider':'gcp','check_id':module.GCP,'status':'FAIL','evidence':{'vulnerabilities':[{'severity':'LOW'}]}},
])
def test_unrelated_or_malformed_not_rewritten(bad):
    assert module.evidence_summary(bad) is None


def test_formatter_hook_returns_before_native_imports(monkeypatch):
    import types
    original=sys.modules.get('peaso.provider_followup_observations_20261021')
    sys.modules['peaso.provider_followup_observations_20261021']=module
    spec=importlib.util.spec_from_file_location('entry',ROOT/'peaso/finding_observation.py')
    entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
    import builtins
    real=builtins.__import__
    def block(name,*args,**kwargs):
        if name.startswith(('peaso.checks','peaso.analysis','peaso.engine')):raise AssertionError('native import '+name)
        return real(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',block)
    try:
        value=entry.evidence_summary(finding(module.RUNTIME,'PASS',{'runtime':'PYTHON|3.10'}))
        assert 'not deprecated' in value
    finally:
        if original is None:sys.modules.pop('peaso.provider_followup_observations_20261021',None)
        else:sys.modules['peaso.provider_followup_observations_20261021']=original


def test_scoped_npm_package_is_readable():
    rows=[{'severity':'HIGH','vulnerability_id':'GHSA-aaaa-bbbb-cccc','package':'@sample/package','version':'1.2.3'}]
    value=module.evidence_summary(finding(module.GCP,'FAIL',{'coverage_status':'COMPLETE','vulnerabilities':rows}))
    assert '@sample/package 1.2.3' in value

@pytest.mark.parametrize('status,coverage,rows,expected',[
 ('PASS','COMPLETE',[],True),('PASS','UNKNOWN',[],False),('FAIL','COMPLETE',[],False),
 ('UNKNOWN','UNKNOWN',[],True),('DENIED','UNKNOWN',[],True),
])
def test_aws_image_completion_semantics(status,coverage,rows,expected):
    value={'check_id':module.AWS,'provider':'aws','status':status,
           'evidence':{'Coverage':coverage,'Vulnerabilities':rows}}
    assert bool(module.evidence_summary(value)) is expected


def test_aws_image_positive_is_brief_and_keeps_incomplete_warning():
    row={'severity':'CRITICAL','vulnerability_id':'CVE-2026-12345','package':'sample-lib','version':'1.2.3'}
    value=module.evidence_summary({'check_id':module.AWS,'provider':'aws','status':'FAIL',
        'evidence':{'Coverage':'UNKNOWN','Vulnerabilities':[row]}})
    assert value=='The selected immutable image has 1 HIGH or CRITICAL package vulnerabilities: CVE-2026-12345 (sample-lib 1.2.3). Image coverage is incomplete.'
    assert 'running' not in value


def test_aws_image_unrelated_provider_not_rewritten():
    assert module.evidence_summary({'check_id':module.AWS,'provider':'gcp','status':'PASS',
        'evidence':{'Coverage':'COMPLETE','Vulnerabilities':[]}}) is None
