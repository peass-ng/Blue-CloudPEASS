"""Admission preserves native semantics and fails closed on conflicts or tampering."""
from copy import deepcopy
import json
from pathlib import Path
from dataclasses import replace
import pytest
from peaso import checks
from peaso.checks import fixtures
from peaso.checks import azure_function_settings_runtime_admission_20261020 as admission
from peaso.checks import azure_function_settings_review_20261020 as candidate


@pytest.mark.parametrize('check',range(2))
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_exact_native_capture_projection_has_decisive_and_unresolved_branches(check,branch):
    _,cases,declarations=admission.reviewed_inputs()
    d,fn=declarations[check];case=cases[d['id']]
    assert fn(deepcopy(case[branch]),deepcopy(case[branch+'_index']))[0]==branch.upper()


def isolated_registry(monkeypatch):
    ids={d['id']for d in candidate.PROPOSALS}
    monkeypatch.setattr(checks,'CHECKS',[c for c in checks.CHECKS if c.id not in ids])
    monkeypatch.setattr(fixtures,'CASES',{k:deepcopy(v)for k,v in fixtures.CASES.items()if k not in ids})
    return ids


def test_install_is_idempotent_without_overwriting_existing_registry(monkeypatch):
    ids=isolated_registry(monkeypatch);before=tuple(checks.CHECKS)
    admission.install();admission.install()
    assert tuple(checks.CHECKS[:len(before)])==before
    assert len([c for c in checks.CHECKS if c.id in ids])==2
    assert ids<=fixtures.CASES.keys()


def test_second_registration_error_rolls_back_both_controls_and_cases(monkeypatch):
    ids=isolated_registry(monkeypatch);before=tuple(checks.CHECKS);cases=deepcopy(fixtures.CASES)
    original=checks.register;calls=[]
    def fail_second(*args,**kwargs):
        calls.append(args[0])
        if len(calls)==2:raise RuntimeError('injected second registration failure')
        return original(*args,**kwargs)
    monkeypatch.setattr(checks,'register',fail_second)
    with pytest.raises(RuntimeError,match='second registration'):admission.install()
    assert len(calls)==2 and set(calls)==ids
    assert tuple(checks.CHECKS)==before and fixtures.CASES==cases


def test_existing_conflicting_check_is_never_replaced(monkeypatch):
    isolated_registry(monkeypatch);admission.install()
    pos=next(i for i,c in enumerate(checks.CHECKS)if c.id==candidate.PROPOSALS[0]['id'])
    checks.CHECKS[pos]=replace(checks.CHECKS[pos],title='Conflicting reviewed contract')
    before=tuple(checks.CHECKS);cases=deepcopy(fixtures.CASES)
    with pytest.raises(RuntimeError,match='conflict'):admission.install()
    assert tuple(checks.CHECKS)==before and fixtures.CASES==cases


def test_conflicting_native_cases_are_not_silently_refreshed(monkeypatch):
    isolated_registry(monkeypatch);cid=candidate.PROPOSALS[0]['id'];fixtures.CASES[cid]={'historical':'preserve'}
    before=tuple(checks.CHECKS)
    with pytest.raises(RuntimeError,match='CASES conflict'):admission.install()
    assert tuple(checks.CHECKS)==before and fixtures.CASES[cid]=={'historical':'preserve'}


@pytest.mark.parametrize('fault',['receipt','source','fixture'])
def test_changed_reviewed_inputs_fail_before_admission(tmp_path,fault):
    root=Path(admission.__file__).resolve().parents[2]
    raw=root/'peaso/checks'/admission.RECEIPT;receipt=json.loads(raw.read_text())
    files=['peaso/checks/'+admission.RECEIPT,*receipt['sources'],receipt['fixture']['path']]
    for name in files:
        target=tmp_path/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((root/name).read_bytes())
    selected=('peaso/checks/'+admission.RECEIPT if fault=='receipt' else next(iter(receipt['sources']))if fault=='source'else receipt['fixture']['path'])
    p=tmp_path/selected;p.write_bytes(p.read_bytes()+b'\n')
    with pytest.raises(RuntimeError,match='changed'):admission.reviewed_inputs(tmp_path)


def test_runtime_helper_replacement_cannot_reuse_native_acceptance(monkeypatch):
    monkeypatch.setattr(candidate,'_evaluate',lambda *a:('PASS',{}))
    with pytest.raises((ValueError,RuntimeError)):admission.reviewed_inputs()
