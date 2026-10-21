"""Offline ARM HTTP producer and typed consumer regression for selected ML jobs."""
import importlib.util
import json
import socket
import sys
from pathlib import Path
from copy import deepcopy

import pytest

from peaso.collectors import azure
from peaso.collectors import azure_ml_selected_job_secret_indicators as producer
from peaso.checks import azure_ml_selected_job_secret_review_20261020 as consumer
from tests import test_azure_ml_selected_job_secret_review_20261020 as prior


@pytest.fixture(autouse=True)
def bind_candidate(monkeypatch):
    def blocked(*a, **kw):
        pytest.fail('live network forbidden')
    monkeypatch.setattr(socket, 'create_connection', blocked)


def variant(kind, hit=False, *, missing=False, extra=0):
    literal = prior.TOKEN if hit else 'mode=ready'
    if kind == 'Command':
        return {'jobType':'Command','command':'python train.py','environmentVariables':{'SETTING':literal}}
    if kind == 'Sweep':
        return {'jobType':'Sweep','trial':{'command':'python train.py','environmentVariables':{'SETTING':literal}}}
    children = {'first':{'jobType':'Command','command':'python train.py','environmentVariables':{'SETTING':literal}},
                'second':{'jobType':'Sweep','trial':{'command':'python tune.py','environmentVariables':{'MODE':'ready'}}}}
    if missing: children['unsupported']={'jobType':'Pipeline','jobs':{}}
    for n in range(extra):children['node'+str(n)]={'jobType':'Command','command':'echo ready','environmentVariables':{}}
    return {'jobType':'Pipeline','jobs':children,'inputs':{'private':prior.TOKEN}}


@pytest.mark.parametrize('kind',['Command','Sweep','Pipeline'])
@pytest.mark.parametrize('hit',[False,True])
def test_native_http_variant_status(monkeypatch,kind,hit):
    def transform(op,data,rid):
        if op=='job':data['properties']=variant(kind,hit)
        return data
    snapshot,rows,trace=prior.collect(monkeypatch, transform=transform, concrete_http=True)
    assert {r['status'] for r in rows}==({'FAIL'} if hit else {'PASS'}), rows
    assert len(trace.calls)==4 and all(r.closed for r in trace.responses)
    marker=prior.own(snapshot)['items'][0][producer.MARKER]
    assert marker['job_type']==kind and marker['native_stable'] is True
    assert prior.TOKEN not in json.dumps([snapshot,rows])


@pytest.mark.parametrize('case',['denied','foreign','drift','missing','limit'])
@pytest.mark.parametrize('hit',[False,True])
def test_incomplete_native_read_retains_only_proven_positive(monkeypatch,case,hit):
    counts={'job':0}
    def transform(op,data,rid):
        if op=='job':
            counts['job']+=1
            data['properties']=variant('Pipeline',hit,missing=case=='missing',extra=producer.MAX_NODES if case=='limit' else 0)
            if case=='foreign' and counts['job']==2:data['id']=data['id'].replace(prior.SCOPE,prior.FOREIGN)
            if case=='drift' and counts['job']==2:data['properties']['description']='changed'
        return data
    def fault(op,response,rid):
        if case=='denied' and op=='job' and counts['job']==2:return prior.Response({'error':'denied'},403)
        return response
    snapshot,rows,trace=prior.collect(monkeypatch,transform=transform,fault=fault)
    assert {r['status'] for r in rows}==({'FAIL'} if hit else {'UNKNOWN'}),rows
    assert prior.TOKEN not in json.dumps([snapshot,rows])
    assert all(r.closed for r in trace.responses)


def test_off_by_default_zero_http(monkeypatch):
    snapshot,rows,trace=prior.collect(monkeypatch,options={'content_secret_scans':False})
    assert not trace.calls and not trace.tokens and {r['status'] for r in rows}=={'UNKNOWN'}


def test_foreign_selected_scope_rejected_before_auth():
    with pytest.raises(ValueError):
        producer.selected_targets({producer.OPTION:[{'resource_id':prior.JOB.replace(prior.SCOPE,prior.FOREIGN)}]},[prior.SCOPE])
