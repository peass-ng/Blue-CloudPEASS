"""Existing-kind field extraction and installed collector/check pipeline."""
from copy import deepcopy
from pathlib import Path
import json
import socket
import sys

import pytest
from peaso import collectors, secret_scanning
from peaso.collectors import k8s_literal_secret_indicators as base
from peaso.checks import k8s_literal_secret_review_20261020 as predicate
from tests import test_k8s_literal_secret_review_20261020 as native_test

from peaso.collectors import k8s_literal_secret_fields_compatible as source
TOKEN = native_test.TOKEN


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('network and cloud auth forbidden')
    for owner, names in ((socket, ('create_connection', 'getaddrinfo')),
                         (socket.socket, ('connect', 'connect_ex', 'sendto'))):
        for name in names:
            monkeypatch.setattr(owner, name, blocked)
    secret_scanning._RESULTS.clear()
    yield
    secret_scanning._RESULTS.clear()


def dto(kind='Pod'):
    target = {'cluster_id': 'review-cluster', 'namespace': 'team-a', 'kind': kind, 'name': 'review-pod'}
    doc = {'apiVersion': source.NATIVE_KINDS[kind][0], 'kind': kind,
        'metadata': {'name': target['name'], 'namespace': target['namespace'],
                     'uid': 'opaque-uid-1', 'resourceVersion': '207'}}
    template = {'metadata': {'annotations': {}},
                'spec': {'containers': [{'name': 'app', 'image': 'example.invalid/app:1'}]}}
    if kind == 'Pod':
        doc['spec'] = template['spec']
    elif kind == 'PodTemplate':
        doc['template'] = template
    elif kind == 'CronJob':
        doc['spec'] = {'jobTemplate': {'spec': {'template': template}}}
    else:
        doc['spec'] = {'template': template}
    return target, doc


def template(doc, kind):
    if kind == 'Pod':
        return doc
    value = doc
    for field in source.NATIVE_KINDS[kind][2][:-1]:
        value = value[field]
    return value


def result(monkeypatch, doc, target=None, *, real=False):
    target = target or native_test.target()
    snapshot, trace = native_test.capture(monkeypatch, targets=[target],
        documents={native_test.route(target): doc}, real=real)
    status, evidence = predicate.evaluate(*native_test.item_index(snapshot))
    assert native_test.findings(snapshot)[0]['status'] == status
    assert TOKEN not in json.dumps(snapshot)
    return status, evidence, trace


def test_existing_constants_configmap_and_default_off():
    assert (source.KIND, source.CHECK, source.OPTION, source.MARKER, source.SCHEMA) == (
        base.KIND, base.CHECK, base.OPTION, base.MARKER, base.SCHEMA)
    assert source.NATIVE_KINDS == base.NATIVE_KINDS
    target = native_test.target('ConfigMap', 'review-map')
    doc = native_test.native(target, TOKEN)
    assert source._extract(doc, target) == base._extract(doc, target)
    assert not source.enabled({'content_secret_scans': False, '_content_secret_scan_kinds': [source.KIND]})


@pytest.mark.parametrize('kind', [kind for kind in source.NATIVE_KINDS if kind != 'ConfigMap'])
@pytest.mark.parametrize('field', ('labels', 'annotations'))
def test_exact_native_template_paths(kind, field):
    target, doc = dto(kind)
    template(doc, kind)['metadata'].setdefault(field, {})['example.test/value'] = TOKEN
    payload, uid, version, count, refs = source._extract(doc, target)
    assert TOKEN.encode() in payload and uid == 'opaque-uid-1' and version == '207'
    assert count > 0 and refs == 0
    if kind != 'Pod':
        doc['metadata'][field] = {'example.test/value': TOKEN[::-1]}
        assert TOKEN[::-1].encode() not in source._extract(doc, target)[0]


@pytest.mark.parametrize('probe', ('livenessProbe', 'readinessProbe', 'startupProbe'))
@pytest.mark.parametrize('handler', ('httpGet', 'exec'))
def test_probe_fields(probe, handler):
    target, doc = dto()
    doc['spec']['containers'][0][probe] = ({'httpGet': {'httpHeaders': [{'name': 'X-Auth', 'value': TOKEN}]}}
        if handler == 'httpGet' else {'exec': {'command': ['/bin/sh', TOKEN]}})
    assert TOKEN.encode() in source._extract(doc, target)[0]


@pytest.mark.parametrize('hook', ('postStart', 'preStop'))
@pytest.mark.parametrize('handler', ('httpGet', 'exec'))
def test_lifecycle_fields(hook, handler):
    target, doc = dto('CronJob')
    container = template(doc, 'CronJob')['spec']['containers'][0]
    container['lifecycle'] = {hook: ({'httpGet': {'httpHeaders': [{'name': 'X-Auth', 'value': TOKEN}]}}
        if handler == 'httpGet' else {'exec': {'command': ['/bin/sh', TOKEN]}})}
    assert TOKEN.encode() in source._extract(doc, target)[0]


@pytest.mark.parametrize('bad', (
    {'livenessProbe': {'exec': {}}},
    {'readinessProbe': {'exec': {'command': 'bad'}}},
    {'startupProbe': {'httpGet': {'httpHeaders': [{'name': 'X', 'value': 7}]}}},
    {'livenessProbe': {'httpGet': {'httpHeaders': [False]}}},
    {'readinessProbe': {'tcpSocket': {'port': 80}}},
    {'lifecycle': {'postStart': {'exec': {'command': [None]}}}},
    {'lifecycle': {'preStop': {'httpGet': []}}},
    {'lifecycle': {'postStart': {'sleep': {'seconds': 1}}}},
    {'lifecycle': {'postStart': {'exec': {'command': ['ok']}, 'unexpected': 'value'}}},
    {'startupProbe': {'exec': {'command': ['ok'], 'unexpected': 'value'}}},
    {'startupProbe': {'httpGet': {'httpHeaders': [{'name': 'X', 'value': 'ok', 'unexpected': 'value'}]}}},
))
def test_malformed_or_unsupported_handler_is_incomplete(bad):
    target, doc = dto()
    doc['spec']['containers'][0].update(bad)
    with pytest.raises(source.Incomplete):
        source._extract(doc, target)


def test_field_and_aggregate_bounds():
    target, doc = dto()
    command = doc['spec']['containers'][0].setdefault('startupProbe', {'exec': {'command': []}})['exec']['command']
    command.append('a' * (base.MAX_VALUE + 1))
    with pytest.raises(source.Incomplete, match='unsupported_workload_literal'):
        source._extract(doc, target)
    command[:] = ['a' * base.MAX_VALUE] * 5
    with pytest.raises(source.Incomplete, match='literal_byte_limit'):
        source._extract(doc, target)


def test_existing_kind_pipeline_pass_fail_and_configmap(monkeypatch):
    clean = native_test.native(value='ready = true')
    clean['spec']['containers'][0]['livenessProbe'] = {'exec': {'command': ['echo', 'ready']}}
    assert result(monkeypatch, clean)[0] == 'PASS'
    positive = native_test.native(value='ready = true')
    positive['spec']['containers'][0]['readinessProbe'] = {'httpGet': {'httpHeaders': [{'name': 'Authorization', 'value': TOKEN}]}}
    positive['spec']['containers'][0]['lifecycle'] = {'preStop': {'exec': {'command': [TOKEN]}}}
    status, evidence, trace = result(monkeypatch, positive)
    assert status == 'FAIL' and len(trace.calls) == 2 and len(evidence['secret_leaks']) == 1
    assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert all(response.closed and response.released for response in trace.responses)
    config_target = native_test.target('ConfigMap', 'review-map')
    config = native_test.native(config_target, TOKEN)
    assert result(monkeypatch, config, config_target)[0] == 'FAIL'


def test_old_pod_literals_and_uid_binding_remain_enforced(monkeypatch):
    old = native_test.native(value=TOKEN)
    status, evidence, trace = result(monkeypatch, old)
    assert status == 'FAIL' and len(trace.calls) == 2 and evidence['complete']
    changing = lambda ordinal: native_test.native(value='ready = true')
    def change_uid(ordinal):
        document = changing(ordinal)
        if ordinal == 2:
            document['metadata']['uid'] = 'different-uid'
        return document
    target = native_test.target()
    snapshot, trace = native_test.capture(monkeypatch, documents={native_test.route(target): change_uid})
    assert native_test.findings(snapshot)[0]['status'] == 'UNKNOWN'
    assert len(trace.calls) == 2 and not trace.scans


def test_installed_real_offline_scanners_detect_new_field(monkeypatch):
    doc = native_test.native(value='ready = true')
    doc['spec']['containers'][0]['startupProbe'] = {'exec': {'command': [TOKEN]}}
    status, evidence, trace = result(monkeypatch, doc, real=True)
    assert status == 'FAIL' and len(trace.calls) == 2
    assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}


def test_malformed_handler_pipeline_unknown_without_scan(monkeypatch):
    doc = native_test.native(value='ready = true')
    doc['spec']['containers'][0]['livenessProbe'] = {'exec': {}}
    status, evidence, trace = result(monkeypatch, doc)
    assert status == 'UNKNOWN' and len(trace.calls) == 1 and not trace.scans
    assert evidence['observed']
