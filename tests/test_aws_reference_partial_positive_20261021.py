"""Verified source positives survive later native drift; clean claims require stability."""
from copy import deepcopy
import json
from pathlib import Path

import boto3
import pytest

from peaso.checks import aws_workload_referenced_source_review as workload_check
from peaso.checks import aws_build_deployment_referenced_source_review as build_check
from peaso.collectors import aws_workload_referenced_source_indicators as workload
from peaso.collectors import aws_build_deployment_referenced_source_indicators as build


@pytest.mark.parametrize('check,reader', [(workload_check, workload), (build_check, build)])
@pytest.mark.parametrize('label,expected', [('fail', 'FAIL'), ('pass', 'UNKNOWN')])
def test_native_after_read_drift_preserves_positive_only(check, reader, label, expected):
    path = Path(check.__file__).with_name(Path(check.__file__).stem + '_cases.json')
    cases = json.loads(path.read_text())[reader.CHECK]
    item, index = deepcopy(cases[label]), deepcopy(cases[label + '_index'])
    marker = item[reader.MARKER]
    marker['association_coherent'] = False
    marker['native_after_request'] = None
    index['collections'][reader.KIND][0]['items'] = [deepcopy(item)]
    status, evidence = check.evaluate(item, index)
    assert status == expected
    assert evidence['complete'] is False
    if expected == 'FAIL':
        assert evidence['secret_leaks']
        assert {'kingfisher', 'trufflehog'} == {
            d['engine'] for leak in evidence['secret_leaks'] for d in leak['detectors']}


@pytest.mark.parametrize('check,reader', [(workload_check, workload), (build_check, build)])
def test_non_boolean_native_consistency_marker_is_rejected(check, reader):
    path = Path(check.__file__).with_name(Path(check.__file__).stem + '_cases.json')
    cases = json.loads(path.read_text())[reader.CHECK]
    item, index = deepcopy(cases['pass']), deepcopy(cases['pass_index'])
    item[reader.MARKER]['association_coherent'] = 1
    index['collections'][reader.KIND][0]['items'] = [deepcopy(item)]
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_workload_actual_sdk_endpoint_must_match_native_endpoint():
    session = boto3.Session(aws_access_key_id='offline', aws_secret_access_key='offline',
                            region_name='us-east-1')
    client = session.client('glue', region_name='us-east-1')
    assert workload._native_client(client, 'glue', 'us-east-1') is None
    client._endpoint.host = 'https://foreign.example.invalid'
    with pytest.raises(ValueError, match='workload_endpoint_unbound'):
        workload._native_client(client, 'glue', 'us-east-1')
