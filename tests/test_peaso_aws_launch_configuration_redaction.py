import base64
import copy
import json
from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber
from peaso.collectors import aws
from peaso.collectors.aws_launch_configuration_redaction import indicators, project_response
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

KEY = 'AKIA' + 'X' * 16
SECRET = 'x' * 40

def encoded(text):
    return base64.b64encode(text.encode()).decode()

@pytest.mark.parametrize('text,expected', [
    ('#!/bin/sh\necho safe', {'InspectionStatus':'collected','HasAwsKeyPair':False}),
    (f'export AWS_ACCESS_KEY_ID={KEY}\nexport AWS_SECRET_ACCESS_KEY={SECRET}', {'InspectionStatus':'collected','HasAwsKeyPair':True}),
    (f'{{"accessKeyId":"{KEY}","secretAccessKey":"{SECRET}"}}', {'InspectionStatus':'collected','HasAwsKeyPair':True}),
    (f'aws_access_key_id={KEY}\nsecret=unsupported-format', {'InspectionStatus':'unresolved_key_pair'}),
    ('x' * 16385, {'InspectionStatus':'decode_failed'}),
])
def test_known_literal_and_unresolved_key_formats(text,expected):
    assert indicators(encoded(text)) == expected

@pytest.mark.parametrize('value', ['not-base64', 3, encoded('x')+'!', base64.b64encode(b'\xff').decode(), base64.b64encode(b'\x1f\x8b\x00').decode()])
def test_unreadable_payload_never_passes(value):
    assert indicators(value) == {'InspectionStatus':'decode_failed'}

def test_native_optional_absence_and_empty_payload():
    assert indicators(None) == indicators('') == {'InspectionStatus':'collected','HasAwsKeyPair':False}

def test_projection_does_not_mutate_provider_response_or_retain_payload():
    raw = {'LaunchConfigurations':[{'UserData':encoded(f'{KEY}\nAWS_SECRET_ACCESS_KEY={SECRET}'), 'LaunchConfigurationName':'qa'}]}
    before=copy.deepcopy(raw); safe=project_response(raw)
    assert raw == before
    assert 'UserData' not in safe['LaunchConfigurations'][0]
    assert KEY not in json.dumps(safe) and SECRET not in json.dumps(safe)

def test_sdk_response_is_redacted_before_future_cache_and_works_with_registered_check(monkeypatch):
    session=boto3.Session(aws_access_key_id='inert',aws_secret_access_key='inert',region_name='us-east-1')
    client=session.client('autoscaling'); monkeypatch.setattr(aws.Requests,'client',lambda *args:client)
    row={'LaunchConfigurationName':'qa','LaunchConfigurationARN':'arn:aws:autoscaling:us-east-1:123456789012:launchConfiguration:qa:launchConfigurationName/qa',
         'ImageId':'ami-qa','InstanceType':'t3.micro','CreatedTime':datetime.now(timezone.utc),
         'UserData':encoded(f'{KEY}\nAWS_SECRET_ACCESS_KEY={SECRET}')}
    requests=aws.Requests({})
    with Stubber(client) as stub:
        stub.add_response('describe_launch_configurations',{'LaunchConfigurations':[row]}, {})
        read=requests.pages(session,'autoscaling','us-east-1','describe_launch_configurations','LaunchConfigurations')
        again=requests.pages(session,'autoscaling','us-east-1','describe_launch_configurations','LaunchConfigurations')
        assert requests.calls == 1 and again.items == read.items
        stub.assert_no_pending_responses()
    retained=json.dumps([future.result() for future in requests._cache.values()],default=str)
    assert KEY not in retained and SECRET not in retained and 'UserData"' not in retained
    scope='123456789012/us-east-1'
    snapshot=make_snapshot('aws',[scope],[{'type':'autoscaling_launch_configuration','scope':scope,'service':'autoscaling','status':read.status,'items':json.loads(json.dumps(read.items,default=lambda value:value.isoformat()))}])
    findings=evaluate_snapshot(snapshot,checks=['aws_autoscaling_userdata_plaintext_aws_key'])['findings']
    assert len(findings)==1 and findings[0]['status']=='FAIL'
    assert KEY not in json.dumps(findings) and SECRET not in json.dumps(findings)

def test_native_alias_is_advertised_only_with_real_source():
    from peaso.collectors.bulk_evidence import coverage
    assert coverage()['aws']['native_aliases']['autoscaling_launch_configuration'] == 'launch_configuration'
