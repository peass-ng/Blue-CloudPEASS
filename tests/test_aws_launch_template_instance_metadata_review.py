"""Real SDK -> pre-cache projection -> enrichment -> registered predicate."""
from copy import deepcopy
import json

import boto3
from botocore.stub import Stubber
import pytest

from peaso.checks import evaluate_check
from peaso.checks.claude_aws_a_common import idx
from peaso.collectors import aws
from peaso.collectors import aws_launch_template_instance_metadata as native
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = 'aws.claude_a.ec2.launch_template_instances_no_public_ip'
INSTANCE = 'i-0123456789abcdef0'
REGION = 'us-east-1'
SCOPE = '123456789012/' + REGION
TEMPLATE = {'LaunchTemplateId': 'lt-1234567890abcdef0'}
ROW = {'InstanceId': INSTANCE, 'Tags': [{'Key': native.TAG, 'Value': TEMPLATE['LaunchTemplateId']}]}
SECRET = 'synthetic-user-data-secret-5926'


def response(nics):
    data = {'UserData': SECRET, 'ImageId': 'ami-12345678', 'KeyName': 'sensitive-key-name'}
    if nics is not None:
        data['NetworkInterfaces'] = nics
    return {'LaunchTemplateData': data, 'ResponseMetadata': {'HTTPStatusCode': 200,
            'RequestId': 'fixture', 'HTTPHeaders': {'sensitive-header': SECRET}}}


def projected(nics):
    return native.project_response(response(nics), 'ec2', 'get_launch_template_data',
                                   {'InstanceId': INSTANCE}, REGION)['LaunchTemplateData']


def status(data, *, row=None):
    item = deepcopy(ROW if row is None else row)
    item['LaunchTemplateData'] = data
    return evaluate_check(CID, TEMPLATE, idx(instance=[item]))[0]


@pytest.mark.parametrize('nics,expected', [
    ([{'AssociatePublicIpAddress': True}], 'FAIL'),
    ([{'AssociatePublicIpAddress': False}], 'PASS'), ([], 'PASS'),
    (None, 'UNKNOWN'), ([{}], 'UNKNOWN'),
    ([{}, {'AssociatePublicIpAddress': True}], 'FAIL'),
])
def test_native_predicate_requires_explicit_flags_or_proven_empty(nics, expected):
    assert status(projected(nics)) == expected


@pytest.mark.parametrize('field,value', [('InstanceId', 'i-foreign'), ('collection_status', 'denied'),
                                      ('NetworkInterfacesComplete', False)])
def test_foreign_failed_or_incomplete_observation_cannot_pass(field, value):
    data = projected([])
    data[field] = value
    assert status(data) == 'UNKNOWN'


@pytest.mark.parametrize('field,value', [('region', 'eu-west-1'), ('read_only', False),
    ('profile', 'foreign'), ('source_operation', 'ec2:DescribeInstances')])
def test_provenance_binding_is_required(field, value):
    data = projected([{'AssociatePublicIpAddress': False}])
    data['_provenance'][field] = value
    assert status(data) == 'UNKNOWN'


@pytest.mark.parametrize('bad', [{}, {'LaunchTemplateData': {}},
    {'LaunchTemplateData': {}, 'ResponseMetadata': {'HTTPStatusCode': 403}},
    response('bad'), response([{'AssociatePublicIpAddress': 'false'}]), response([None])])
def test_malformed_response_rejected_before_cache(bad):
    with pytest.raises(aws.ReadFailure):
        native.project_response(bad, 'ec2', 'get_launch_template_data', {'InstanceId': INSTANCE}, REGION)


def test_projection_only_keeps_consumer_metadata():
    raw = response([{'AssociatePublicIpAddress': False, 'Description': SECRET,
                     'NetworkInterfaceId': 'eni-1234', 'PrivateIpAddress': '10.0.0.1'}])
    safe = native.project_response(raw, 'ec2', 'get_launch_template_data', {'InstanceId': INSTANCE}, REGION)
    assert safe['LaunchTemplateData']['NetworkInterfaces'] == [{'AssociatePublicIpAddress': False}]
    assert SECRET not in json.dumps(safe)
    assert 'UserData' not in json.dumps(safe)
    assert raw['LaunchTemplateData']['UserData'] == SECRET


def test_installed_sdk_contract_has_sensitive_body_and_instance_bound_request():
    import botocore.session
    model = botocore.session.get_session().get_service_model('ec2').operation_model('GetLaunchTemplateData')
    assert model.input_shape.required_members == ['InstanceId']
    body = model.output_shape.members['LaunchTemplateData']
    assert body.members['UserData'].type_name == 'string'
    assert body.members['NetworkInterfaces'].member.members['AssociatePublicIpAddress'].type_name == 'boolean'


@pytest.mark.parametrize('mode,expected', [('true', 'FAIL'), ('false', 'PASS'), ('empty', 'PASS'),
    ('denied', 'UNKNOWN'), ('omitted', 'UNKNOWN'), ('missing_flag', 'UNKNOWN'), ('malformed', 'UNKNOWN'),
    ('foreign', 'UNKNOWN')])
def test_real_sdk_shared_cache_enrichment_and_registered_snapshot_consumer(mode, expected):
    assert 'peaso.collectors.aws_launch_template_instance_metadata' in aws.EXTENSION_MODULES
    assert native.OPERATIONS <= aws.READ_ACTIONS
    session = boto3.Session(aws_access_key_id='fixture', aws_secret_access_key='fixture', region_name=REGION)
    client = session.client('ec2')
    requests = aws.Requests({'retry_attempts': 1, 'max_calls': 1})
    requests._clients[(id(session), 'ec2', REGION)] = client
    nics = {'true': [{'AssociatePublicIpAddress': True}], 'false': [{'AssociatePublicIpAddress': False}],
            'empty': [], 'omitted': None, 'missing_flag': [{}], 'malformed': [], 'foreign': []}
    with Stubber(client) as stub:
        params = {'InstanceId': INSTANCE}
        if mode == 'denied':
            stub.add_client_error('get_launch_template_data', 'UnauthorizedOperation', expected_params=params)
        else:
            raw = response(nics[mode])
            if mode == 'malformed':
                raw.pop('ResponseMetadata')
            stub.add_response('get_launch_template_data', raw, params)
        # Use the producer's real registered function without unrelated enrichers.
        rows = native.ENRICHERS['instance'](requests, session, REGION, [ROW, ROW])
        assert requests.calls == 1
        if mode == 'foreign':
            rows[0]['LaunchTemplateData']['InstanceId'] = 'i-foreign'
        assert status(rows[0]['LaunchTemplateData']) == expected
        snapshot = make_snapshot('aws', [SCOPE], [
            {'type': 'instance', 'scope': SCOPE, 'service': 'ec2', 'status': 'collected', 'items': [rows[0]]},
            {'type': 'ec2_launch_template', 'scope': SCOPE, 'service': 'ec2', 'status': 'collected', 'items': [TEMPLATE]}])
        report = evaluate_snapshot(snapshot, checks=[CID])
        assert report['findings'][0]['status'] == expected
        for future in requests._cache.values():
            if future.exception() is None:
                cached = json.dumps(future.result())
                assert SECRET not in cached and 'UserData' not in cached and 'KeyName' not in cached
        for artifact in (rows, snapshot, report):
            serialized = json.dumps(artifact, default=str)
            assert SECRET not in serialized and 'UserData' not in serialized
        stub.assert_no_pending_responses()


def test_only_tagged_instances_read_and_shared_budget_denial_cannot_pass():
    requests = aws.Requests({'retry_attempts': 1, 'max_calls': 1})
    requests.calls = 1  # Another service already consumed the shared budget.
    session = object()
    untagged = {'InstanceId': 'i-untagged', 'Tags': []}
    stale = deepcopy(ROW)
    stale['LaunchTemplateData'] = projected([])
    rows = native.enrich(requests, session, REGION, [untagged, stale])
    assert rows[0] == untagged
    assert rows[1]['LaunchTemplateData']['collection_status'] == 'not_collected'
    assert status(rows[1]['LaunchTemplateData']) == 'UNKNOWN'
    assert requests.calls == 1


def test_source_predicate_does_not_substitute_current_addressing_or_other_templates():
    public_now = {**ROW, 'PublicIpAddress': '203.0.113.8'}
    assert status(projected([{'AssociatePublicIpAddress': False}]), row=public_now) == 'PASS'
    other = {**ROW, 'Tags': [{'Key': native.TAG, 'Value': 'lt-other'}]}
    assert status(projected([{'AssociatePublicIpAddress': True}]), row=other) == 'NOT_APPLICABLE'
    assert status({'NetworkInterfaces': []}) == 'UNKNOWN'


def test_complete_instance_inventory_is_required_for_pass():
    item = {**ROW, 'LaunchTemplateData': projected([])}
    index = idx(instance=[item])
    index['collections']['instance'][0]['status'] = 'partial'
    assert evaluate_check(CID, TEMPLATE, index)[0] == 'UNKNOWN'
