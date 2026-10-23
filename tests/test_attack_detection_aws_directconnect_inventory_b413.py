"""Synthetic derivatives of empty Direct Connect inventory CloudTrail reads."""

from copy import deepcopy

from peaso.attack_detection.aws_directconnect_inventory_b413 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = '999999999999'
ROW = {
    'eventSource': 'directconnect.amazonaws.com',
    'eventName': 'DescribeVirtualInterfaces',
    'eventType': 'AwsApiCall', 'eventCategory': 'Management',
    'managementEvent': True, 'readOnly': True,
    'eventID': 'synthetic-dx-read', 'eventTime': '2026-10-23T00:00:00Z',
    'recipientAccountId': ACCOUNT, 'awsRegion': 'us-east-2',
    'userIdentity': {'type': 'IAMUser', 'accountId': ACCOUNT,
                     'arn': f'arn:aws:iam::{ACCOUNT}:user/synthetic-operator'},
    'requestParameters': None, 'responseElements': None,
}
RULE = Rule(
    id='synthetic-dx', title='Synthetic DX inventory', description='Synthetic',
    level='medium', technique_id='aws-directconnect-virtual-interfaces-enumerated',
    product='aws', selection={
        'event.source': 'directconnect.amazonaws.com',
        'event.name': 'DescribeVirtualInterfaces', 'event.outcome': 'success',
        'request.directconnect_virtual_interfaces_enumerated': True,
    },
)


def test_unscoped_read_hits_without_copying_response_material():
    event = normalize(ROW)
    assert event is not None
    assert event['target.id'].startswith('sha256:')
    hits = detect_aws_events([ROW], (RULE,))
    assert len(hits) == 1
    with_material = deepcopy(ROW)
    with_material['responseElements'] = {'authKey': 'synthetic-secret-material'}
    assert 'synthetic-secret-material' not in str(normalize(with_material))
    assert 'synthetic-secret-material' not in str(detect_aws_events([with_material], (RULE,)))


def test_scoped_failed_or_foreign_reads_are_negative():
    changes = (
        lambda row: row.update(errorCode='AccessDeniedException'),
        lambda row: row['userIdentity'].update(accountId='888888888888'),
        lambda row: row.update(requestParameters={'virtualInterfaceId': 'dxvif-synthetic'}),
        lambda row: row.update(readOnly=False),
        lambda row: row.update(eventCategory='Data'),
    )
    for change in changes:
        row = deepcopy(ROW)
        change(row)
        assert normalize(row) is None
        assert detect_aws_events([row], (RULE,)) == []
