"""Secrets Manager rules exercise sanitized, accepted laboratory events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_secretsmanager_followup_lab_events.json').read_text())
FIELDS = {
    'request.secret_batch_multi_read_requested', 'request.secret_current_value_written',
    'request.secret_kms_key_associated', 'request.secret_deletion_scheduled',
    'request.secret_restored', 'request.secretsmanager_current_version_moved',
}
RULES = tuple(Rule(id=field, title=field, description=field, level='medium',
                   technique_id=field, product='aws', selection={field: True}) for field in FIELDS)


def hits(events):
    return {hit.technique_id for hit in detect_aws_events(events, RULES)}


def test_real_secret_lifecycle_and_negative_controls():
    assert hits(EVENTS) == FIELDS
    assert not hits([e for e in EVENTS if e['eventName'] == 'GetSecretValue'])
    for event in EVENTS:
        if not hits([event]):
            continue
        assert not hits([{**event, 'errorCode': 'AccessDeniedException'}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
        assert not hits([{**event, 'readOnly': not event['readOnly']}])

    batch = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'BatchGetSecretValue'))
    batch['requestParameters']['secretIdList'] = batch['requestParameters']['secretIdList'][:1]
    assert not hits([batch])

    write = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'PutSecretValue'))
    write['requestParameters']['versionStages'] = ['AWSPENDING']
    assert not hits([write])

    key = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'UpdateSecret'))
    key['requestParameters']['kmsKeyId'] = key['requestParameters']['kmsKeyId'].replace(
        ':222233334444:', ':000000000000:')
    assert not hits([key])

    scheduled = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'DeleteSecret'
                               and 'recoveryWindowInDays' in e['requestParameters']))
    scheduled['requestParameters']['forceDeleteWithoutRecovery'] = True
    assert not hits([scheduled])
    scheduled['requestParameters']['forceDeleteWithoutRecovery'] = False
    scheduled['responseElements']['arn'] = scheduled['responseElements']['arn'].replace(
        ':222233334444:', ':000000000000:')
    assert not hits([scheduled])

    restored = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'RestoreSecret'))
    restored['responseElements']['arn'] = None
    assert not hits([restored])
